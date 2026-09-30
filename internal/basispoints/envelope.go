package basispoints

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const maxEnvelopeBytes = 1 << 20

// customTransportEnvelope recognises the explicitly marked raw custom-tool
// transport (summary = gptbridge.custom/NAME, code = raw input).
func customTransportEnvelope(arguments object) (object, bool, error) {
	summary, ok := arguments["summary"].(string)
	if !ok {
		return nil, false, nil
	}
	var name string
	switch {
	case strings.HasPrefix(summary, CustomMarker):
		name = strings.TrimPrefix(summary, CustomMarker)
	case strings.HasPrefix(summary, legacyCustomMarker):
		name = strings.TrimPrefix(summary, legacyCustomMarker)
	default:
		return nil, false, nil
	}
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "/\\") || strings.IndexFunc(name, unicode.IsSpace) >= 0 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return nil, true, fmt.Errorf("Basispoints raw custom transport requires an exact nonempty catalog tool name in summary")
	}
	input, ok := arguments["code"].(string)
	if !ok {
		return nil, true, fmt.Errorf("Basispoints raw custom transport code must be a string")
	}
	if len(input) > maxEnvelopeBytes {
		return nil, true, fmt.Errorf("Basispoints raw custom transport code exceeds the size limit")
	}
	return object{"name": name, "input": input}, true, nil
}

// decodeTransportCode unwraps common model formatting (fences, short prose
// prefixes, double encoding) around one JSON envelope without evaluating
// anything. Ambiguous batches are rejected.
func decodeTransportCode(value any) (object, error) {
	original := value
	for depth := 0; depth < 4; depth++ {
		if item, ok := value.(object); ok && item != nil {
			return item, nil
		}
		raw, ok := value.(string)
		if !ok || len(raw) > maxEnvelopeBytes {
			break
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			break
		}
		if decoded, ok := decodeEnvelopeValue(raw); ok {
			value = decoded
			continue
		}
		if start := strings.Index(raw, "```"); start >= 0 && prosePrefix(raw[:start]) {
			fenced := raw[start:]
			newline := strings.IndexByte(fenced, '\n')
			if newline >= 0 && strings.HasSuffix(fenced, "```") {
				language := strings.TrimSpace(fenced[3:newline])
				if language == "" || strings.EqualFold(language, "json") {
					value = strings.TrimSpace(fenced[newline+1 : len(fenced)-3])
					continue
				}
			}
		}
		if start := strings.IndexByte(raw, '{'); start > 0 && prosePrefix(raw[:start]) {
			if decoded, ok := decodeEnvelopeValue(raw[start:]); ok {
				value = decoded
				continue
			}
		}
		break
	}
	return nil, fmt.Errorf("Basispoints tool transport code must contain one JSON client-tool envelope (%s)", transportShape(original))
}

func transportShape(value any) string {
	raw, ok := value.(string)
	if !ok {
		if value == nil {
			return "format=missing"
		}
		return fmt.Sprintf("format=non_string_%T", value)
	}
	trimmed := strings.TrimSpace(raw)
	format := "text_or_code"
	switch {
	case trimmed == "":
		format = "empty"
	case strings.HasPrefix(trimmed, "```"):
		format = "markdown"
	case strings.HasPrefix(trimmed, "{"):
		format = "json_object"
	case strings.HasPrefix(trimmed, "["):
		format = "json_array"
	case strings.HasPrefix(trimmed, `"`):
		format = "json_string"
	}
	return fmt.Sprintf("format=%s; bytes=%d", format, len(raw))
}

// decodeTransportEnvelope decodes code and unwraps up to two nested
// run_officejs wrappers the model may have produced by mistake.
func decodeTransportEnvelope(value any) (object, error) {
	for depth := 0; depth < 3; depth++ {
		envelope, err := decodeTransportCode(value)
		if err != nil {
			return nil, err
		}
		name, err := envelopeName(envelope)
		if err != nil {
			return nil, err
		}
		if name != TransportTool && name != "functions."+TransportTool {
			return envelope, nil
		}
		args, err := envelopeArguments(envelope)
		if err != nil {
			return nil, err
		}
		if raw, ok := args.(string); ok {
			var parsed object
			if decode([]byte(raw), &parsed) != nil {
				return nil, fmt.Errorf("Basispoints nested transport arguments must be one JSON object")
			}
			args = parsed
		}
		outer, ok := args.(object)
		if !ok {
			return nil, fmt.Errorf("Basispoints nested transport arguments must be an object")
		}
		value = outer["code"]
	}
	return nil, fmt.Errorf("Basispoints tool transport exceeds two nested wrappers")
}

var callShaped = regexp.MustCompile(`^\s*(?:return\s+)?(?:await\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*\(`)

// recoverTransportEnvelope handles code written as a call expression such as
// functions.exec_command({"cmd":"pwd"}) by selecting the callee from the
// catalog and decoding exactly one JSON argument. Nothing is evaluated.
func (b *Bridge) recoverTransportEnvelope(arguments object) (object, bool) {
	code, ok := arguments["code"].(string)
	if !ok || len(code) > maxEnvelopeBytes {
		return nil, false
	}
	match := callShaped.FindStringSubmatchIndex(code)
	if match == nil {
		return nil, false
	}
	key, info, known := b.catalogTool(code[match[2]:match[3]])
	if !known {
		return nil, false
	}
	rest := code[match[1]:]
	value, end, ok := decodeLeadingValue(rest)
	if !ok && info.Kind == "function" {
		rest = repairTransportJSONStrings(rest)
		value, end, ok = decodeLeadingValue(rest)
	}
	if !ok {
		return nil, false
	}
	tail := strings.TrimSpace(rest[end:])
	if !strings.HasPrefix(tail, ")") {
		return nil, false
	}
	tail = strings.TrimSpace(tail[1:])
	if tail != "" && tail != ";" {
		return nil, false
	}
	switch info.Kind {
	case "function":
		if args, ok := value.(object); ok && args != nil {
			return object{"name": key, "arguments": args}, true
		}
	case "custom":
		if input, ok := value.(string); ok {
			return object{"name": key, "input": input}, true
		}
	}
	return nil, false
}

func decodeLeadingValue(raw string) (any, int, bool) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, 0, false
	}
	return value, int(decoder.InputOffset()), true
}

func envelopeName(envelope object) (string, error) {
	name := text(envelope["name"])
	alias := text(envelope["tool"])
	if name != "" && alias != "" && name != alias {
		return "", fmt.Errorf("Basispoints tool envelope contains conflicting names")
	}
	if name == "" {
		name = alias
	}
	if name == "" {
		name = text(envelope["function"])
	}
	return strings.TrimSpace(name), nil
}

func envelopeArguments(envelope object) (any, error) {
	args, exists := envelope["arguments"]
	alias, hasAlias := envelope["args"]
	if exists && hasAlias {
		return nil, fmt.Errorf("Basispoints tool envelope contains conflicting argument fields")
	}
	if !exists {
		args = alias
		if !hasAlias {
			if params, ok := envelope["parameters"]; ok {
				args = params
			} else if input, ok := envelope["input"]; ok {
				args = input
			}
		}
	}
	return args, nil
}

func prosePrefix(prefix string) bool {
	return len(prefix) <= 512 && !strings.ContainsAny(prefix, "{}[]();=`\"")
}

func decodeEnvelopeValue(raw string) (any, bool) {
	var value any
	if decode([]byte(raw), &value) == nil {
		return value, true
	}
	fixed := repairTransportJSONStrings(raw)
	if fixed != raw && decode([]byte(fixed), &value) == nil {
		return value, true
	}
	return nil, false
}

// repairTransportJSONStrings escapes raw line breaks and tabs inside JSON
// strings and repairs illegal backslash escapes. It never invents missing
// quotes, separators or delimiters.
func repairTransportJSONStrings(raw string) string {
	var out strings.Builder
	out.Grow(len(raw))
	quoted := false
	for i := 0; i < len(raw); i++ {
		ch := raw[i]
		if ch == '"' {
			quoted = !quoted
		}
		if quoted {
			switch ch {
			case '\n':
				out.WriteString(`\n`)
				continue
			case '\r':
				out.WriteString(`\r`)
				continue
			case '\t':
				out.WriteString(`\t`)
				continue
			}
		}
		if ch != '\\' || !quoted || i+1 >= len(raw) {
			out.WriteByte(ch)
			continue
		}
		next := raw[i+1]
		valid := strings.ContainsRune(`"\/bfnrt`, rune(next))
		if next == 'u' && i+5 < len(raw) {
			valid = true
			for _, digit := range raw[i+2 : i+6] {
				if !strings.ContainsRune("0123456789abcdefABCDEF", digit) {
					valid = false
				}
			}
		}
		out.WriteByte('\\')
		if valid {
			out.WriteByte(next)
			i++
		} else {
			out.WriteByte('\\')
		}
	}
	return out.String()
}
