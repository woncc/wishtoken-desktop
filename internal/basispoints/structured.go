package basispoints

import (
	"encoding/json"
	"regexp"
	"strings"
)

var structuredFormatName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// structuredOutput emulates text.format (json_schema / json_object): the
// gateway rejects those fields, so the contract is delivered as instructions
// and the terminal answer is validated before any message text is exposed.
type structuredOutput struct {
	format object
	kind   string
	schema object
}

func prepareStructuredOutput(textConfig any, responseFormat any) (*structuredOutput, error) {
	var format object
	if config, ok := textConfig.(object); ok {
		if f, ok := config["format"].(object); ok {
			format = f
		}
	}
	if format == nil {
		if rf, ok := responseFormat.(object); ok {
			format = object{"type": text(rf["type"])}
			if schema, ok := rf["json_schema"].(object); ok {
				for k, v := range schema {
					format[k] = v
				}
			}
		}
	}
	if format == nil {
		return nil, nil
	}
	kind := text(format["type"])
	if kind == "" || kind == "text" {
		return nil, nil
	}
	if kind != "json_object" && kind != "json_schema" {
		return nil, prepareErr(CategoryOutputFormat, "text.format requires text, json_object or json_schema")
	}
	result := &structuredOutput{format: format, kind: kind}
	if kind == "json_object" {
		return result, nil
	}
	if name := text(format["name"]); name != "" && !structuredFormatName.MatchString(name) {
		return nil, prepareErr(CategoryOutputFormat, "json_schema name must be 1-64 letters, digits, underscores or hyphens")
	}
	schema, ok := format["schema"].(object)
	if !ok || schema == nil {
		return nil, prepareErr(CategoryOutputFormat, "json_schema requires a schema object")
	}
	if encoded, err := json.Marshal(schema); err != nil || len(encoded) > 1<<20 {
		return nil, prepareErr(CategoryOutputFormat, "structured output schema exceeds 1 MiB")
	}
	result.schema = schema
	return result, nil
}

func (s *structuredOutput) instructions() string {
	prompt := "The client requires a structured final answer. Your final assistant answer must be exactly one JSON value, with no Markdown fences or surrounding prose. " +
		"Tool calls and refusals remain separate protocol items; use the client tool transport as needed before the final answer. " +
		"The bridge validates the final JSON before returning it to the client."
	if s.schema != nil {
		encoded, _ := json.Marshal(s.schema)
		prompt += " The final answer must satisfy this JSON schema:\n" + string(encoded)
	}
	return prompt
}

// validate checks the terminal response. A tool turn is not a final answer
// and refusals stay outside the JSON contract.
func (s *structuredOutput) validate(response object) error {
	output, _ := response["output"].([]any)
	var answer strings.Builder
	hasTool, hasRefusal := false, false
	for _, raw := range output {
		item, _ := raw.(object)
		hasTool = hasTool || isTool(item)
		if text(item["type"]) != "message" {
			continue
		}
		content, _ := item["content"].([]any)
		for _, rawPart := range content {
			part, _ := rawPart.(object)
			switch text(part["type"]) {
			case "output_text":
				value, _ := part["text"].(string)
				answer.WriteString(value)
			case "refusal":
				hasRefusal = true
			}
		}
	}
	if hasTool || (hasRefusal && answer.Len() == 0) {
		return nil
	}
	cleaned := stripFences(answer.String())
	var instance any
	if decode([]byte(cleaned), &instance) != nil {
		return &PrepareError{Category: CategoryOutputFormat, Detail: "structured output is not one valid JSON value"}
	}
	if s.schema != nil {
		if err := checkSchema(instance, s.schema); err != nil {
			return &PrepareError{Category: CategoryOutputFormat, Detail: "structured output does not satisfy the requested schema: " + err.Error()}
		}
	}
	// Rewrite the message so the client receives the bare JSON value.
	if cleaned != answer.String() {
		for _, raw := range output {
			item, _ := raw.(object)
			if text(item["type"]) != "message" {
				continue
			}
			content, _ := item["content"].([]any)
			for _, rawPart := range content {
				part, _ := rawPart.(object)
				if text(part["type"]) == "output_text" {
					part["text"] = cleaned
					cleaned = "" // subsequent parts become empty
				}
			}
		}
	}
	return nil
}

func stripFences(s string) string {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "```") {
		if nl := strings.IndexByte(t, '\n'); nl >= 0 {
			t = t[nl+1:]
		}
		t = strings.TrimSuffix(strings.TrimSpace(t), "```")
	}
	return strings.TrimSpace(t)
}

// checkSchema is a small structural validator (type, required, properties,
// items, enum). It is not a full JSON Schema engine.
func checkSchema(value any, schema object) error {
	if schema == nil {
		return nil
	}
	if kind := schema["type"]; kind != nil && !typeMatches(value, kind) {
		return &PrepareError{Category: CategoryOutputFormat, Detail: "value type mismatch"}
	}
	if choices, ok := schema["enum"].([]any); ok && len(choices) > 0 {
		matched := false
		for _, c := range choices {
			if jsonEqual(c, value) {
				matched = true
				break
			}
		}
		if !matched {
			return &PrepareError{Category: CategoryOutputFormat, Detail: "value not in enum"}
		}
	}
	switch typed := value.(type) {
	case object:
		if required, ok := schema["required"].([]any); ok {
			for _, name := range required {
				if _, exists := typed[text(name)]; !exists {
					return &PrepareError{Category: CategoryOutputFormat, Detail: "missing required field " + text(name)}
				}
			}
		}
		properties, _ := schema["properties"].(object)
		for key, nested := range typed {
			if raw, ok := properties[key]; ok {
				if nestedSchema, ok := raw.(object); ok {
					if err := checkSchema(nested, nestedSchema); err != nil {
						return err
					}
				}
			} else if additional, ok := schema["additionalProperties"].(bool); ok && !additional && properties != nil {
				return &PrepareError{Category: CategoryOutputFormat, Detail: "unexpected field " + key}
			}
		}
	case []any:
		if items, ok := schema["items"].(object); ok {
			for _, item := range typed {
				if err := checkSchema(item, items); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func typeMatches(value, kind any) bool {
	if alternatives, ok := kind.([]any); ok {
		for _, candidate := range alternatives {
			if typeMatches(value, candidate) {
				return true
			}
		}
		return false
	}
	switch kind {
	case "object":
		_, ok := value.(object)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "number", "integer":
		_, ok := value.(json.Number)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	}
	return true
}

func jsonEqual(a, b any) bool {
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return string(ra) == string(rb)
}

func isStructuredMessageEvent(kind string, item object) bool {
	return strings.HasPrefix(kind, "response.output_text.") || strings.HasPrefix(kind, "response.refusal.") ||
		strings.HasPrefix(kind, "response.content_part.") ||
		(strings.HasPrefix(kind, "response.output_item.") && text(item["type"]) == "message")
}

// emitStructuredMessage reconstructs message events from the validated
// terminal item so earlier deltas never escape validation.
func emitStructuredMessage(item object, index int, emit func(string, object) error) error {
	id := text(item["id"])
	added := cloneObject(item)
	added["content"], added["status"] = []any{}, "in_progress"
	if err := emit("response.output_item.added", object{"output_index": index, "item": added}); err != nil {
		return err
	}
	content, _ := item["content"].([]any)
	for i, raw := range content {
		part, _ := raw.(object)
		field, prefix := "text", "response.output_text"
		if text(part["type"]) == "refusal" {
			field, prefix = "refusal", "response.refusal"
		}
		empty := cloneObject(part)
		empty[field] = ""
		events := []struct {
			kind    string
			payload object
		}{
			{"response.content_part.added", object{"part": empty}},
			{prefix + ".delta", object{"delta": part[field]}},
			{prefix + ".done", object{field: part[field]}},
			{"response.content_part.done", object{"part": part}},
		}
		for _, event := range events {
			event.payload["output_index"], event.payload["item_id"], event.payload["content_index"] = index, id, i
			if err := emit(event.kind, event.payload); err != nil {
				return err
			}
		}
	}
	return emit("response.output_item.done", object{"output_index": index, "item": item})
}
