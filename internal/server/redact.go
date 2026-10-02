package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
)

// redactManagement buffers a management response and removes OAuth material
// before it is written. Model streaming routes must not use this wrapper.
func (s *Server) redactManagement(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bw := &bufferWriter{ResponseWriter: w, status: http.StatusOK}
		next(bw, r)
		body := s.redactManagementBody(bw.buf.Bytes())
		w.Header().Del("Content-Length")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(bw.status)
		if r.Method != http.MethodHead && len(body) > 0 {
			_, _ = w.Write(body)
		}
	}
}

type bufferWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
	buf    bytes.Buffer
}

func (b *bufferWriter) WriteHeader(status int) {
	if b.wrote {
		return
	}
	b.wrote = true
	b.status = status
}

func (b *bufferWriter) Write(p []byte) (int, error) {
	if !b.wrote {
		b.WriteHeader(http.StatusOK)
	}
	return b.buf.Write(p)
}

func (b *bufferWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

func (s *Server) redactManagementBody(raw []byte) []byte {
	raw = replaceSecrets(raw, s.oauthSecrets())
	cleaned, changed := blankCredentialFields(raw)
	if changed {
		return cleaned
	}
	return raw
}

func (s *Server) oauthSecrets() []string {
	var secrets []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if len(v) < 12 || strings.ContainsAny(v, "\\\"\n\r") {
			return
		}
		secrets = append(secrets, v)
	}
	if s.Store != nil {
		for _, acc := range s.Store.List() {
			add(acc.AccessToken)
			add(acc.RefreshToken)
			add(acc.IDToken)
		}
	}
	if s.cockpitStore != nil {
		for _, acc := range s.cockpitStore.List() {
			add(acc.AccessToken)
			add(acc.RefreshToken)
			add(acc.IDToken)
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return secrets
}

func replaceSecrets(raw []byte, secrets []string) []byte {
	text := string(raw)
	for _, secret := range secrets {
		// Exact bytes miss a token copied with a spacing mark or percent
		// encoding. Mask the known secret without reformatting the JSON.
		text = httpx.MaskEncodedSecret(text, secret, "[redacted]")
		quoted, err := json.Marshal(secret)
		if err != nil || len(quoted) < 2 {
			continue
		}
		text = httpx.MaskEncodedSecret(text, string(quoted[1:len(quoted)-1]), "[redacted]")
	}
	return []byte(text)
}

func blankCredentialFields(raw []byte) ([]byte, bool) {
	if len(raw) == 0 || !json.Valid(raw) {
		return raw, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return raw, false
	}
	if !blankValue(&v) {
		return raw, false
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return raw, false
	}
	return buf.Bytes(), true
}

func blankValue(v *any) bool {
	changed := false
	switch t := (*v).(type) {
	case map[string]any:
		for k, child := range t {
			if credentialField(k) {
				if s, ok := child.(string); ok && blankCredentialString(s) {
					t[k] = ""
					changed = true
				}
				continue
			}
			if blankValue(&child) {
				t[k] = child
				changed = true
			}
		}
	case []any:
		for i := range t {
			item := t[i]
			if blankValue(&item) {
				t[i] = item
				changed = true
			}
		}
	}
	return changed
}

func credentialField(key string) bool {
	switch key {
	case "access_token", "refresh_token", "id_token", "accessToken", "refreshToken", "idToken", "api_key", "experimental_bearer_token":
		return true
	default:
		return false
	}
}

func blankCredentialString(s string) bool {
	if s == "" || s == "[redacted]" || s == "gptbridge" || strings.HasPrefix(s, "$") {
		return false
	}
	return len(s) >= 8
}
