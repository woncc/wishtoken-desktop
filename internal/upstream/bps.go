package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/basispoints"
	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
)

// BPSClient talks to the Basispoints gateway.
type BPSClient struct {
	// ResponsesURL / AttachmentsURL override the defaults (tests).
	ResponsesURL   string
	AttachmentsURL string
}

func (c *BPSClient) responsesURL() string {
	if c.ResponsesURL != "" {
		return c.ResponsesURL
	}
	return basispoints.ResponsesURL
}

func (c *BPSClient) attachmentsURL() string {
	if c.AttachmentsURL != "" {
		return c.AttachmentsURL
	}
	return basispoints.AttachmentsURL
}

// ApplyBPSHeaders sets the headers the gateway expects from the Excel add-in.
func ApplyBPSHeaders(req *http.Request, cred Credentials) {
	req.Header.Set("Authorization", "Bearer "+cred.AccessToken)
	req.Header.Set("Chatgpt-Account-Id", cred.AccountID)
	req.Header.Set("X-OpenAI-Account-Id", cred.AccountID)
	req.Header.Set("X-Basispoints-Auth-Mode", "chatgpt")
	req.Header.Set("Origin", "https://bps.openai.com")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Product", "basispoints-excel-plugin")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Agent-Profile", "excel")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Editor", "excel")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Host", "office")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Platform", "excel")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Platform-Class", "PC")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Client-Runtime", "desktop")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Office-Host", "Excel")
	req.Header.Set("X-OpenAI-Internal-Basispoints-Office-Platform", "PC")
}

// Responses posts a prepared gateway request and returns the raw response.
func (c *BPSClient) Responses(ctx context.Context, cred Credentials, body []byte) (*http.Response, error) {
	if strings.TrimSpace(cred.AccessToken) == "" || strings.TrimSpace(cred.AccountID) == "" {
		return nil, fmt.Errorf("basispoints requires a ChatGPT access token and account id")
	}
	hc, err := client(cred, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.responsesURL(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	ApplyBPSHeaders(req, cred)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	return hc.Do(req)
}

// UploadAttachment uploads one image the way the add-in's upload button does
// and returns the gateway file id.
func (c *BPSClient) UploadAttachment(ctx context.Context, cred Credentials, att basispoints.Attachment) (string, error) {
	hc, err := client(cred, 120*time.Second)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="image.%s"`, att.Extension()))
	header.Set("Content-Type", att.MIME)
	part, err := writer.CreatePart(header)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(att.Data); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.attachmentsURL(), &buf)
	if err != nil {
		return "", err
	}
	ApplyBPSHeaders(req, cred)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("attachment upload failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", NewHTTPError(resp.StatusCode, "basispoints-attachments", string(body))
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("attachment upload returned invalid JSON")
	}
	for _, key := range []string{"openai_file_id", "file_id", "id"} {
		if id, ok := payload[key].(string); ok && strings.TrimSpace(id) != "" {
			return strings.TrimSpace(id), nil
		}
	}
	return "", fmt.Errorf("attachment upload returned no file id")
}

// HTTPError is a non-2xx upstream answer. The raw body is parsed once and
// discarded so logs and account errors cannot retain credential material.
type HTTPError struct {
	Status   int
	Upstream string
	code     string
	detail   string
}

// NewHTTPError parses body into a safe code and operator message.
func NewHTTPError(status int, upstreamName, body string) *HTTPError {
	code, detail := parseUpstreamFailure(upstreamName, status, body)
	return &HTTPError{Status: status, Upstream: upstreamName, code: code, detail: detail}
}

func (e *HTTPError) Error() string {
	if e == nil {
		return "upstream error"
	}
	if e.detail == "" {
		return fmt.Sprintf("%s returned %d", e.Upstream, e.Status)
	}
	return fmt.Sprintf("%s returned %d: %s", e.Upstream, e.Status, e.detail)
}

// ErrorCode extracts error.code (or error.type) from a JSON error body.
func (e *HTTPError) ErrorCode() string {
	if e == nil {
		return ""
	}
	return e.code
}

// Message extracts a human readable message from a JSON error body.
func (e *HTTPError) Message() string {
	if e == nil {
		return ""
	}
	return e.detail
}

func parseUpstreamFailure(upstreamName string, status int, body string) (string, string) {
	trimmed := strings.TrimSpace(body)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return "", fmt.Sprintf("%s upstream returned HTTP %d (gateway error; retry the same model later)", upstreamName, status)
	}
	var payload struct {
		Error struct {
			Code    string `json:"code"`
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
		Detail any `json:"detail"`
	}
	if json.Unmarshal([]byte(trimmed), &payload) == nil {
		code := safeUpstreamCode(payload.Error.Code)
		if code == "" {
			code = safeUpstreamCode(detailCode(payload.Detail))
		}
		if code == "" {
			code = safeUpstreamCode(payload.Error.Type)
		}
		msg := payload.Error.Message
		if msg == "" {
			msg = detailMessage(payload.Detail)
		}
		msg = limitFailure(httpx.SanitizeFailure(msg), 400)
		if msg != "" {
			return code, msg
		}
		if code != "" {
			return code, code
		}
		if trimmed != "" {
			return "", fmt.Sprintf("%s upstream returned HTTP %d", upstreamName, status)
		}
		return "", ""
	}
	plain := limitFailure(httpx.SanitizeFailure(trimmed), 400)
	if plain != "" {
		return "", plain
	}
	if trimmed != "" {
		return "", fmt.Sprintf("%s upstream returned HTTP %d", upstreamName, status)
	}
	return "", ""
}

func detailCode(detail any) string {
	m, ok := detail.(map[string]any)
	if !ok {
		return ""
	}
	code, _ := m["code"].(string)
	return code
}

func detailMessage(detail any) string {
	switch d := detail.(type) {
	case string:
		return d
	case map[string]any:
		msg, _ := d["message"].(string)
		return msg
	default:
		return ""
	}
}

func safeUpstreamCode(code string) string {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 80 || strings.ContainsAny(code, " \t\r\n\"'") {
		return ""
	}
	if httpx.SanitizeFailure(code) != code {
		return ""
	}
	return code
}

func limitFailure(s string, n int) string {
	if s == "" || n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	i := 0
	for idx := range s {
		if i == n {
			return s[:idx] + "..."
		}
		i++
	}
	return s
}
