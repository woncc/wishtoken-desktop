package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
)

// UsageURL is the zero-cost ChatGPT usage endpoint used by Codex clients.
const UsageURL = "https://chatgpt.com/backend-api/wham/usage"

// UsageIdentity carries the client identity headers used for the probe.
type UsageIdentity struct {
	UserAgent  string
	Originator string
	Version    string
}

// QueryUsage fetches the 5h/7d rate limit windows of acc.
func QueryUsage(ctx context.Context, client *http.Client, acc *account.Account, ident UsageIdentity) (*account.Usage, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if strings.TrimSpace(acc.AccessToken) == "" {
		return nil, fmt.Errorf("account has no access token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, UsageURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+acc.AccessToken)
	req.Header.Set("Accept", "application/json")
	if ident.UserAgent != "" {
		req.Header.Set("User-Agent", ident.UserAgent)
	}
	if ident.Originator != "" {
		req.Header.Set("Originator", ident.Originator)
	}
	if ident.Version != "" {
		req.Header.Set("Version", ident.Version)
	}
	if acc.AccountID != "" {
		req.Header.Set("Chatgpt-Account-Id", acc.AccountID)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, &UsageError{Status: resp.StatusCode, detail: usageFailureDetail(string(body), acc.AccessToken)}
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse usage response: %w", err)
	}
	usage := &account.Usage{UpdatedAt: time.Now()}
	if plan := stringField(raw, "plan_type"); plan != "" && acc.PlanType == "" {
		acc.PlanType = plan
	}
	if rl, ok := raw["rate_limit"].(map[string]any); ok {
		if v, ok := rl["limit_reached"].(bool); ok {
			usage.LimitReached = v
		}
		usage.Primary = parseWindow(rl["primary_window"])
		usage.Secondary = parseWindow(rl["secondary_window"])
	}
	return usage, nil
}

// UsageError is a non-200 answer from the usage endpoint.
// The raw response is not retained; detail is safe to store and return.
type UsageError struct {
	Status int
	detail string
}

func (e *UsageError) Error() string {
	if e == nil {
		return "usage endpoint error"
	}
	if e.detail == "" {
		return fmt.Sprintf("usage endpoint returned %d", e.Status)
	}
	return fmt.Sprintf("usage endpoint returned %d: %s", e.Status, e.detail)
}

func parseWindow(v any) *account.Window {
	m, ok := v.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	w := &account.Window{}
	w.UsedPercent = floatField(m, "used_percent", "usedPercent")
	w.WindowSeconds = int(floatField(m, "limit_window_seconds", "limitWindowSeconds"))
	if resetAt := floatField(m, "reset_at", "resetAt"); resetAt > 0 {
		w.ResetAt = time.Unix(int64(resetAt), 0)
	} else if after := floatField(m, "reset_after_seconds", "resetAfterSeconds"); after > 0 {
		w.ResetAt = time.Now().Add(time.Duration(after) * time.Second)
	}
	return w
}

func stringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func floatField(m map[string]any, keys ...string) float64 {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return v
		case json.Number:
			f, _ := v.Float64()
			return f
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				return f
			}
		}
	}
	return 0
}
