// Package httpx builds outbound HTTP clients with optional proxies.
package httpx

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Options tunes a client.
type Options struct {
	// ProxyURL routes traffic through http://, https:// or socks5:// proxies.
	// Empty means the standard HTTPS_PROXY / NO_PROXY environment applies.
	ProxyURL string
	// ResponseHeaderTimeout bounds the wait for response headers. Zero means
	// unbounded, which streaming reasoning responses require.
	ResponseHeaderTimeout time.Duration
	// Timeout is the whole-request timeout (zero for streaming clients).
	Timeout time.Duration
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*http.Client{}
)

// NewClient returns a client honouring opts. Clients are cached per option
// set so connection pools are reused.
func NewClient(opts Options) (*http.Client, error) {
	key := fmt.Sprintf("%s|%d|%d", opts.ProxyURL, opts.ResponseHeaderTimeout, opts.Timeout)
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, ok := cache[key]; ok {
		return c, nil
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
	}
	if raw := strings.TrimSpace(opts.ProxyURL); raw != "" {
		parsed, err := ParseProxyURL(raw)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	c := &http.Client{Transport: transport, Timeout: opts.Timeout}
	cache[key] = c
	return c, nil
}

// ParseProxyURL validates a proxy URL. socks5h is mapped to socks5, which the
// Go transport resolves remotely as well.
func ParseProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid proxy url")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "socks5":
	case "socks5h":
		parsed.Scheme = "socks5"
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https or socks5)", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("proxy url has no host")
	}
	return parsed, nil
}

// Redact hides credentials embedded in a proxy URL for logging and management
// responses. A schemeless user:password@host value is recognized too.
// A space or bad percent escape makes url.Parse fail; those passwords are
// scrubbed instead of returned unchanged.
func Redact(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	candidate := raw
	restore := ""
	if !strings.Contains(raw, "://") {
		if strings.HasPrefix(raw, "//") {
			// Prepending "http://" would produce "http:////user..." and hide userinfo.
			candidate = "http:" + raw
			restore = "//"
		} else {
			candidate = "http://" + raw
			restore = "schemeless"
		}
	}
	parsed, err := url.Parse(candidate)
	if err == nil && parsed.User != nil {
		// user%3Apassword is decoded into the username, so Password() is empty
		// while the secret is still visible in the original text.
		if _, ok := parsed.User.Password(); !ok {
			if name, secret, found := strings.Cut(parsed.User.Username(), ":"); found && secret != "" {
				parsed.User = url.UserPassword(name, secret)
			}
		}
		if _, ok := parsed.User.Password(); !ok {
			return raw
		}
		redacted := parsed.Redacted()
		switch restore {
		case "schemeless":
			redacted = strings.TrimPrefix(redacted, "http://")
		case "//":
			redacted = "//" + strings.TrimPrefix(redacted, "http://")
		}
		return redacted
	}
	if scrubbed, ok := scrubProxyUserinfo(raw); ok {
		return scrubbed
	}
	return raw
}

// scrubProxyUserinfo replaces a password in user:password@host when url.Parse
// rejects the string. Username-only values are left unchanged.
func scrubProxyUserinfo(raw string) (string, bool) {
	at := strings.LastIndex(raw, "@")
	if at <= 0 {
		return "", false
	}
	head, tail := raw[:at], raw[at:]
	prefix, userinfo := "", head
	if i := strings.Index(head, "://"); i >= 0 {
		prefix = head[:i+3]
		userinfo = head[i+3:]
	} else if strings.HasPrefix(head, "//") {
		prefix = "//"
		userinfo = head[2:]
	}
	colon := strings.Index(userinfo, ":")
	if colon < 0 {
		return "", false
	}
	return prefix + userinfo[:colon] + ":xxxxx" + tail, true
}

// PreserveProxy returns current when incoming is empty of changes or is only
// the redacted form of current. Callers can show Redact(current) in an editor
// and accept it back without storing the mask as the password.
func PreserveProxy(current, incoming string) string {
	incoming = strings.TrimSpace(incoming)
	current = strings.TrimSpace(current)
	if incoming == "" || current == "" {
		return incoming
	}
	if incoming == current || incoming == Redact(current) {
		return current
	}
	return incoming
}
