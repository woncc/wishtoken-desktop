package server

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/basispoints"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/localcodex"
	"github.com/xxx-holic/wishtoken-desktop/internal/pool"
	"github.com/xxx-holic/wishtoken-desktop/internal/router"
)

// Cockpit owns account storage, refresh and quota. The bridge accepts only the
// token attached by the selected Codex OAuth instance, never a refresh token.
// This separate in-memory pool prevents persistence and account substitution.
func (s *Server) initCockpit() {
	s.cockpitStore, _ = account.Open("")
	cfg := func() *config.Config {
		c := *s.Config()
		c.ActiveAccountID = ""
		c.RoutePolicy = config.PolicyBPSOnly
		c.NativeFallback = false
		c.AutoRefresh = false
		c.UsageProbe = false
		return &c
	}
	p := pool.New(s.cockpitStore, cfg)
	s.cockpitRouter = &router.Router{Config: cfg, Pool: p, BPS: s.Router.BPS, Codex: s.Codex, Replay: basispoints.NewReplayCache(), Attachments: &basispoints.AttachmentCache{}, Observer: s.logs.add}
}

func (s *Server) handleCockpit(w http.ResponseWriter, r *http.Request) {
	key := s.Config().CockpitKey
	// Empty addresses and hostnames are not proof of a loopback socket.
	if !config.IsLoopbackPeer(r.RemoteAddr) || key == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-GPTBridge-Cockpit")), []byte(key)) != 1 {
		writeError(w, r, 401, "cockpit_plugin_auth", "authentication_error", "请通过已配置的 GPTBridge BPS 实例连接")
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeError(w, r, 403, "csrf", "permission_error", "cross-site requests are not allowed")
		return
	}
	if r.URL.Path == "/cockpit/v1/models" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(localcodex.Catalog())
		return
	}
	if r.URL.Path != "/cockpit/v1/responses" || r.Method != http.MethodPost {
		writeError(w, r, 400, "unsupported_cockpit_endpoint", "invalid_request_error", "此实例使用 BPS Responses HTTP 流式接口")
		return
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") || len(auth) > 32768 {
		writeError(w, r, 401, "missing_oauth_token", "authentication_error", "Codex 未发送所选子号的 OAuth access_token")
		return
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	workspace := strings.TrimSpace(r.Header.Get("Chatgpt-Account-Id"))
	if workspace == "" {
		workspace = strings.TrimSpace(r.Header.Get("X-OpenAI-Account-Id"))
	}
	raw, _ := json.Marshal(object{"access_token": token, "workspace_id": workspace})
	parsed, err := account.Parse(raw, "cockpit-oauth")
	if err != nil || len(parsed.Accounts) != 1 {
		writeError(w, r, 401, "invalid_oauth_token", "authentication_error", "无法识别所选子号的 OAuth 凭据")
		return
	}
	a := parsed.Accounts[0]
	if a.AccountID == "" || a.AccessToken == "" || a.Expired() {
		writeError(w, r, 401, "expired_oauth_token", "authentication_error", "子号凭据缺少工作区或已经过期，请在 Cockpit 刷新或重新导入")
		return
	}
	a.RefreshToken = ""
	a.IDToken = ""
	for _, cached := range s.cockpitStore.List() {
		if cached.Expired() {
			_ = s.cockpitStore.Delete(cached.ID)
		}
	}
	up, err := s.cockpitStore.Upsert(a)
	if err != nil {
		writeError(w, r, 500, "cockpit_account_error", "server_error", "无法准备子号请求")
		return
	}
	request := r.Clone(r.Context())
	request.Header = r.Header.Clone()
	request.Header.Set("X-GPTBridge-Account", up.ID)
	request.Header.Del("X-GPTBridge-Cockpit")
	// Native auth is used only by the upstream credential adapter, never by
	// local API-key validation. Responses retains its normal streaming parser.
	child := &Server{cfg: s.cockpitRouter.Config(), Router: s.cockpitRouter, Store: s.cockpitStore, Pool: s.cockpitRouter.Pool, Codex: s.Codex}
	w.Header().Set("X-GPTBridge-Integration", "cockpit-oauth")
	child.handleResponses(w, request)
}
