// Command gptbridge runs a local Team-account bridge and an isolated Codex launcher.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/xxx-holic/wishtoken-desktop/internal/account"
	"github.com/xxx-holic/wishtoken-desktop/internal/api"
	"github.com/xxx-holic/wishtoken-desktop/internal/basispoints"
	"github.com/xxx-holic/wishtoken-desktop/internal/codexcfg"
	"github.com/xxx-holic/wishtoken-desktop/internal/config"
	"github.com/xxx-holic/wishtoken-desktop/internal/httpx"
	"github.com/xxx-holic/wishtoken-desktop/internal/oauth"
	"github.com/xxx-holic/wishtoken-desktop/internal/router"
	"github.com/xxx-holic/wishtoken-desktop/internal/server"
	"github.com/xxx-holic/wishtoken-desktop/internal/version"
)

const usage = `gptbridge — 本地 GPT 不降智桥接 / local Basispoints bridge

用法 / Usage:
  gptbridge cockpit                   启动 Cockpit 与本地 BPS（默认动作）
  gptbridge desktop                   打开独立本地面板
  gptbridge stop                      停止本地服务
  gptbridge serve [--listen 127.0.0.1:8791] [--proxy URL] [--open]
  gptbridge import <file|dir|-> [--source NAME] [--no-refresh]
  gptbridge import --codex            从 ~/.codex/auth.json 导入 (codex login)
  gptbridge import --cpa [DIR]        从 CLIProxyAPI 凭据目录导入
  gptbridge login                     浏览器 OAuth 登录并导入
  gptbridge accounts [list|remove ID|refresh [ID]|usage [ID]|export --format cpa|codex -o FILE]
  gptbridge check                     检查凭据、代理与上游连通性
  gptbridge test [--model M] [--route bps|codex]   发送一条探测请求
  gptbridge codex-config [--model M] [--effort E] [--remove]  写入 Codex config.toml
  gptbridge claude-config             打印 Claude Code 环境变量
  gptbridge version

环境变量 / Env: GPTBRIDGE_HOME GPTBRIDGE_LISTEN GPTBRIDGE_PROXY GPTBRIDGE_API_KEY
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) == 0 {
		cmd = "cockpit"
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	var err error
	switch cmd {
	case "cockpit":
		err = runCockpit(args)
	case "desktop":
		err = runDesktop()
	case "stop":
		err = runStop()
	case "serve", "run", "start":
		err = runServe(args)
	case "import":
		err = runImport(args)
	case "login":
		err = runLogin(args)
	case "accounts", "account":
		err = runAccounts(args)
	case "check", "doctor":
		err = runCheck(args)
	case "test", "ping":
		err = runTest(args)
	case "codex-config":
		err = runCodexConfig(args)
	case "claude-config":
		err = runClaudeConfig(args)
	case "version", "-v", "--version":
		fmt.Println(version.String())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if len(os.Args) == 1 {
			showStartupError(err.Error())
		}
		os.Exit(1)
	}
}

func loadConfig(fs *flag.FlagSet) (*config.Config, string, error) {
	path := config.Path()
	cfg, err := config.Load(path)
	if err != nil {
		return nil, path, err
	}
	return cfg, path, nil
}

func openStore() (*account.Store, error) {
	return account.Open(config.AccountsPath())
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "", "listen address (default from config, 127.0.0.1:8791)")
	proxy := fs.String("proxy", "", "outbound proxy URL, e.g. http://127.0.0.1:7890")
	openBrowser := fs.Bool("open", false, "open the dashboard in a browser")
	noUI := fs.Bool("no-ui", false, "disable the embedded dashboard")
	apiKey := fs.String("api-key", "", "require this bearer token on the API")
	policy := fs.String("route-policy", "", "bps_prefer | bps_only | codex_only")
	_ = fs.Parse(args)
	cfg, cfgPath, err := loadConfig(fs)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *proxy != "" {
		cfg.ProxyURL = *proxy
	}
	if *apiKey != "" {
		cfg.APIKey = *apiKey
	}
	if *policy != "" {
		cfg.RoutePolicy = *policy
	}
	if *noUI {
		cfg.WebUI = false
	}
	if err := cfg.Normalize(); err != nil {
		return err
	}
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		if err := cfg.Save(cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not write config:", err)
		}
	}
	store, err := openStore()
	if err != nil {
		return err
	}
	srv := server.New(cfg, cfgPath, store)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Printf("%s\n配置 / config: %s\n账号 / accounts: %d (%s)\n路由策略 / route policy: %s  BPS 模型: %s\n", version.String(), cfgPath, store.Count(), store.Path(), cfg.RoutePolicy, strings.Join(cfg.BPSModels, ","))
	if store.Count() == 0 {
		fmt.Println("提示：还没有账号。打开面板导入 JSON，或运行 `gptbridge import --codex` / `gptbridge login`。")
	}
	if *openBrowser {
		go func() {
			time.Sleep(600 * time.Millisecond)
			_ = browse("http://" + displayAddr(cfg.Listen) + "/")
		}()
	}
	return srv.ListenAndServe(ctx)
}

func displayAddr(listen string) string {
	host, port, ok := strings.Cut(listen, ":")
	if !ok {
		return listen
	}
	if host == "" || host == "0.0.0.0" || host == "[::]" || host == "::" {
		host = "127.0.0.1"
	}
	return host + ":" + port
}

func browse(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// ---------------------------------------------------------------------------
// import / login
// ---------------------------------------------------------------------------

func runImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	fromCodex := fs.Bool("codex", false, "import ~/.codex/auth.json")
	fromCPA := fs.Bool("cpa", false, "import CLIProxyAPI credential files (~/.cli-proxy-api)")
	source := fs.String("source", "", "label stored with the imported accounts")
	noRefresh := fs.Bool("no-refresh", false, "do not refresh tokens after import")
	_ = fs.Parse(args)
	cfg, _, err := loadConfig(fs)
	if err != nil {
		return err
	}
	var res *account.ImportResult
	label := *source
	switch {
	case *fromCodex:
		path := account.CodexAuthPath()
		if fs.NArg() > 0 {
			path = fs.Arg(0)
		}
		res, err = account.ParseFile(path)
		if label == "" {
			label = "codex-cli"
		}
	case *fromCPA:
		dir := account.CPADir()
		if fs.NArg() > 0 {
			dir = fs.Arg(0)
		}
		res, err = account.ParseDir(dir)
		if label == "" {
			label = "cpa"
		}
	default:
		if fs.NArg() == 0 {
			return fmt.Errorf("import needs a file, a directory, '-' for stdin, --codex or --cpa")
		}
		target := fs.Arg(0)
		if target == "-" {
			raw, rerr := io.ReadAll(os.Stdin)
			if rerr != nil {
				return rerr
			}
			res, err = account.Parse(raw, "stdin")
		} else if info, serr := os.Stat(target); serr == nil && info.IsDir() {
			res, err = account.ParseDir(target)
		} else {
			res, err = account.ParseFile(target)
		}
		if label == "" {
			label = filepath.Base(target)
		}
	}
	if err != nil {
		return err
	}
	store, err := openStore()
	if err != nil {
		return err
	}
	created, merged := 0, 0
	var ids []string
	for _, acc := range res.Accounts {
		acc.Source = label
		up, uerr := store.Upsert(acc)
		if uerr != nil {
			return uerr
		}
		ids = append(ids, up.ID)
		if up.Created {
			created++
		} else {
			merged++
		}
	}
	for _, w := range res.Warnings {
		fmt.Println("warning:", w)
	}
	fmt.Printf("导入 %d 个新账号，合并 %d 个，跳过 %d 个。 / imported %d, merged %d, skipped %d\n", created, merged, res.Skipped, created, merged, res.Skipped)
	if *noRefresh {
		return nil
	}
	client, err := httpx.NewClient(httpx.Options{ProxyURL: cfg.ProxyURL, Timeout: 60 * time.Second})
	if err != nil {
		return err
	}
	for _, id := range ids {
		acc, _ := store.Get(id)
		if acc.RefreshToken == "" || (acc.AccountID != "" && acc.AccessToken != "" && !acc.ExpiringWithin(10*time.Minute)) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		rerr := oauth.RefreshAccount(ctx, client, &acc)
		cancel()
		_ = store.Update(id, func(stored *account.Account) { *stored = acc })
		if rerr != nil {
			fmt.Printf("  %s: 刷新失败 / refresh failed: %v\n", acc.Label(), rerr)
		} else {
			fmt.Printf("  %s: 已刷新 (%s, 到期 %s)\n", acc.Label(), acc.PlanType, acc.ExpiresAt.Local().Format("2006-01-02 15:04"))
		}
	}
	return nil
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening a browser")
	_ = fs.Parse(args)
	cfg, _, err := loadConfig(fs)
	if err != nil {
		return err
	}
	client, err := httpx.NewClient(httpx.Options{ProxyURL: cfg.ProxyURL, Timeout: 60 * time.Second})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	session, err := oauth.StartLogin(ctx, client)
	if err != nil {
		return err
	}
	fmt.Println("请在浏览器中完成登录 / open this URL to sign in:")
	fmt.Println(session.AuthURL)
	if !*noBrowser {
		_ = browse(session.AuthURL)
	}
	tokens, err := session.Wait(ctx)
	if err != nil {
		return err
	}
	acc := account.Account{Source: "browser-login"}
	oauth.Apply(&acc, tokens)
	store, err := openStore()
	if err != nil {
		return err
	}
	up, err := store.Upsert(acc)
	if err != nil {
		return err
	}
	fmt.Printf("登录成功：%s (%s) id=%s\n", acc.Label(), acc.PlanType, up.ID)
	return nil
}

// ---------------------------------------------------------------------------
// accounts
// ---------------------------------------------------------------------------

func runAccounts(args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		args = args[1:]
	}
	store, err := openStore()
	if err != nil {
		return err
	}
	cfg, _, err := loadConfig(nil)
	if err != nil {
		return err
	}
	switch sub {
	case "list", "ls":
		list := store.List()
		if len(list) == 0 {
			fmt.Println("（无账号 / no accounts）")
			return nil
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tEMAIL\tPLAN\tACCOUNT\tSTATUS\tEXPIRES\tSOURCE")
		for _, acc := range list {
			v := acc.View()
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", acc.ID, acc.Email, acc.PlanType, v.AccountID, v.Status, v.ExpiresAt, acc.Source)
		}
		return tw.Flush()
	case "remove", "rm", "delete":
		if len(args) == 0 {
			return fmt.Errorf("accounts remove needs an account id")
		}
		return store.Delete(args[0])
	case "refresh":
		client, err := httpx.NewClient(httpx.Options{ProxyURL: cfg.ProxyURL, Timeout: 60 * time.Second})
		if err != nil {
			return err
		}
		for _, acc := range store.List() {
			if len(args) > 0 && acc.ID != args[0] {
				continue
			}
			if acc.RefreshToken == "" {
				fmt.Printf("%s: 无 refresh token，跳过\n", acc.Label())
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			current := acc
			rerr := oauth.RefreshAccount(ctx, client, &current)
			cancel()
			_ = store.Update(acc.ID, func(stored *account.Account) { *stored = current })
			if rerr != nil {
				fmt.Printf("%s: 失败 / failed: %v\n", acc.Label(), rerr)
			} else {
				fmt.Printf("%s: OK (到期 %s)\n", acc.Label(), current.ExpiresAt.Local().Format("2006-01-02 15:04"))
			}
		}
		return nil
	case "usage":
		client, err := httpx.NewClient(httpx.Options{ProxyURL: cfg.ProxyURL, Timeout: 30 * time.Second})
		if err != nil {
			return err
		}
		ident := serverIdentity(cfg)
		for _, acc := range store.List() {
			if len(args) > 0 && acc.ID != args[0] {
				continue
			}
			current := acc
			usage, uerr := oauth.QueryUsage(context.Background(), client, &current, ident)
			if uerr != nil {
				fmt.Printf("%s: %v\n", acc.Label(), uerr)
				continue
			}
			_ = store.Update(acc.ID, func(stored *account.Account) { stored.Usage = usage; stored.PlanType = current.PlanType })
			fmt.Printf("%s: %s\n", acc.Label(), formatUsage(usage))
		}
		return nil
	case "export":
		fs := flag.NewFlagSet("export", flag.ExitOnError)
		format := fs.String("format", "cpa", "cpa | codex")
		out := fs.String("o", "", "owner-only output file (required; stdout is refused)")
		_ = fs.Parse(args)
		return exportAccounts(store.List(), *format, *out)
	default:
		return fmt.Errorf("unknown accounts subcommand %q", sub)
	}
}

func exportAccounts(accounts []account.Account, format, out string) error {
	out = strings.TrimSpace(out)
	if out == "" || out == "-" {
		return fmt.Errorf("accounts export requires -o FILE; OAuth credentials are not written to stdout")
	}
	raw, err := account.ExportJSON(accounts, format)
	if err != nil {
		return err
	}
	return writeOwnerFile(out, raw)
}

func serverIdentity(cfg *config.Config) oauth.UsageIdentity {
	srv := server.New(cfg, "", &account.Store{})
	return oauth.UsageIdentity{UserAgent: srv.Codex.Identity.UserAgent, Originator: srv.Codex.Identity.Originator, Version: srv.Codex.Identity.Version}
}

func formatUsage(u *account.Usage) string {
	if u == nil {
		return "n/a"
	}
	parts := []string{}
	if u.Primary != nil {
		parts = append(parts, fmt.Sprintf("5h %.0f%% (reset %s)", u.Primary.UsedPercent, relative(u.Primary.ResetAt)))
	}
	if u.Secondary != nil {
		parts = append(parts, fmt.Sprintf("7d %.0f%% (reset %s)", u.Secondary.UsedPercent, relative(u.Secondary.ResetAt)))
	}
	if u.LimitReached {
		parts = append(parts, "LIMIT REACHED")
	}
	if len(parts) == 0 {
		return "no windows reported"
	}
	return strings.Join(parts, ", ")
}

func relative(t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	d := time.Until(t).Round(time.Minute)
	if d < 0 {
		return "now"
	}
	return d.String()
}

// ---------------------------------------------------------------------------
// check / test
// ---------------------------------------------------------------------------

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg, cfgPath, err := loadConfig(fs)
	if err != nil {
		return err
	}
	store, err := openStore()
	if err != nil {
		return err
	}
	fmt.Println(version.String())
	fmt.Printf("config      : %s\naccounts    : %s (%d)\nlisten      : %s\nroute policy: %s (bps models: %s, fallback=%v)\nproxy       : %s\n",
		cfgPath, store.Path(), store.Count(), cfg.Listen, cfg.RoutePolicy, strings.Join(cfg.BPSModels, ","), cfg.NativeFallback, orNone(httpx.Redact(cfg.ProxyURL)))
	client, err := httpx.NewClient(httpx.Options{ProxyURL: cfg.ProxyURL, Timeout: 20 * time.Second})
	if err != nil {
		return err
	}
	for _, target := range []string{"https://bps.openai.com/", "https://chatgpt.com/backend-api/codex/models", "https://auth.openai.com/"} {
		start := time.Now()
		resp, rerr := client.Get(target)
		if rerr != nil {
			fmt.Printf("reach %-46s FAIL %v\n", target, rerr)
			continue
		}
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		fmt.Printf("reach %-46s HTTP %d (%s)\n", target, resp.StatusCode, time.Since(start).Round(time.Millisecond))
	}
	for _, acc := range store.List() {
		v := acc.View()
		fmt.Printf("account %-28s plan=%-8s status=%-14s expires=%s\n", acc.Label(), orNone(acc.PlanType), v.Status, orNone(v.ExpiresAt))
	}
	st := codexcfg.Inspect(codexcfg.ConfigPath())
	fmt.Printf("codex config: %s (active provider: %s, bridge active: %v)\n", st.Path, orNone(st.ActiveProvider), st.BridgeActive)
	return nil
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func runTest(args []string) error {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	model := fs.String("model", "", "model to probe (default config default_model)")
	route := fs.String("route", "", "bps | codex (default policy)")
	prompt := fs.String("prompt", "Reply with exactly the single word: pong", "prompt to send")
	_ = fs.Parse(args)
	cfg, cfgPath, err := loadConfig(fs)
	if err != nil {
		return err
	}
	store, err := openStore()
	if err != nil {
		return err
	}
	srv := server.New(cfg, cfgPath, store)
	m := *model
	if m == "" {
		m = cfg.DefaultModel
	}
	switch *route {
	case "bps":
		m += ":bps"
	case "codex":
		m += ":codex"
	}
	body := map[string]any{"model": m, "input": *prompt, "instructions": "You are a connectivity probe. Follow the user's instruction literally.", "reasoning": map[string]any{"effort": "low"}}
	raw, _ := json.Marshal(body)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	start := time.Now()
	res, rerr := srv.Router.Responses(ctx, &router.Request{Raw: raw, Body: body, Headers: http.Header{}, Client: "cli-test"})
	if rerr != nil {
		return fmt.Errorf("%s (%s)", rerr.Message, rerr.Code)
	}
	defer res.Body.Close()
	collected, err := api.Collect(res.Body)
	if err != nil {
		return err
	}
	if collected.Failed != nil {
		return fmt.Errorf("upstream failed: %v", collected.Failed["message"])
	}
	in, out, _, _ := api.Usage(collected.Response)
	fmt.Printf("route=%s account=%s model=%s effort=%s %s\nusage: in=%d out=%d\n---\n%s\n", res.Route, res.Account, res.Model, res.Effort, time.Since(start).Round(time.Millisecond), in, out, api.OutputText(collected.Response))
	if len(res.Warnings) > 0 {
		fmt.Println("warnings:", strings.Join(res.Warnings, "; "))
	}
	return nil
}

// ---------------------------------------------------------------------------
// client configuration helpers
// ---------------------------------------------------------------------------

func runCodexConfig(args []string) error {
	fs := flag.NewFlagSet("codex-config", flag.ExitOnError)
	model := fs.String("model", "", "top-level model to set (default config default_model)")
	effort := fs.String("effort", "", "model_reasoning_effort to set (low|medium|high|xhigh)")
	remove := fs.Bool("remove", false, "remove the bridge provider block")
	printOnly := fs.Bool("print", false, "print the TOML snippet instead of writing")
	path := fs.String("path", "", "config.toml path (default ~/.codex/config.toml)")
	_ = fs.Parse(args)
	cfg, _, err := loadConfig(fs)
	if err != nil {
		return err
	}
	target := codexcfg.ConfigPath()
	if *path != "" {
		target = *path
	}
	m := *model
	if m == "" {
		m = cfg.DefaultModel
	}
	base := "http://" + displayAddr(cfg.Listen) + "/v1"
	projection := codexcfg.Projection{BaseURL: base, Model: m, Effort: *effort, APIKey: cfg.APIKey}
	if *printOnly {
		fmt.Print(codexcfg.Snippet(projection))
		return nil
	}
	if *remove {
		backup, err := codexcfg.Remove(target)
		if err != nil {
			return err
		}
		fmt.Printf("已移除桥接 provider，备份：%s\n", backup)
		return nil
	}
	backup, err := codexcfg.Apply(target, projection)
	if err != nil {
		return err
	}
	fmt.Printf("已写入 %s\n", target)
	if backup != "" {
		fmt.Printf("备份 / backup: %s\n", backup)
	}
	fmt.Printf("Codex 现在使用 provider %q → %s（模型 %s）。完全退出 Codex Desktop 后重新打开生效。\n", codexcfg.ProviderID, base, m)
	if _, known := basispoints.Known(basispoints.ResolveModel(m).Upstream); !known {
		fmt.Println("提示：该模型不在已知 Basispoints 模型目录中，可能会走原生 Codex 通道。")
	}
	return nil
}

func runClaudeConfig(args []string) error {
	cfg, _, err := loadConfig(nil)
	if err != nil {
		return err
	}
	base := "http://" + displayAddr(cfg.Listen)
	key := cfg.APIKey
	if key == "" {
		key = "gptbridge"
	}
	fmt.Printf("# bash / zsh\nexport ANTHROPIC_BASE_URL=%s\nexport ANTHROPIC_AUTH_TOKEN=%s\nexport ANTHROPIC_MODEL=%s\nexport ANTHROPIC_DEFAULT_OPUS_MODEL=gpt-6-astra\nexport ANTHROPIC_DEFAULT_SONNET_MODEL=gpt-5.6-sol\nexport ANTHROPIC_DEFAULT_HAIKU_MODEL=gpt-5.6-luna\nclaude\n\n", base, key, cfg.DefaultModel)
	fmt.Printf("# PowerShell\n$env:ANTHROPIC_BASE_URL=\"%s\"\n$env:ANTHROPIC_AUTH_TOKEN=\"%s\"\n$env:ANTHROPIC_MODEL=\"%s\"\n$env:ANTHROPIC_DEFAULT_OPUS_MODEL=\"gpt-6-astra\"\n$env:ANTHROPIC_DEFAULT_SONNET_MODEL=\"gpt-5.6-sol\"\n$env:ANTHROPIC_DEFAULT_HAIKU_MODEL=\"gpt-5.6-luna\"\nclaude\n", base, key, cfg.DefaultModel)
	return nil
}
