# 贡献与发布

请先在 Issue 中说明用户可见的问题、系统版本和脱敏复现步骤。协议修改应附确定性的本地 mock 测试；不要用真实账号构成测试夹具，也不要把上游回复能力等同于内部模型质量。

## 项目结构

- `desktop/`：Electron 主进程、受限 IPC、原生界面、账号切换和作品比较。
- `internal/`：Go 核心，账号存储、上游适配、路由、模型清单和本地服务。
- `cmd/gptbridge/`：兼容的核心服务入口；名称保留以便升级。
- `.github/workflows/`：测试及跨平台发布。
- `scripts/check-public.py`：源码和路径公开性检查。

新功能应说明数据流、兼容性和失败行为。不要添加静默的模型/档位/账号/通道替换，不要引入宽泛 shell IPC、关闭渲染器沙箱或开放远程管理监听。

## 本地验证

```sh
python scripts/check-public.py
gofmt -w ./cmd ./internal
go vet ./...
go test ./...
cd desktop
npm ci
npm test
npm run backend -- win32 x64
npm run smoke
```

`smoke` 是 Windows 上使用合成账号的真实 Electron/IPC/Go 集成检查，不访问真实账号。截图只写入忽略的 `build/validation/`。Mac 原生联动应在 Mac 实机验收，不能用交叉编译代替。

## 版本发布

1. 同步修改 `desktop/package.json`、`desktop/package-lock.json` 的版本，更新 `CHANGELOG.md`。
2. 运行源码检查、Go vet/test 和桌面测试，核对发布范围。
3. 为验证过的 main 提交打 `v<版本>` 标签。发布 workflow 验证标签与包版本一致，分别构建 Windows、Mac arm64、Mac x64。
4. 工作流生成校验和并创建 **草稿** Release。维护者检查三平台产物、签名状态和验收结果后再发布。未完成 Mac 实机验收的版本注明开发测试状态，不声称已签名或已公证。
5. 发布页只保留该版本安装/便携包、校验和及必要说明。源码由 Git 标签管理，不上传账号、内部报告、交接或本地会话。

依赖升级由 Dependabot 提 PR；自动检查通过不等于应自动合并。邀请码由维护者不定期发布公告，代码、CI 和安装包不嵌入有效邀请码或运营密钥。
