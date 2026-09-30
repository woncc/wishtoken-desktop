# Linux 使用说明

Linux x64 提供 WishToken Desktop 的完整账号管理、额度查询、BPS / 原生选择、鹈鹕测智和 Codex CLI 启动。发布流水线在 Ubuntu 24.04 原生构建和测试。其他发行版的系统库、托盘与窗口系统兼容性需实机确认。

## 安装

- Debian / Ubuntu：下载 deb 后执行 `sudo apt install ./WishToken-Desktop-<版本>-linux-x64.deb`，从应用菜单打开。
- AppImage：下载后在文件属性中允许执行，或运行 `chmod +x WishToken-Desktop-<版本>-linux-x64.AppImage`，再双击打开。部分发行版需要 FUSE 2 兼容库。
- tar.gz：解压到自己的应用目录，运行其中的 `wishtoken-desktop`。保留完整目录；不要只复制可执行文件。

安装包没有捆绑 Codex CLI。先按官方方式安装 CLI，例如 `npm install -g @openai/codex`，确认 `codex --version` 可运行，再重启 WishToken。自动寻找 PATH、`~/.local/bin`、`~/.npm-global/bin` 等位置。

需要图形桌面与系统终端。支持 Debian 默认终端、GNOME Terminal、Konsole、Xfce Terminal、MATE Terminal、Kitty、Alacritty 和 xterm。无桌面服务器不属于本客户端的 GUI 使用范围。

## 切换与启动

1. 导入账号 JSON，选择通道、模型、推理档位。
2. 在「启动方式」选择 Codex CLI，填写项目目录，点击「切换并启动」。
3. 在「最近项目」中继续该账号、该项目的会话。

图形 Codex App 需要另行安装与系统兼容的版本。没有检测到时，客户端默认提供 CLI；可手动选择已有图形程序的真实可执行文件。AppImage 包装器和单独 CLI 二进制不视为 Codex 图形程序。本项目不捆绑、下载或修改第三方 Codex App。

账号、额度、作品和本地配置仍保存在 `~/.gptbridge-desktop`。卸载不会自动删除此目录。主 App 接管、恢复与备份规则见 [使用说明](QUICKSTART.md)。

## 系统限制

Electron 依赖系统 GTK、NSS、音频、图形和沙箱支持。请以普通用户运行，不要使用 root 或通过 `--no-sandbox` 关闭浏览器沙箱。若系统策略阻止 Chromium 沙箱，优先使用 deb 安装包或咨询系统管理员。

GNOME 等不提供托盘的桌面可安装托盘扩展；关闭主窗口会保留后台服务，再次启动客户端可重新显示窗口。Linux 自动测试使用 Xvfb，不代表所有 Wayland、显卡和发行版已验证。
