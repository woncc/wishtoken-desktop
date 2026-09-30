# WishToken Desktop

[中文](README.md) · [Downloads](https://github.com/xxx-holic/wishtoken-desktop/releases) · [WishToken](https://wishtoken.team/?utm_source=github&utm_medium=readme)

An open-source desktop companion for WishToken and Codex. Import authorized Team account JSON, inspect quotas, switch accounts and launch isolated Codex App or CLI workspaces on Windows and macOS.

Select BPS or native Codex explicitly (BPS by default). Sessions remain pinned to their account and channel. Native speed preferences are recorded separately from the service tier actually reported upstream. Visual pelican comparisons support batch runs, isolated HTML previews and saved results; they are not intelligence scores or proof of the upstream model identity.

Account credentials stay in the local data directory. There is no telemetry, embedded account, invitation credential, or automatic upload to WishToken. Optional site and release links open in your browser. Invitation announcements are published irregularly through the [project announcements](https://github.com/xxx-holic/wishtoken-desktop/discussions/categories/announcements) and the website.

See the [setup guide](docs/QUICKSTART.md), [privacy documentation](docs/PRIVACY.md), [security policy](SECURITY.md) and [contribution guide](CONTRIBUTING.md). Release notes describe validation status. macOS downloads are unsigned development bundles unless a release explicitly states otherwise.

Build with Go 1.25+, Node.js 24 and npm: `go test ./...`, then `cd desktop`, `npm ci`, `npm test` and `npm run dist:win` or `npm run dist:mac` on the appropriate platform.

MIT licensed; third-party notices are in [NOTICE.md](NOTICE.md). This project is not affiliated with OpenAI or Microsoft.
