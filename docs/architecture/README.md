# Architecture evidence

Source review: `5b18ed5662041fc254e9ca5c13de9280548578ca` (2026-10-09).

The marked Mermaid block in [README](../../README.md) is the only maintained diagram source. GitHub renders it natively in the reader's theme. No duplicate SVG or independent `.mmd` is committed; extracted Mermaid and SVG files are disposable verification artifacts.

本图只描述远端主分支的 Windows PowerShell 客户端，不包含其他分支的 Android 实现。所有网络调用由 `whut-net.ps1` 发起；配置和 DPAPI 密码保存在当前用户本地目录。凭据发送前检查 Portal allowlist 和 Windows 物理网络配置。

Portal 当前使用 HTTP，DPAPI 只保护本地密码，不能提供传输加密。登录接口返回后还需核对账号状态和实际联网结果。当前源码没有自动重试循环或退避模块：失败返回明确 exit code；后续重试来自用户再次调用，或已安装任务的下一次登录/联网事件。不得把一次 750 ms 等待画成重试机制。

## Source map

- [whut-net.ps1](../../whut-net.ps1): `function Test-Internet`, `function Resolve-PortalSession`, `function Test-TrustedLocalNetwork`, `function Read-ProtectedPassword`, `function Invoke-LoginCommand`, `Start-Sleep -Milliseconds 750`, `function Install-WhutScheduledTask`

The anchors in `evidence.json` catch renamed/deleted source symbols; they do not prove call semantics. The source review above checked the actual call sites and boundaries. A significant change to data flow, persistence, authentication, recovery or process boundaries requires reviewing this diagram and updating the evidence. Routine edits do not require redrawing it.

## Verification

Requires Python 3, Node.js 22+ and network access for the documentation-only Mermaid CLI. From the repository root:

```sh
python docs/architecture/verify.py --render
```

This checks local README image references and source anchors, extracts the authoritative block, renders it twice with Mermaid CLI 11.12.0 using deterministic IDs, compares SVG bytes, validates SVG XML, and also renders the dark theme. If the bundled browser is unavailable, pass `--chrome /absolute/path/to/chrome` (or set `PUPPETEER_EXECUTABLE_PATH`). The CLI version is pinned; its transitive npm dependencies and the browser are environment-dependent, so the byte comparison proves repeatability within the same installed toolchain. Output goes to a temporary directory, never application runtime dependencies. GitHub Markdown/browser rendering still requires visual review; CLI validation alone is not evidence of GitHub rendering.

GitDiagram returned an initial diagram on 2026-10-09 for the public repository as a discovery aid. Its page reported **0 source files read**, so its README-derived connections were checked directly against the local PowerShell source. Its generated output is not imported as authoritative architecture or licensed artwork. No private source, config or credentials were submitted.

Existing repository licenses and third-party notices continue to apply. These diagrams are documentation authored from this repository's public source; no app icons, installer assets or third-party marks are replaced.
