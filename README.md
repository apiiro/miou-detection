# MIOU / Beretta detection rules

Detection content for MIOU, a malware operation that ships trojanized Python MCP servers and crypto tools on GitHub. Starting the server (for example from an MCP client such as Claude Desktop, Cursor or Cline) fetches an encrypted payload that maps the private "Beretta" stealer in memory and installs a persistent clipboard clipper (`msedgeview.dll`, per-user COM hijack, `rundll32 …,#3`).

## Contents

| Path | What |
|---|---|
| `yara/failproxy_python_loader.yar` | 4 rules for the Python loader in the repos (hidden stdin stager, ctypes PE mapper, Cloudflare/curl fallback transport, kit material) |
| `yara/miou_beretta.yar` | 6 rules for binaries: stage 3 crypter, stage 4 loader, Beretta image and in-memory image, clipper DLL, app-bound-encryption helper DLL |
| `sigma/` | 6 Sigma rules: hidden Python child fed over stdin, rundll32 ordinal #3 from AppData, clipper file drop, COM hijack registry write, browser started with a `%TEMP%\v20_*` profile, `CrHlp_*` named pipe (app-bound encryption bypass) |
| `kql/miou_mde.kql` | Microsoft Defender for Endpoint hunting queries |
| `tests/` | Test results: recall on known family samples and false positives on benign corpora |

## Test results

- Python loader YARA: 36/36 known family repos, 0 false positives on 96,893 benign Python files.
- Binary YARA: all known stages hit, 0 false positives on 1,478 benign Windows PEs.
- YARA Forge (11,852 community rules): no hits on stage 3, stage 4, the clipper or the Beretta image.

## Usage

```
yara -r yara/ <path-to-cloned-repo-or-sample>
```

Author: Shmulik Cohen (Apiiro).
