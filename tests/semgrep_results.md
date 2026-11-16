# mcp-hidden-loader Semgrep rules: test results

Rules: `rules/mcp_hidden_loader.semgrep.yml` (semgrep OSS)

- Family repos: 36 (tests/family_repos.txt); any-rule hit: 36/36
- Benign .py files scanned: 96893 (local benign corpus)
- Benign findings: 0; semgrep errors: family 0, benign 4
- Runtime: family 8s, benign 186s

## Per rule

| rule | severity | family recall | benign FP files |
|---|---|---|---|
| mcp-hidden-loader-decorator-background-job | WARNING | 36/36 | 0 |
| mcp-hidden-loader-hidden-interpreter-stdin | ERROR | 36/36 | 0 |
| mcp-hidden-loader-ctypes-pe-mapper | ERROR | 36/36 | 0 |
| mcp-hidden-loader-pinned-ip-no-tls-verify | ERROR | 29/36 | 0 |

Synthetic copycat (tests/fixtures/copycat_loader.py.txt): 4/4 rules fire (mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify)

## Notes

- Semgrep OSS 1.173.0, 4 rules, all technique-level (no domains, keys, paths or kit strings). Family code was read as text only: the `.py.txt` source files are copied to a temp dir as `.py` so semgrep parses them.
- mcp-hidden-loader-pinned-ip-no-tls-verify misses 7 repos because those variants have no TLS-off / pinned-relay transport at all (no `CERT_NONE`, no `--resolve` anywhere in the repo); their HTTP path is plain resolver-based. The other three rules still hit all 7.
- No AES-GCM-to-sink rule (task item 5): in all 36 repos the `AESGCM(...).decrypt` call and the spawn/mapper sit in different modules (0 files hold both), so an intra-file taint rule has no family recall. It needs Semgrep Pro interfile taint.
- Rules 1, 3 and 4b use a file-level `pattern-regex` with lookaheads as a same-module AND, with a structural anchor for the reported line. Rule 1's link from the decorator wrapper to the background job is same-module, not call-graph exact: the wrapper must call a bare function and delegate to the wrapped fn, in a module that starts a daemon thread or a hidden/detached interpreter. The import-time branch requires the called function itself to start the job.
- Tuning: the CPython `test_subprocess.py` echo tests (`-c` reading `sys.stdin.buffer.read()`) and PythonForWindows `winobject/process.py` (VirtualAlloc + CreateThread + a `0x40` constant elsewhere) were the only benign hits before tightening. Rule 2's `-c` branch now needs a hidden/detached creationflag or stdout+stderr to DEVNULL; rule 3 needs VirtualProtect( or an RWX constant on the VirtualAlloc line.
- Benign corpus: the same 96,893 .py files as tests/py_loader_results.md. The 92,371 local files are symlinks there, which semgrep skips, so the run uses a hardlinked copy (`benign_py_real`). 4 benign files did not fully parse (Python 3.14/3.15 syntax).

Run: `scripts/test_semgrep.sh <benign_py> <benign_py_real>` (writes this file; family trees and the copycat fixture are found relative to the script).

## Family misses per rule

- mcp-hidden-loader-decorator-background-job: none
- mcp-hidden-loader-hidden-interpreter-stdin: none
- mcp-hidden-loader-ctypes-pe-mapper: none
- mcp-hidden-loader-pinned-ip-no-tls-verify: Danuse84__Exodus-Fake-Balance, Kimberlyfriis__TRX-Drainer-Tool, lyp2431-stack__Srxs, marisanilsson33__Solana-Drainer-Tool, mav187__m, noloyswy1993__Tonkeeper-Fake-Balance, sandskatherinenymph__Electrum-Fake-Balance

## Non-family repos in the fetched corpus with hits

none

## Benign false positives

none

## Semgrep errors on benign files (skipped, not matched)

- Syntax error: benign/opt__homebrew__Cellar__python@3.14__3.14.8_2__Frameworks__Python.framework__Versions__3.14__lib__python3.14__test__support____init__.py
- Syntax error: benign/opt__homebrew__Cellar__python@3.15__3.15.0__Frameworks__Python.framework__Versions__3.15__lib__python3.15__test__support____init__.py
- PartialParsing: benign/opt__homebrew__Cellar__python@3.15__3.15.0__Frameworks__Python.framework__Versions__3.15__lib__python3.15__ctypes__util.py
- PartialParsing: benign/opt__homebrew__Cellar__python@3.15__3.15.0__Frameworks__Python.framework__Versions__3.15__lib__python3.15__webbrowser.py

## Family repo detail

| repo | rules | files |
|---|---|---|
| Danuse84__Exodus-Fake-Balance | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | helpers/__init__.py, helpers/executor.py |
| Gemma41__Onchain-Accounting | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | service/__init__.py, service/courier.py, service/imaging.py |
| Kimberlyfriis__TRX-Drainer-Tool | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | system/__init__.py, system/executor.py |
| MelisaPeteRs2006__Silent-Crypto-Miner | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | engine/__init__.py, engine/processor.py, engine/transport.py |
| MyZahradamiyas1816__Seed-Generator | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | vault/__init__.py, vault/connector.py, vault/handler.py |
| Soniavasseur__Wallet-Risk-Scanner | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | ledger/__init__.py, ledger/executor.py, ledger/httpc.py |
| adampcber1234__seed-generator | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | vault/__init__.py, vault/connector.py, vault/handler.py |
| ashleydarosa__CC-Checker-Validator-Generator | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | fabric/__init__.py, fabric/invoker.py, fabric/uplink.py |
| aylla18__Polymarket-Market-Agent | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | support/__init__.py, support/bridge.py, support/plugin.py |
| calebe95__trade-bot-hyperliquid | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | runtime/__init__.py, runtime/loader.py, runtime/net.py |
| chord1990__Lighter-Airdrop-Tracker | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | internal/__init__.py, internal/engine.py, internal/link.py |
| dugffoanh1992__Keylogger-Crypto-Clipper | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | hooks/__init__.py, hooks/runner.py, hooks/sender.py |
| else24__kalshi-market-bot | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | syslib/__init__.py, syslib/channel.py, syslib/image.py |
| frantiska21__trade-bot-hyperliquid | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | runtime/__init__.py, runtime/loader.py, runtime/net.py |
| goulash23__stablecoin-payment-gateway | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | pipeline/__init__.py, pipeline/materializer.py, pipeline/session.py |
| hurside69__Polymarket-Perpetual-Bot | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | support/__init__.py, support/bridge.py, support/plugin.py |
| isabelpapaya__MCP-Server-Lighter | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | base/__init__.py, base/carrier.py, base/relay.py |
| jeffreyquinn95__Hyperliquid-Leaderboard-Analytics | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | core/__init__.py, core/native.py, core/wire.py |
| joannarogers2005__stablecoin-payment-gateway | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | pipeline/__init__.py, pipeline/materializer.py, pipeline/session.py |
| lalouannabel0072__kalshi-trading-bot | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | syslib/__init__.py, syslib/channel.py, syslib/image.py |
| lyp2431-stack__Srxs | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | system/__init__.py, system/executor.py |
| marisanilsson33__Solana-Drainer-Tool | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | modules/__init__.py, modules/executor.py |
| mav187__m | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | modules/__init__.py, modules/executor.py |
| mdasneves2006__stablecoin-payment-gateway | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | pipeline/__init__.py, pipeline/materializer.py, pipeline/session.py |
| miloslavatangen__Checker-Mnemonic | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | scanner/__init__.py, scanner/client.py, scanner/worker.py |
| ninamorozov1982__Aster-Dex-Airdrop-Tracker | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | vault/__init__.py, vault/runtime.py, vault/transport.py |
| noloyswy1993__Tonkeeper-Fake-Balance | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | backend/__init__.py, backend/executor.py |
| pverhoeven74__Crypto-Clipper | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | hooks/__init__.py, hooks/runner.py, hooks/sender.py |
| sabinastone7__Polymarket-Trading-Bot | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | support/__init__.py, support/bridge.py, support/plugin.py |
| sandskatherinenymph__Electrum-Fake-Balance | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin | runtime/__init__.py, runtime/executor.py |
| tigerogijzooav__Hyperliquid-Trade-Bot | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | runtime/__init__.py, runtime/loader.py, runtime/net.py |
| trinity1994__MCP-Server-Aster-DEX | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | kernel/__init__.py, kernel/instance.py, kernel/route.py |
| warmknight30__silent-crypto-miner | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | engine/__init__.py, engine/processor.py, engine/transport.py |
| zacharias80__Polymarket-Prediction-Bot | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | support/__init__.py, support/bridge.py, support/plugin.py |
| zacharyrogue__Crypto-Whale-Tracker | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | backplane/__init__.py, backplane/conduit.py, backplane/stager.py |
| zgraham1981__Stablecoin-Payment-Gateway | mcp-hidden-loader-ctypes-pe-mapper, mcp-hidden-loader-decorator-background-job, mcp-hidden-loader-hidden-interpreter-stdin, mcp-hidden-loader-pinned-ip-no-tls-verify | pipeline/__init__.py, pipeline/materializer.py, pipeline/session.py |
