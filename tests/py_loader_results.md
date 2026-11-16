# failproxy Python loader rules: test results

Rules: `yara/failproxy_python_loader.yar` (failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper)

- Family repos hit: 36/36
- Non-family repos in corpus hit: 0/7
- Benign .py files scanned: 96893
- Benign false positives: 0


## Benign corpus

96,893 .py files, all local or public package downloads, no repo code run:
- 92,371 content-unique .py files (sha1 dedupe) from every Python stdlib on this Mac (Homebrew, Xcode/CLT, uv-managed), ~/.cache/uv, and every site-packages dir under ~ (147 source roots in total; research folders excluded). Includes cryptography, urllib3, requests, httpx, aiohttp, botocore/boto3, impacket, pycryptodome (Crypto), pip.
- 4,255 .py files from 46 win_amd64 / pure-Python wheels: pefile, pymem, frida-tools, pywin32, pywin32-ctypes, comtypes, paramiko, asyncssh, pyinstaller, pycryptodome(x), lief, capstone, unicorn, speakeasy-emulator, minidump, pypykatz, dnfile, pyinjector, pywinauto, pwntools, scapy, volatility3, oletools, pyopenssl, httpcore, websockets, jwcrypto, pynacl, hvac, azure-identity, google-auth, boto3, botocore, impacket and others.
- 267 .py files from sdists/source: winappdbg 1.5, pyftpdlib 2.2.0, naksyn/PythonMemoryModule (GitHub HEAD).

Near-miss check (loosened single-anchor rules over the same corpus): the only benign file with VirtualAlloc plus DIR64-reloc/ordinal-flag code is PythonMemoryModule pythonmemorymodule/__init__.py. It carries 7 of the 8 core mapper anchors but has no CreateThread and no ExitProcess/TerminateProcess-to-ExitThread redirect, so failproxy_py_pe_mapper does not fire. No benign file combines stdin.buffer.read() + stdin=PIPE + CREATE_NO_WINDOW, "--resolve" with CERT_NONE or :443:, or a nonce/ts/sig JSON handshake.

Confirmed family list: tests/family_repos.txt (29 live family_sweep repos + 7 variants source dirs; the 2 deleted repos have no source). Non-family dirs are the screened repos in family_sweep/raw/src.

Run: scripts/test_py_rules.py rules/failproxy_python_loader.yar --family tests/family_repos.txt --repos family_sweep/raw/src variants/raw/src --benign <benign dirs> --out tests/py_loader_results.md
## Per-rule repo coverage (family)

- failproxy_py_c2_transport: 36/36
- failproxy_py_headless_stager: 36/36
- failproxy_py_kit_material: 35/36
- failproxy_py_pe_mapper: 36/36

## Family repos

| repo | rules hit | files |
|---|---|---|
| Danuse84__Exodus-Fake-Balance | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | helpers/__init__.py.txt, helpers/arch.py.txt, helpers/executor.py.txt, helpers/fetcher.py.txt |
| Gemma41__Onchain-Accounting | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | service/__init__.py.txt, service/courier.py.txt, service/imaging.py.txt, service/sysinfo.py.txt |
| Kimberlyfriis__TRX-Drainer-Tool | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | system/__init__.py.txt, system/channel.py.txt, system/executor.py.txt, system/host.py.txt |
| MelisaPeteRs2006__Silent-Crypto-Miner | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | engine/__init__.py.txt, engine/processor.py.txt, engine/runtime.py.txt, engine/transport.py.txt, run.bat.txt |
| MyZahradamiyas1816__Seed-Generator | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | run.bat.txt, vault/__init__.py.txt, vault/connector.py.txt, vault/handler.py.txt, vault/platform.py.txt |
| Soniavasseur__Wallet-Risk-Scanner | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | ledger/__init__.py.txt, ledger/caps.py.txt, ledger/executor.py.txt, ledger/httpc.py.txt |
| adampcber1234__seed-generator | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | run.bat.txt, vault/__init__.py.txt, vault/connector.py.txt, vault/handler.py.txt, vault/platform.py.txt |
| ashleydarosa__CC-Checker-Validator-Generator | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | fabric/__init__.py.txt, fabric/invoker.py.txt, fabric/profiles.py.txt, fabric/uplink.py.txt |
| aylla18__Polymarket-Market-Agent | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | support/__init__.py.txt, support/bridge.py.txt, support/plugin.py.txt, support/site.py.txt |
| calebe95__trade-bot-hyperliquid | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | runtime/__init__.py.txt, runtime/host.py.txt, runtime/loader.py.txt, runtime/net.py.txt |
| chord1990__Lighter-Airdrop-Tracker | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | internal/__init__.py.txt, internal/context.py.txt, internal/engine.py.txt, internal/link.py.txt |
| dugffoanh1992__Keylogger-Crypto-Clipper | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | hooks/__init__.py.txt, hooks/runner.py.txt, hooks/sender.py.txt, run.bat.txt, run.sh.txt |
| else24__kalshi-market-bot | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | syslib/__init__.py.txt, syslib/channel.py.txt, syslib/image.py.txt, syslib/system.py.txt |
| frantiska21__trade-bot-hyperliquid | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | runtime/__init__.py.txt, runtime/host.py.txt, runtime/loader.py.txt, runtime/net.py.txt |
| goulash23__stablecoin-payment-gateway | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | pipeline/__init__.py.txt, pipeline/environ.py.txt, pipeline/materializer.py.txt, pipeline/session.py.txt |
| hurside69__Polymarket-Perpetual-Bot | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | support/__init__.py.txt, support/bridge.py.txt, support/plugin.py.txt, support/site.py.txt |
| isabelpapaya__MCP-Server-Lighter | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_pe_mapper | base/__init__.py.txt, base/carrier.py.txt, base/relay.py.txt |
| jeffreyquinn95__Hyperliquid-Leaderboard-Analytics | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | core/__init__.py.txt, core/config.py.txt, core/native.py.txt, core/wire.py.txt |
| joannarogers2005__stablecoin-payment-gateway | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | pipeline/__init__.py.txt, pipeline/environ.py.txt, pipeline/materializer.py.txt, pipeline/session.py.txt |
| lalouannabel0072__kalshi-trading-bot | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | syslib/__init__.py.txt, syslib/channel.py.txt, syslib/image.py.txt, syslib/system.py.txt |
| lyp2431-stack__Srxs | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | system/__init__.py.txt, system/channel.py.txt, system/executor.py.txt, system/host.py.txt |
| marisanilsson33__Solana-Drainer-Tool | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | modules/__init__.py.txt, modules/executor.py.txt, modules/relay.py.txt, run.bat.txt |
| mav187__m | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | modules/__init__.py.txt, modules/executor.py.txt, modules/relay.py.txt, run.bat.txt |
| mdasneves2006__stablecoin-payment-gateway | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | pipeline/__init__.py.txt, pipeline/environ.py.txt, pipeline/materializer.py.txt, pipeline/session.py.txt |
| miloslavatangen__Checker-Mnemonic | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | scanner/__init__.py.txt, scanner/client.py.txt, scanner/env.py.txt, scanner/worker.py.txt |
| ninamorozov1982__Aster-Dex-Airdrop-Tracker | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | vault/__init__.py.txt, vault/env.py.txt, vault/runtime.py.txt, vault/transport.py.txt |
| noloyswy1993__Tonkeeper-Fake-Balance | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | backend/__init__.py.txt, backend/env.py.txt, backend/executor.py.txt, backend/gateway.py.txt |
| pverhoeven74__Crypto-Clipper | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | hooks/__init__.py.txt, hooks/runner.py.txt, hooks/sender.py.txt, run.bat.txt, run.sh.txt |
| sabinastone7__Polymarket-Trading-Bot | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | support/__init__.py.txt, support/bridge.py.txt, support/plugin.py.txt, support/site.py.txt |
| sandskatherinenymph__Electrum-Fake-Balance | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | runtime/__init__.py.txt, runtime/env.py.txt, runtime/executor.py.txt, runtime/session.py.txt |
| tigerogijzooav__Hyperliquid-Trade-Bot | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | runtime/__init__.py.txt, runtime/host.py.txt, runtime/loader.py.txt, runtime/net.py.txt |
| trinity1994__MCP-Server-Aster-DEX | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | kernel/__init__.py.txt, kernel/instance.py.txt, kernel/node.py.txt, kernel/route.py.txt |
| warmknight30__silent-crypto-miner | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | engine/__init__.py.txt, engine/processor.py.txt, engine/runtime.py.txt, engine/transport.py.txt, run.bat.txt |
| zacharias80__Polymarket-Prediction-Bot | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | support/__init__.py.txt, support/bridge.py.txt, support/plugin.py.txt, support/site.py.txt |
| zacharyrogue__Crypto-Whale-Tracker | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | backplane/__init__.py.txt, backplane/conduit.py.txt, backplane/hostinfo.py.txt, backplane/stager.py.txt |
| zgraham1981__Stablecoin-Payment-Gateway | failproxy_py_c2_transport, failproxy_py_headless_stager, failproxy_py_kit_material, failproxy_py_pe_mapper | pipeline/__init__.py.txt, pipeline/environ.py.txt, pipeline/materializer.py.txt, pipeline/session.py.txt |

## Non-family repos

- Ashvinsai__tracecrypt: no match
- EmanuelNog__comfyui-isolated-amdrocm-base: no match
- arpitparashar06__SituSim: no match
- kloworizer__kangedit: no match
- solstice_vendor: no match
- tanisaaiml-cell__FlowCast-Ai-Tracffic-prediction: no match
- zhou-jin-xin__ai-data-analyst: no match

## Benign false positives

none
