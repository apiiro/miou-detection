# MIOU and Beretta: technical notes

Beretta is a C++ infostealer that labels itself `// Beretta Private build 2.1`. It has no public record. It reaches victims through MIOU, an operation of 34 GitHub repos that includes two MCP servers an AI client starts for you; the delivery story and the money are in the Apiiro write-up. These notes are for people who have to take the sample apart.

Two findings matter most. The loader turns its anti-debugging checks into the decryption key, so a debugger, an emulator or an instrumentation tool gets a clean exit and no stealer instead of an alert. And the same build key leaks through the loader's API-hash routine, so one function gives an analyst everything needed to unpack the payload statically. Beretta is also private, misattributed to StealC, and missed by every community YARA rule we tried.

No decrypted stage touches disk until the clipper. A cloned repo starts a hidden child `python.exe -c "…d=sys.stdin.buffer.read();from base.carrier import mount;mount(d)"` and pipes it a PE. Everything after that runs inside that one child:

1. Stage 3, the MIOU crypter: a 10 MB `taskhostw.exe` look-alike. Every payload byte costs a gather index into a 2 MB decoy pool and a swap index for an inverse Fisher-Yates, ahead of xorshift64 and ChaCha20.
2. Stage 4, the loader: no imports, timestamp 0, flattened control flow, 202 encrypted strings, indirect syscalls.
3. A `.bdata` section holding a MIOU container, which unpacks to Beretta, plus a second record that is the clipper DLL.
4. Beretta runs from memory, headerless. The clipper is written to disk and persists through a COM hijack.

Addresses are RVAs in the stage-4 loader, except in the "Beretta itself" section, where they are RVAs in the Beretta image. The analysis is static, checked against a sandboxed run under Process Monitor and the canary runs in the main post.

## The key that decrypts garbage when watched

The stage-4 loader does not refuse to run under a debugger. It runs, derives a wrong key, decrypts noise and exits cleanly. Beretta, once it does run, has a second gate: the usual PEB and debug-port checks end in `ExitProcess(0)`, and a human check wants at least five cursor moves within about 45 seconds. A sandbox with a still cursor sees the process end before it touches a file. There are no VM strings, no locale kill switch and no self-deletion.

A 14-step handler pipeline over a 0x370-byte context runs nine key handlers. Each adds `CONST ^ penalty` to a 64-bit accumulator at `ctx+0x220`. On a clean machine every penalty is 0.

| # | Handler | Clean term | Check | Penalty |
|---|---|---|---|---|
| 1 | 0x122e0 | 0x29ad699809e9b776 | none | – |
| 2 | 0x124a0 | 0x1a9e5aab3ada8445 | none | – |
| 3 | 0x12620 | 0x0b8f4bba2bcb9554 | PEB.BeingDebugged | flag × 0x2045deef38bd7888 |
| 4 | 0x12820 | 0x7cf83ccd5cbce223 | PEB.NtGlobalFlag & 0x70 | value × 0xa5a5a5a5a5a5a5a5 |
| 5 | 0x129b0 | 0x6de92ddc4dadf332 | rdtsc delta ≥ 10,000,001 | 0xbadc0ffee0ddf00d |
| 6 | 0x12ae0 | 0x5eda1eef7e9ec001 | none | – |
| 7 | 0x12bf0 | 0x4fcb0ffe6f8fd110 | none | – |
| 8 | 0x12cf0 | 0xb034f00190702eef | DR0-DR3 via NtGetContextThread | 0xfeedfacebaadf00d |
| 9 | 0x12e90 | 0xa125e11081613ffe | ProcessDebugPort, ProcessDebugObjectHandle, int 2d / VEH trap, one stub | per hit: 0xc0ffee1122334455, 0x2045deef38bd7888, 0x8c1d4e9a37f5b260, 0xdeadc0de5a5a5a5a |

That is eight checks. One of them is a stub that always reports clean, and four handlers add a constant and check nothing. The clean sum is 0x3abc7aa71afaa662.

Handler 9 then folds in a second term from `ctx+0x228`: an LCG chain (`x = x*0x5deece66d + 0xb ^ t`) over the Windows major version from KUSER_SHARED_DATA (6 to 11), the CPUID leaf 1 EDX feature mask 0x06808031, a non-null `PEB.ProcessHeap`, and an FNV hash of the loader's own code XORed with 0xc0de1a7e5afe8b1d. The self-hash catches what the checks miss: a software breakpoint or a patched byte in the hashed code changes the key.

None of these inputs identifies a machine. Every clean Windows 6.x to 11 x64 host produces the same accumulator, so the payload is environment-gated, not victim-bound.

The accumulator never reaches a comparison. It is folded into a 32-bit value, XORed with four bytes of the record header and expanded through a Galois LFSR (seed 0xf3a72b81, taps 0xb4bcd35c) into the mask over the payload record. The record's header check covers only the build key, not the accumulator. So a watched run passes the header check, unmasks noise, fails the MZ test with internal error 0xe214 and returns. The crypter then calls `NtTerminateProcess(-1, 0)`. The stealer never runs, and the hidden Python child exits with status 0.

A separate routine (0x11170) queries ProcessDebugPort, ProcessDebugObjectHandle and ProcessDebugFlags again and sets flag bits at `ctx+0x3c`. Those bits never enter the key. They look like the anti-debug logic, and patching them changes nothing.

## How to beat it: the build key leaks through the API hash

The loader resolves its six syscalls with a per-build export hash at 0x32610:

```c
h = 0x2044deee;
for (c in name) h = (ror32(h, 7) + c) ^ lo;
return ror32(h, 19) ^ 0x788918f8;
```

Every constant in it comes from the loader's 64-bit build key K:

- the seed 0x2044deee is `hi32(K) ^ lo32(K)`;
- the round XOR `lo` is `lo32(K)`, rebuilt at run time as `(c0 + 0x790ec5fa) ^ (0x59b6b117 - c1) ^ (c2 + 0x2c5ee844) ^ (0x0d062261 - c3)` from four cells at 0x393f0, which gives 0x18f8a667;
- the final XOR 0x788918f8 is `(K >> 16) & 0xffffffff`, which doubles as a self-check.

So K = 0x38bc788918f8a667, read from one function. The effect is that every build hashes API names differently, and every build hands over its key in the routine an analyst reads first.

K is what the header check verifies, and it keys the next two layers (below). The record mask needs the clean accumulator on top of K, and since that accumulator is a constant on any clean host, it can be computed once. In this build the mask also falls to known plaintext: the second record in `.bdata` is the clipper DLL byte for byte, and all 2,784 columns of the 16-byte mask agree.

`scripts/extract_k.py` pattern-matches the routine, rebuilds `lo` from the four rip-relative cells, derives K and confirms it against the final XOR. It runs in milliseconds on any stage 4 with the same code shape. `scripts/stage4_api_hash.py` reimplements the hash and shows which Nt* names land in the six syscall slots.

The syscall layer itself is standard Halo's Gate with Tartarus' Gate's byte-3 hook check, and stage 3 and Beretta each bring their own separate implementation.

## The MIOU container

`.bdata` starts with magic `8C 99 FF EB` and a directory pointing at two records: a main record of 0x58074 bytes and a `CLPR` record of 0xae00 bytes. Both share the LFSR and the 16-byte mask. Under the mask, the main record has two more keyed layers before the container appears:

`mask → keyed base64 → keyed LZ4 → MIOU container → 33 shuffled ChaCha20 chunks → keyed LZ4 → Beretta image`

The first is keyed base64. An 8-byte header carries a check word (`((K>>16)^K)*0x7feb352d ^ w0 == 0xf2f2f2f2`) and the output length. The alphabet is the standard one shuffled by a PCG generator seeded with `K ^ 0x98e1ebbba7e279b3`, and each output byte i is XORed with `K[i&7] ^ (i*0x47)`. The same PCG family decrypts the loader's string table.

The second is keyed LZ4 (0x17350). Each token is rotated right by `K[seq&7] & 7`, a mode byte picks one of five literal/match nibble layouts (mode 4 interleaves bits), and match offsets take 1 to 3 bytes behind a 0x80/0xC0 prefix. A stock LZ4 decoder fails on the first token. This build uses mode 4 and inflates 270,417 bytes to the 269,342-byte container.

The container then keys itself from its own bytes. The labels `MIOU_header_v1`, `MIOU_meta_v1` and `MIOU_hmac_v1`, found in the loader's string table, are where the operation's name comes from.

| Offset | Size | Content |
|---|---|---|
| 0x00 | 0x80 | header: first 8 bytes XOR nonce, then ChaCha20 under K_header |
| 0x80 | 8 | nonce |
| 0x88 | 32 | IKM, XORed with the repeating nonce |
| 0xa8 | 32 | HKDF salt |
| 0xc8 | 32 | tag (no comparison observed) |
| 0xe8 | 0x8e0 | meta table: 16-byte prefix + ChaCha20 body under K_meta |
| 0x9c8 | rest | data: 16-byte prefix + 33 shuffled chunks |

Keys come from a single-block HKDF-SHA256: `PRK = HMAC(salt, IKM)`, then `K_x = HMAC(PRK, label || 0x01)` for each label. The header (ChaCha20, counter 0) holds the version 0x00010000, the area offsets, the chunk and relocation counts, the entry RVA 0x32aa0 and the nonce for the meta table (counter 1).

Each 56-byte meta entry gives a chunk's ID, stored offset and size, output position (`id * 0x2081`), nonce and tag. Chunks are stored out of order: slot 0 holds chunk 1, slot 1 the 6-byte tail. Each chunk key is four parallel 64-bit FNV-1a variants over `IKM || chunk_id ||` the container's 8-byte nonce, concatenated to 32 bytes; ChaCha20 then uses the entry's own 12-byte nonce. Relocations follow the entries. The reassembled stream goes through the same keyed LZ4, now under IKM[0:8], and comes out as the 591,360-byte Beretta image.

The integrity layer does nothing we could find. The loader derives the `MIOU_hmac_v1` key and wipes it, nothing in the decompiled loader reads it, and no handler compares the tag fields, although the string table carries `Signature verification failed`.

After mapping, the loader wipes the PE headers, the buffers and its context before calling the entry point, and can arm page re-encryption hooks keyed by a per-run hash of ASLR pointers. The `CLPR` record goes to disk as the clipper (see Indicators).

## Beretta itself

Beretta is clang-built C++ with the MSVC ABI. Its strings, 716 slots of which 707 are in use, are encrypted in one block. One initialiser builds a seed, a second decrypts every string in place, and code reaches each string through a tiny `lea rax,[s]; ret` getter. At exit the whole block is wiped. Several hundred further inline decryptors use the golden-ratio step 0x9e3779b9. APIs resolve through FNV-1a 32.

The getters settle which strings matter. `--headless=new`, `--window-position=-32000,-32000`, `--start-minimized`, `ChromeHelperSync`, `v20_stealth_` and `aster_app_bound_encrypted_key` are decrypted and wiped with no getter and no code reference. They are dead. Beretta does not start a headless Chrome, whatever its string dump suggests.

### Config: BRT2CFG2

The builder patches a 0x250-byte block at 0x90000, bracketed by `BRT2CFG2` and `END2`. It holds a version (2), a ChaCha20 key and nonce, and up to 0x200 bytes of ciphertext. The loader at 0xcd40 decrypts it with counter 1, unpacks a small LZ format into a 0x15c-byte struct and checks an FNV-1a 32 trailer.

This build's struct gives the build name `git1509`, the build ID `527e1519bee9a267641f06cc` (sent to the server as `ct`), the C2 62[.]60[.]226[.]113 on port 6673 and the fallback spellmarketplace[.]club on 443. `scripts/brt_config_unpack.py` reproduces it and the checksum passes. A legacy plaintext struct next to it still holds developer defaults: the path salt `DEFAULT`, a second build ID `a3030ea66d3519ffcff329b3` and `shell_debug`.

### C2

- Identity: a 64-hex-character HWID from forward and reverse FNV-1a plus an LCG over `COMPUTERNAME|USERNAME|BRTX-SHELL`.
- URLs: `/<prefix>/<endpoint>`, where the prefix is 24 base62 characters mixed from the HWID, the current Unix hour and the salt. It rotates every hour, so URL blocklists age out fast. Endpoints are `h` (handshake), `g` (config), `u` and `u/chunk` (upload), plus a HEAD `/` probe.
- Transport: WinHTTP, TLS when a config flag is set or the port is 443 or 2265, with security flags 0x3100, which ignore unknown CAs, name mismatches and expired certificates. It retries with backoff and gives up after 4 hours.
- Handshake: an ephemeral X25519 key pair, POST `{"b","h","t","n","k","ct"}`, reply `{"s","k","t"}`. The session key is HKDF-SHA256 over the shared secret with salt `beretta_session_key` and info `aes-256-gcm`. No server key is pinned and TLS ignores unknown-CA, hostname and date errors, so anyone answering on the C2 address completes the exchange.
- Traffic: AES-256-GCM through BCrypt inside `{"session","nonce","data","tag"}`. The config reply lists Chromium, Gecko and desktop targets, extension IDs and file-grabber settings (`patterns`, `paths`, `max_depth`, size limits, `dedup`).
- Upload: a fresh handshake, then 5 to 8 MB chunks to `u/chunk` or one POST to `u`. The Chromium master keys (`MasterV10`, `MasterV20`, `AsterKey` per browser and profile) travel in a `k` object built outside the AES-GCM layer, protected only by TLS that does not authenticate the server.

There is no command set. Nothing downloads, executes, updates or opens a shell. `BRTX-SHELL` is the HWID salt, not a shell. The only processes Beretta starts are the browser for key theft and a relaunch of `%LOCALAPPDATA%\Microsoft\EdgeWebView\EBWebView\msedgerecovery.exe` after a shared-section handshake with a companion component.

### Chrome app-bound encryption

Beretta gets the app-bound key from inside the browser (Beretta image, 0x25540):

1. It reads `app_bound_encrypted_key` from the browser's `Local State` and maps chrome, msedge, brave, Yandex `browser` or AvastBrowser to its executable.
2. It creates `\\.\pipe\CrHlp_<12 hex>` with a NULL DACL and enables SeDebugPrivilege.
3. If the browser is running, it injects into it. If not, it starts it suspended and windowless in a kill-on-close job with `--disable-gpu --no-sandbox --disable-extensions --no-first-run … --user-data-dir="%TEMP%\v20_<12 hex>" about:blank`, or on a hidden desktop, and deletes the temp profile afterwards.
4. It XOR-decrypts an embedded helper DLL (0x4600 bytes, export `Bootstrap`, PE timestamp 2026-01-26), writes it with NtAllocateVirtualMemory and NtWriteVirtualMemory by indirect syscall and starts `Bootstrap(pipe_name)` with NtCreateThreadEx, falling back to CreateRemoteThread. The remote region is zeroed and freed afterwards.
5. The helper loads the elevation service's type library, decrypts the key with the browser's own IElevator and answers over the pipe: `CON1`, then `INIT` or `ERR<code>`, the 32-byte key, and optionally `AST` with the Aster key. `ChromeHelperSync` is only the helper's default pipe name; Beretta always passes its own.
6. If injection fails, Beretta calls IElevator itself. It finds the CLSID by matching `HKLM\Software\Classes\CLSID\*\LocalServer32` against `elevation_service.exe` and tries 13 interface IDs, including Chrome's 463ABECF, Edge's C9C2B807 and Brave's F396861E.

The design is xaitax's public [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption): inject into the browser, ask IElevator from inside, return the key over a pipe. Beretta packages it with an encrypted helper, indirect syscalls, its own pipe protocol and a stealer-side fallback.

### Targets

The full list is in `targets.tsv`, 220 rows, 17 of them dead strings. The code hardcodes 49 Chromium profile roots (Perplexity Comet and CryptoTab among them), four Gecko browsers, MetaMask and Phantom, Telegram, Discord, FileZilla, PuTTY, RDP credentials and Steam. The file grabber walks Desktop, Documents and Downloads for masks such as `*seed*`, `*wallet*` and `*mnemonic*`, and copies locked files through volume shadow copies. The rest comes from the server: in our sandbox run it pushed 78 wallet and 2FA extension IDs and 38 desktop-wallet roots, recorded by Process Monitor. What it actually sent in our canary runs (whole wallet, KeePass, FileZilla and Discord files; nothing from SSH keys, AWS credentials or `.env`) is in the Apiiro write-up's canary table.

### Not StealC

The April write-up on this operation judged the payload consistent with StealC v2, based on capa and a threat-feed tag on the server IP. The code says otherwise:

- StealC v2 talks plain HTTP on port 80 with JSON, RC4 and base64, per Zscaler's analysis. Beretta uses TLS on a custom port, with X25519 and AES-256-GCM inside.
- Beretta names itself, has its own builder format (`BRT2CFG2`), its own key-exchange salt and its own pipe protocol. None of these has a public hit.
- It matches none of the other families we compared: Lumma reads Chrome's memory for cookies, Phemedrone drives Chrome over the DevTools protocol, and Vidar 2.0 uses Telegram and Steam dead drops.

The label came from capa and from infrastructure. 62[.]60[.]226[.]113 hosted a PHP-gate StealC panel on port 80 in 2025, on a bulletproof range full of other families, and spellmarketplace[.]club was listed as StealC C2 in the April indicators.

## Detection

The rules are in this repo, with test results in `tests/`.

| Rule | Target | Our samples |
|---|---|---|
| `MIOU_Stage3_Crypter` | stage 3 on disk | hit |
| `MIOU_Stage4_Loader` | stage 4 on disk or dumped | hit |
| `Beretta_Stealer_Image` | headerless image, strings still encrypted | hit, also on the memory form |
| `Beretta_Stealer_Memory` | process memory after string init, no MZ needed | hit |
| `MSEdgeView_Clipper_DLL` | clipper on disk | hit |
| `Beretta_ABE_Helper_DLL` | helper DLL, also inside the browser | hit |
| `failproxy_py_*` (4 rules) | the repos' Python loader | every loader source tree we hold: 30 live repos and six surviving copies of deleted repos |

None of the rules fired on clean files. The Python rules ran over 96,893 `.py` files and 7 screened non-family repos.
The PE rules ran against 1,478 benign Windows PEs: PyPI win_amd64 wheels, PortableGit and MinGit, the Python embeddable builds, 7-Zip, uv, node.exe, rclone, ripgrep, fd and bat, 1,065 MB in all. They anchor on code that should survive a rebuild: the indirect-syscall dispatchers, the gadget hunt, FNV-1a values of Nt* names, the K-seeded hash routine with its four cells wildcarded, the penalty constants and the golden-ratio string decryptors.

YARA Forge (full, release 20261115) has zero hits on stage 3, stage 4, the clipper and the Beretta image. The one rule that fires, `RUSSIANPANDA_Win_Mal_Chromium_App_Bound_Encryption_Decrypter`, is a generic match on the Chrome and Brave IElevator GUIDs. It hits the helper DLL once decrypted, and Beretta only after we gave it a synthetic PE header. On a real memory dump it fires only if the dumper rebuilds a header, because the loader wipes the original.

Behaviour rules ship as six Sigma rules (all pass `sigma check`) and Defender KQL:

- a `python.exe` child of `python.exe` whose command line runs `-c` with `sys.stdin.buffer.read()`;
- `rundll32.exe` calling an ordinal in a DLL under `AppData`;
- a per-user `CLSID\{…}\InprocServer32` pointing to a DLL under `AppData\Local`;
- `msedgeview.dll` created under `AppData\Local\Microsoft\EdgeWebView\`;
- a Chromium browser started by a non-browser with `--user-data-dir="…\Temp\v20_<hex>"` and `about:blank`;
- a named pipe `\\.\pipe\CrHlp_<12 hex>`.

The command-line selections match the command lines recorded in our sandbox run. On the wire, the geolocation lookup to ip-api.com goes out as plain HTTP with the truncated user agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`, an easy proxy signature.

## What's new vs. precedent

| Technique | Closest precedent | What Beretta's chain adds |
|---|---|---|
| Anti-analysis folded into the key | [Zscaler, 2CLoader](https://www.zscaler.com/blogs/security-research/2cloader-new-malware-loader-delivering-vidar-and-remus): a timing check flips its section-hash key seed; [CCCS, ACR Stealer loader](https://www.cyber.gc.ca/en/guidance/canadian-centre-cyber-security-uses-frontier-ai-accelerate-malware-reverse-engineering): anti-debug results enter key derivation | Weighted `CONST ^ penalty` terms, decoy handlers, an environment LCG and a self-hash; the header check skips the accumulator, so a watched run fails late and exits 0 |
| Per-build seeded API hashing | [MITRE T1027.007](https://attack.mitre.org/techniques/T1027/007/), [HashDB](https://hashdb.openanalysis.net/) | The hash constants are the payload key, so the hash routine leaks it |
| Shuffled payload crypter | [Straiker, ACR Stealer loader](https://www.straiker.ai/blog/acr-stealer-claude-code-impersonation-campaign) | A gather index and a swap index for every payload byte, drawn from a decoy pool |
| Self-keyed, chunked container | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869); HijackLoader's IDAT chunks | HKDF labels `MIOU_*_v1`, shuffled ChaCha20 chunks with FNV-derived keys, keyed base64 and keyed LZ4; the HMAC key is derived and never used |
| App-bound key theft | [Elastic, Katz and Mouse Game](https://www.elastic.co/security-labs/threat-command/katz-and-mouse-game): MetaStealer calls the elevation service, XenoStealer injects into a launched Chrome; [xaitax ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) | Encrypted helper injected by indirect syscall, `CON1`/`INIT`/`AST` protocol on `CrHlp_<hex>`, stealer-side IElevator fallback |
| Stealer C2 | StealC v2: JSON, RC4 and base64 over HTTP ([Zscaler](https://www.zscaler.com/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc)) | X25519, HKDF and AES-256-GCM with an hourly URL prefix, but no certificate checks and master keys outside the AES layer |

## Appendix: Indicators

| Type | Indicator |
|---|---|
| Stage 3 crypter | sha256 `707e89148589beeb0d1602cc080ae609bc4203b0fd074e80bf8f23159588c0ee` (10,243,072 bytes, fake `taskhostw.exe` version info) |
| Stage 4 loader | sha256 `5ce53eeac3aedcfaf5b593b53a53f59217f880331413f3da30b6966b25f1e4df` (641,536 bytes); `.bdata` magic `0xEBFF998C` |
| MIOU container | sha256 `c278e576e253a59ab7f34005b7fb175d98c2b95dee345e643b33e8ecb8f20c90` (memory only) |
| Beretta image | sha256 `1efc29cbd68b9cceb158dbd1632f682766a706f40d47464afec395c9dad4eb35` (headerless, memory only); `// Beretta Private build 2.1`, `BRT2CFG2`, `beretta_session_key`, build `git1509`, build ID `527e1519bee9a267641f06cc` |
| ABE helper DLL | sha256 `eeff7b96019a65fa4518da67a4bc39e496d3c6f7a327081775140ac8a1ca5b97` (export `Bootstrap`) |
| Clipper | `%LOCALAPPDATA%\Microsoft\EdgeWebView\msedgeview.dll`, sha256 `b6abbfece488080e23f5498ecf006ec02de9fa98b74ce3c385c53a0696ec0e0c`; `HKCU\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32`; `rundll32.exe "<dll>",#3` |
| C2 | 62[.]60[.]226[.]113:6673 (TLS, no certificate checks); fallback spellmarketplace[.]club:443; endpoints `/<24 base62>/h`, `/g`, `/u`, `/u/chunk` |
| Pipe | `\\.\pipe\CrHlp_<12 hex>` |
| Browser profile | `%TEMP%\v20_<12 hex>`, browser launched with `--no-sandbox --disable-extensions … about:blank` |
| Companion | `%LOCALAPPDATA%\Microsoft\EdgeWebView\EBWebView\msedgerecovery.exe`; mutex `Global\M<crc>` / `Local\G<crc>` |
