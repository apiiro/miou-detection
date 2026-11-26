# MIOU / Beretta indicators

## Indicators

| Type | Indicator |
|---|---|
| Delivery C2 | `api.failproxy.space`, `api.nailproxy.space` (routes `/api/v1/auth/session`, `/api/v1/data/sync`) |
| Relay fallback | 104[.]21[.]0[.]1, 172[.]67[.]0[.]1 (Cloudflare, TLS verification off) |
| Exfil | 62[.]60[.]226[.]113:6673 (AS214351), TLS without SNI; fallback `spellmarketplace.club:443`; geolocation via ip-api.com, ipinfo.io, ipapi.co |
| Stealer | Beretta Private build 2.1, build name `git1509`, build ID `527e1519bee9a267641f06cc`; pipe `\\.\pipe\CrHlp_<hex>`; browser profile `%TEMP%\v20_<hex>` |
| Clipper file | `%LOCALAPPDATA%\Microsoft\EdgeWebView\msedgeview.dll`, sha256 `b6abbfece488080e23f5498ecf006ec02de9fa98b74ce3c385c53a0696ec0e0c` (44,544 bytes) |
| Clipper persistence | `HKCU\Software\Classes\CLSID\{AAA288BA-9A4C-45B0-95D7-94D524869DB5}\InprocServer32` (per build); `rundll32.exe "<dll>",#3`; mutex `Local\{8F6E2A14-C9D1-4bdd-B8CF-92F04E6B3E9F}` |
| Payload | stage 3 PE sha256 `707e89148589beeb0d1602cc080ae609bc4203b0fd074e80bf8f23159588c0ee` (10,243,072 bytes, fake taskhostw version info), the same file in every download we decrypted |
| Inner stages (memory only) | loader sha256 `5ce53eeac3aedcfaf5b593b53a53f59217f880331413f3da30b6966b25f1e4df` (`.bdata` magic `0xEBFF998C`); stage 4 layer 1 `df45c54acdbae4012635efd9a89395484640f2c1a55f86ac0c6b2e90c54a96ff`; MIOU container `c278e576e253a59ab7f34005b7fb175d98c2b95dee345e643b33e8ecb8f20c90`; Beretta image `1efc29cbd68b9cceb158dbd1632f682766a706f40d47464afec395c9dad4eb35`; Chrome helper DLL `eeff7b96019a65fa4518da67a4bc39e496d3c6f7a327081775140ac8a1ca5b97` (export `Bootstrap`) |
| Repo markers | `base/data/bundle.pkg`, `runtime/data/embed.pkg` or `kernel/data/dist.pkg` (11 to 22 MB); `base/{carrier,relay,packing,machine,audit}.py`; `@bootstrap` / `@ensure_env` on the entry point; build paths `C:\shellgainer\arhieves_*`; author `Lucas <username@users.noreply.github.com>`, message `Auto commit` |
| MCP repos | `isabelpapaya/MCP-Server-Lighter`, `trinity1994/MCP-Server-Aster-DEX`, `blessedberserker/MCP-Server-Aster-DEX` (all three deleted; blessedberserker was already gone when we reported; all three removed from Glama on November 18) |
| Clipper wallets | BTC `bc1q00h2kl4uvwcvzp7zdl80yx97f0p8jv450qdzwc`, ETH/BNB `0xcEBDCBA0a42B2dE9Be38c48d648471C672C007C1`, TRON `TL1417xeaNrvU6La3N5Vgpye1e47i4zHUv`, SOL `2UoxbkKwhZSvEtTUzWf9aghXi1LJgsgpGApxvFpSdvf3`, LTC `ltc1q36llsr6s3n4c8ur6g0prf8c9l0gs7ufwdakmng`; full pool in ArchLinuxAddict's report |

## Reported repositories

The 36 MIOU repos that were live when we reported them on November 18, 2026, and their state on November 26.

| Repository | November 26 |
|---|---|
| `Adampcber1234/Seed-Generator` | removed |
| `ashleydarosa/CC-Checker-Validator-Generator` | live |
| `aylla18/Polymarket-Market-Agent` | live |
| `Calebe95/Trade-Bot-Hyperliquid` | live |
| `chord1990/Lighter-Airdrop-Tracker` | live |
| `Danuse84/Exodus-Fake-Balance` | removed |
| `dugffoanh1992/Keylogger-Crypto-Clipper` | live |
| `else24/kalshi-market-bot` | live |
| `frantiska21/Trade-Bot-Hyperliquid` | live |
| `Gemma41/Onchain-Accounting` | live |
| `goulash23/Stablecoin-Payment-Gateway` | live |
| `hurside69/Polymarket-Perpetual-Bot` | live |
| `isabelpapaya/MCP-Server-Lighter` | removed |
| `jeffreyquinn95/Hyperliquid-Leaderboard-Analytics` | live |
| `joannarogers2005/Stablecoin-Payment-Gateway` | live |
| `Kimberlyfriis/TRX-Drainer-Tool` | removed |
| `lalouannabel0072/kalshi-trading-bot` | live |
| `lyp2431-stack/Srxs` | live |
| `marisanilsson33/Solana-Drainer-Tool` | removed |
| `mav187/m` | live |
| `mdasneves2006/Stablecoin-Payment-Gateway` | live |
| `MelisaPeteRs2006/Silent-Crypto-Miner` | removed |
| `miloslavatangen/Checker-Mnemonic` | live |
| `MyZahradamiyas1816/Seed-Generator` | removed |
| `ninamorozov1982/Aster-Dex-Airdrop-Tracker` | live |
| `noloyswy1993/Tonkeeper-Fake-Balance` | live |
| `pverhoeven74/Crypto-Clipper` | removed |
| `sabinastone7/Polymarket-Trading-Bot` | removed |
| `sandskatherinenymph/Electrum-Fake-Balance` | removed |
| `Soniavasseur/Wallet-Risk-Scanner` | removed |
| `tigerogijzooav/Hyperliquid-Trade-Bot` | removed |
| `trinity1994/MCP-Server-Aster-DEX` | removed |
| `warmknight30/Silent-Crypto-Miner` | removed |
| `zacharias80/Polymarket-Prediction-Bot` | removed |
| `zacharyrogue/Crypto-Whale-Tracker` | removed |
| `zgraham1981/Stablecoin-Payment-Gateway` | removed |
