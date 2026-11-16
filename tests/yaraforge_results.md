# YARA Forge scan, 2026-11-17

Rule set: YARA Forge full, release 20261115 (v0.9.1), 11,852 rules, compiled with yara-python 4.5.4.

| File | Hits |
|---|---|
| stage 3 707e8914… | 0 |
| stage 4 5ce53eea… (decrypted from stage 3) | 0 |
| Beretta image 1efc29cb… (headerless, strings encrypted) | 0 |
| Beretta image, strings decrypted (memory form) | 0 |
| Beretta memory form wrapped in a synthetic PE header | 1: RUSSIANPANDA_Win_Mal_Chromium_App_Bound_Encryption_Decrypter (IElevator CLSID/IID bytes for Chrome/Brave) |
| clipper msedgeview.dll b6abbfec… | 0 |
| MIOU container c278e576… | 0 |
| Beretta ABE helper DLL eeff7b96… (decrypted from the image) | 1: RUSSIANPANDA_Win_Mal_Chromium_App_Bound_Encryption_Decrypter |

The one hit is a generic ABE-decrypter rule keyed on the Chrome and Brave elevation-service GUIDs. It needs an MZ header, so it fires on a memory dump of Beretta only if the dumping tool rebuilds a header; the loader wipes the real one.
