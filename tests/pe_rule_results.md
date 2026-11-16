# PE rule tests (rules/miou_beretta.yar), 2026-11-17

Benign corpus: 1,478 distinct Windows PEs (PyPI win_amd64 wheels 734, PortableGit 381, MinGit 180, Python embeddable 3.11-3.13 x64/x86 168, 7-Zip 7, uv 3, node.exe, rclone, ripgrep, fd, bat), 1,065 MB, 29 files over 5 MB.

Positives: beretta_mem.bin = decrypted image with the string initialisers emulated (Unicorn, 0x442b0 then 0x44300); beretta_synth.exe = the same wrapped in a one-section PE header (scripts/synth_pe.py); miou.bin = MIOU container (in-memory only, not a target).

```
## Positives
stage3_pe_707e8914.body	707e89148589beeb	MIOU_Stage3_Crypter
stage4.bin	5ce53eeac3aedcfa	MIOU_Stage4_Loader
miou_decompressed.bin	1efc29cbd68b9cce	Beretta_Stealer_Image
beretta_mem.bin	3ad58a43b3d1391f	Beretta_Stealer_Image, Beretta_Stealer_Memory
beretta_synth.exe	fff823cec28455d0	Beretta_Stealer_Image, Beretta_Stealer_Memory
msedgeview.dll.bin	b6abbfece488080e	MSEdgeView_Clipper_DLL
miou.bin	c278e576e253a59a	-
## Benign corpus: 1478 PE files scanned, 0 matches
Beretta_Stealer_Image	0 FP
Beretta_Stealer_Memory	0 FP
MIOU_Stage3_Crypter	0 FP
MIOU_Stage4_Loader	0 FP
MSEdgeView_Clipper_DLL	0 FP
```
