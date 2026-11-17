"""Decrypt and unpack the Beretta 'BRT2CFG2' builder config (block at image RVA 0x90000, 0x250 bytes).
Mirrors the stealer's loader at RVA 0xcd40: ChaCha20 (key blk[0x0c:0x2c], nonce blk[0x2c:0x38], counter 1),
then a byte-oriented LZ unpack (first u32 = unpacked size, must be 0x15c), then FNV-1a-32 over out[0:0x158] == out[0x158:0x15c].
Usage: python -I brt_config_unpack.py <stealer_image.bin> [out_unpacked.bin]"""
import sys, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

blk = open(sys.argv[1], "rb").read()[0x90000:0x90250]
assert blk[:8] == b"BRT2CFG2" and blk[0x240:0x244] == b"END2"
ver = struct.unpack_from("<I", blk, 8)[0]
n, usize = struct.unpack_from("<II", blk, 0x38)
pt = Cipher(algorithms.ChaCha20(blk[0x0c:0x2c], struct.pack("<I", 1) + blk[0x2c:0x38]), None).encryptor().update(blk[0x40:0x40 + n])

def unpack(src):
    total = struct.unpack_from("<I", src, 0)[0]
    out = bytearray(); i = 4
    while i < len(src) and len(out) < total:
        b = src[i]; i += 1
        if b < 0x80:                      # literal run of b+1 bytes
            out += src[i:i + b + 1]; i += b + 1
        else:                             # back-reference: dist = (((b&0x70)<<4)|next)+1, len = (b&0xf)+3
            off = ((b & 0x70) << 4) | src[i]; i += 1
            for _ in range((b & 0xf) + 3):
                out.append(out[-off - 1])
    return bytes(out[:total]), total

def fnv1a(b):
    h = 0x811c9dc5
    for c in b:
        h = ((h ^ c) * 0x01000193) & 0xffffffff
    return h

out, total = unpack(pt)
print(f"version={ver} ct_len={n} unpacked_size_field={usize:#x} unpacked={len(out):#x} (header says {total:#x})")
chk = struct.unpack_from("<I", out, 0x158)[0]
print(f"fnv1a(out[:0x158])={fnv1a(out[:0x158]):#010x} stored={chk:#010x} ok={fnv1a(out[:0x158]) == chk}")
if len(sys.argv) > 2:
    open(sys.argv[2], "wb").write(out)
for off in range(0, len(out), 16):
    row = out[off:off + 16]
    print(f"{off:04x}  {row.hex(' '):<48}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in row)}")
