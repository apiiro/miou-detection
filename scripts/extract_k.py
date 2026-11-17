"""Recover the stage-4 build key K statically from the K-seeded export-hash routine (no brute force).
The routine is seeded with hi32(K)^lo32(K), XORs each round with lo32(K) (rebuilt from four opaque .rdata cells),
and finalises with XOR (K>>16)&0xffffffff. Usage: python -I extract_k.py <stage4.exe>"""
import sys, re, struct, pefile
pe = pefile.PE(sys.argv[1]); d = pe.__data__; base = pe.OPTIONAL_HEADER.ImageBase
M = 0xffffffff
pat = re.compile(rb"\xb8(....)\x44\x8b\x0d(....)\x41\x81\xc1(....)\x41\xb8(....)\x44\x2b\x05(....)\x45\x31\xc1"
                 rb"\x44\x8b\x05(....)\x41\x81\xc0(....)\x45\x31\xc1\x41\xb8(....)\x44\x2b\x05(....)\x45\x31\xc1\xbb\x07\x00\x00\x00", re.S)
def u32(b): return struct.unpack("<I", b)[0]
def s32(b): return struct.unpack("<i", b)[0]
for m in pat.finditer(d):
    off = m.start(); rva = pe.get_rva_from_offset(off)
    seed = u32(m.group(1))
    def cell(gi, end_rel):  # rip-relative operand: target = next-insn rva + disp
        disp = s32(m.group(gi)); nxt = pe.get_rva_from_offset(off + end_rel)
        return u32(pe.get_data(nxt + disp, 4))
    # instruction end offsets relative to match start
    c1 = cell(2, 12); c2 = cell(5, 32); c3 = cell(6, 42); c4 = cell(9, 65)
    lo = ((c1 + u32(m.group(3))) & M) ^ ((u32(m.group(4)) - c2) & M) ^ ((c3 + u32(m.group(7))) & M) ^ ((u32(m.group(8)) - c4) & M)
    hi = seed ^ lo; K = (hi << 32) | lo
    tail = d[m.end():m.end() + 0x30]; t = tail.find(b"\xb1\x13\xd3\xc8\x35")
    fin = u32(tail[t + 5:t + 9]) if t >= 0 else None
    ok = fin == ((K >> 16) & M)
    print(f"hash routine at rva {rva:#x}: seed {seed:#010x} lo32 {lo:#010x} -> K = {K:#018x}  final-xor check {'OK' if ok else 'FAIL'}")
