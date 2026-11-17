"""Stage-4 K-seeded export hash (seed hi^lo, round XOR lo32(K), final XOR (K>>16)) and module hash; prints which Nt* names hit the six syscall slots."""
M=0xffffffff
def kh(s,seed=0x2044deee,x=0x18f8a667,f=0x788918f8):
    h=seed
    for c in s.encode():
        h=((((h>>7)|(h<<25))&M)+c ^ x)&M
    return (((h>>19)|(h<<13))&M)^f
def mh(s):
    h=0xbc802f7f
    for ch in s:
        u=ord(ch)
        if 0x41<=u<=0x5a: u+=0x20
        h=((((h>>6)|(h<<26))&M)+(u&0xff) ^ 0xaccf01f)&M
        if u>>8: h=((((h>>6)|(h<<26))&M)+(u>>8) ^ 0xaccf01f)&M
    return (((h<<19)|(h>>13))&M)^0xffec5bd9
want={0x1d6fbbc6,0xe3e0d35c,0xdc2c58bb,0x68eb1516,0x55a9d80a,0x664fe7ca}
names="NtAllocateVirtualMemory NtProtectVirtualMemory NtFreeVirtualMemory NtQueryInformationProcess NtSetInformationThread NtGetContextThread NtClose NtQueryVirtualMemory NtWriteVirtualMemory NtReadVirtualMemory NtQuerySystemInformation NtDelayExecution NtSetContextThread NtQueryInformationThread NtCreateThreadEx NtTerminateProcess NtContinue NtFlushInstructionCache NtQueryPerformanceCounter".split()
for n in names:
    h=kh(n)
    print(n,hex(h),"HIT" if h in want else "")
for m in ["ntdll.dll","kernel32.dll","kernelbase.dll"]: print(m,hex(mh(m)))
