"""Find FNV-1a 32 hashes of Nt*/Ldr* API names and module names (ASCII/UTF-16, as-is or lowercase) in a binary.
Usage: python -I fnv_api_scan.py <file>"""
import sys,struct,re
d=open(sys.argv[1],'rb').read()
names="""NtAllocateVirtualMemory NtProtectVirtualMemory NtFreeVirtualMemory NtWriteVirtualMemory NtReadVirtualMemory NtQueryVirtualMemory NtCreateThreadEx NtClose NtQueryInformationProcess NtSetInformationThread NtQuerySystemInformation NtDelayExecution NtTerminateProcess NtCreateSection NtMapViewOfSection NtUnmapViewOfSection NtOpenProcess NtCreateFile NtReadFile NtWriteFile NtQueryInformationThread NtGetContextThread NtSetContextThread NtResumeThread NtSuspendThread NtWaitForSingleObject NtOpenKey NtQueryValueKey NtCreateKey NtSetValueKey NtFlushInstructionCache NtQueryPerformanceCounter NtCreateEvent NtSetEvent NtOpenThread NtQueueApcThread NtTestAlert NtContinue NtRaiseException NtQueryObject NtDuplicateObject NtYieldExecution NtQuerySystemTime NtCreateUserProcess NtCreateProcessEx NtQueryInformationFile NtSetInformationProcess NtRemoveProcessDebug NtOpenFile NtDeleteFile NtQueryAttributesFile NtQueryDirectoryFile NtCreateMutant NtOpenMutant NtCreateNamedPipeFile NtFsControlFile NtDeviceIoControlFile LdrLoadDll LdrGetProcedureAddress RtlAddVectoredExceptionHandler RtlRemoveVectoredExceptionHandler RtlCreateUserThread NtLockVirtualMemory NtSetInformationVirtualMemory NtAlertResumeThread NtCreateThread NtTerminateThread NtGetNextProcess NtQuerySection NtExtendSection""".split()
mods="ntdll.dll kernel32.dll kernelbase.dll user32.dll advapi32.dll".split()
def f1a(s,b=0x811c9dc5):
    h=b
    for c in s: h=((h^c)*0x1000193)&0xffffffff
    return h
def f1(s):
    h=0x811c9dc5
    for c in s: h=((h*0x1000193)&0xffffffff)^c
    return h
for n in names+mods+[m.upper() for m in mods]:
    for enc in ("a","w"):
        b=n.encode() if enc=="a" else n.encode("utf-16le")
        for nm,h in (("1a",f1a(b)),("1",f1(b)),("1a-lc",f1a(b.lower()))):
            p=struct.pack('<I',h)
            hits=[m.start() for m in re.finditer(re.escape(p),d)]
            if hits: print(n,enc,nm,hex(h),[hex(x) for x in hits[:4]])
