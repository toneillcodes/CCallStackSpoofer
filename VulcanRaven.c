#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>
#include <dbghelp.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

typedef LONG NTSTATUS;
#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#define STATUS_ASSERTION_FAILURE  ((NTSTATUS)0xC0000420L)

#define MAX_STACK_FRAMES   20
#define MAX_CACHE_ENTRIES  50
#define MAX_STACK_SIZE     0x3000

#define UNW_FLAG_CHAININFO 0x4
#define RBP_OP_INFO        0x5

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo   : 4;
    };
    USHORT Op2;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags   : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL      = 0,
    UWOP_ALLOC_LARGE      = 1,
    UWOP_ALLOC_SMALL      = 2,
    UWOP_SET_FPREG        = 3,
    UWOP_SAVE_NONVOL      = 4,
    UWOP_SAVE_NONVOL_FAR  = 5,
    UWOP_SAVE_XMM128      = 8,
    UWOP_SAVE_XMM128_FAR  = 9,
    UWOP_PUSH_MACHFRAME   = 10
} UNWIND_CODE_OPS;

typedef struct _StackFrame {
    WCHAR targetDll[MAX_PATH];
    ULONG offset;
    ULONG totalStackSize;   // includes return address
    BOOL  requiresLoadLibrary;
    BOOL  setsFramePointer;
    PVOID returnAddress;
    BOOL  pushRbp;
    ULONG countOfCodes;
    ULONG pushRbpIndex;
} StackFrame;

typedef struct _ImageBaseEntry {
    WCHAR   dllPath[MAX_PATH];
    HMODULE hModule;
} ImageBaseEntry;

typedef struct _StackProfileEntry {
    WCHAR modulePath[MAX_PATH];
    char  functionName[64];
    ULONG offsetFromExport;
    BOOL  needLoad;
} StackProfileEntry;

ImageBaseEntry g_ImageBaseCache[MAX_CACHE_ENTRIES];
int g_CacheCount = 0;

HMODULE GetCachedImageBase(const WCHAR* dllPath)
{
    for (int i = 0; i < g_CacheCount; i++) {
        if (_wcsicmp(g_ImageBaseCache[i].dllPath, dllPath) == 0) {
            return g_ImageBaseCache[i].hModule;
        }
    }
    return NULL;
}

void CacheImageBase(const WCHAR* dllPath, HMODULE hModule)
{
    if (g_CacheCount < MAX_CACHE_ENTRIES) {
        wcscpy_s(g_ImageBaseCache[g_CacheCount].dllPath, MAX_PATH, dllPath);
        g_ImageBaseCache[g_CacheCount].hModule = hModule;
        g_CacheCount++;
    }
}

DWORD GetRvaFromName(HMODULE hModule, const char* functionName)
{
    PBYTE base = (PBYTE)hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders =
        (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDirInfo =
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportDirInfo.Size == 0) {
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory =
        (PIMAGE_EXPORT_DIRECTORY)(base + exportDirInfo.VirtualAddress);

    PDWORD addressOfFunctions =
        (PDWORD)(base + exportDirectory->AddressOfFunctions);
    PDWORD addressOfNames =
        (PDWORD)(base + exportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinals =
        (PWORD)(base + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* currentName = (char*)(base + addressOfNames[i]);
        if (strcmp(currentName, functionName) == 0) {
            return addressOfFunctions[addressOfNameOrdinals[i]];
        }
    }
    return 0;
}

NTSTATUS CalculateFunctionStackSize(
    PRUNTIME_FUNCTION pRuntimeFunction,
    DWORD64 ImageBase,
    StackFrame* stackFrame
)
{
    PUNWIND_INFO pUnwindInfo =
        (PUNWIND_INFO)(ImageBase + pRuntimeFunction->UnwindData);

    ULONG index = 0;

    while (index < pUnwindInfo->CountOfCodes) {
        ULONG unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        ULONG operationInfo   = pUnwindInfo->UnwindCode[index].OpInfo;

        switch (unwindOperation) {

        case UWOP_PUSH_NONVOL:
            stackFrame->totalStackSize += 8;
            if (operationInfo == RBP_OP_INFO) {
                stackFrame->pushRbp      = TRUE;
                stackFrame->countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame->pushRbpIndex = index;
            }
            break;

        case UWOP_ALLOC_SMALL: {
            ULONG size = (operationInfo * 8) + 8;
            stackFrame->totalStackSize += size;
            break;
        }

        case UWOP_ALLOC_LARGE: {
            index++;
            if (index >= pUnwindInfo->CountOfCodes) {
                break;
            }

            ULONG size = 0;

            if (operationInfo == 0) {
                USHORT low16 = pUnwindInfo->UnwindCode[index].Op2;
                size = (ULONG)low16 * 8;
            } else {
                USHORT low16 = pUnwindInfo->UnwindCode[index].Op2;
                index++;
                if (index >= pUnwindInfo->CountOfCodes) {
                    break;
                }
                USHORT high16 = pUnwindInfo->UnwindCode[index].Op2;
                size = ((ULONG)high16 << 16) | (ULONG)low16;
            }

            stackFrame->totalStackSize += size;
            break;
        }

        case UWOP_SAVE_NONVOL:
        case UWOP_SAVE_XMM128:
            index++;
            break;

        case UWOP_SAVE_NONVOL_FAR:
        case UWOP_SAVE_XMM128_FAR:
            index += 2;
            break;

        case UWOP_SET_FPREG:
            stackFrame->setsFramePointer = TRUE;
            break;

        case UWOP_PUSH_MACHFRAME:
            if (operationInfo == 1) {
                stackFrame->totalStackSize += 48;
            } else {
                stackFrame->totalStackSize += 40;
            }
            break;

        default:
            break;
        }

        index++;
    }

    if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO) {
        ULONG countOfCodes = pUnwindInfo->CountOfCodes;
        ULONG alignedSlots = (countOfCodes + 1) & ~1;

        PRUNTIME_FUNCTION pChainedRuntimeFunction =
            (PRUNTIME_FUNCTION)&pUnwindInfo->UnwindCode[alignedSlots];

        return CalculateFunctionStackSize(
            pChainedRuntimeFunction,
            ImageBase,
            stackFrame
        );
    }

    stackFrame->totalStackSize += 8; // return address
    return STATUS_SUCCESS;
}

NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame* stackFrame)
{
    DWORD64 ImageBase = 0;
    PRUNTIME_FUNCTION pRuntimeFunction =
        RtlLookupFunctionEntry((DWORD64)stackFrame->returnAddress,
                               &ImageBase,
                               NULL);

    if (!pRuntimeFunction) {
        return STATUS_ASSERTION_FAILURE;
    }

    return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
}

void BuildDynamicStack(
    const StackProfileEntry* blueprint,
    int blueprintSize,
    StackFrame* outStack,
    int* outFrameCount
)
{
    *outFrameCount = 0;

    for (int i = 0; i < blueprintSize; i++) {
        HMODULE hMod = GetCachedImageBase(blueprint[i].modulePath);
        if (!hMod) {
            hMod = GetModuleHandleW(blueprint[i].modulePath);
            if (!hMod || blueprint[i].needLoad) {
                hMod = LoadLibraryW(blueprint[i].modulePath);
            }
            if (hMod) {
                CacheImageBase(blueprint[i].modulePath, hMod);
            }
        }

        if (!hMod) {
            continue;
        }

        FARPROC pFunc = GetProcAddress(
            hMod,
            blueprint[i].functionName
        );

        DWORD64 funcAddr = 0;

        if (pFunc) {
            funcAddr = (DWORD64)pFunc +
                       (DWORD64)blueprint[i].offsetFromExport;
        } else {
            DWORD funcRva = GetRvaFromName(hMod, blueprint[i].functionName);
            if (funcRva == 0) {
                continue;
            }
            funcAddr = (DWORD64)((PBYTE)hMod + funcRva +
                                 blueprint[i].offsetFromExport);
        }

        StackFrame* frame = &outStack[*outFrameCount];
        memset(frame, 0, sizeof(StackFrame));

        wcscpy_s(frame->targetDll, MAX_PATH, blueprint[i].modulePath);
        frame->offset             = (ULONG)(funcAddr - (DWORD64)hMod);
        frame->requiresLoadLibrary = blueprint[i].needLoad;
        frame->returnAddress      = (PVOID)funcAddr;

        if (STATUS_SUCCESS == CalculateFunctionStackSizeWrapper(frame)) {
            printf("[+] Resolved %ls!%s to RVA: %lX (Size: %lu)\n",
                   blueprint[i].modulePath,
                   blueprint[i].functionName,
                   frame->offset,
                   frame->totalStackSize);
            (*outFrameCount)++;
        }
    }
}

void PushToStack(CONTEXT* context, ULONG64 value)
{
    context->Rsp -= sizeof(ULONG64);
    *(ULONG64*)(context->Rsp) = value;
}

void InitialiseFakeThreadState(
    CONTEXT* context,
    StackFrame* targetCallStack,
    int frameCount
)
{
    ULONG64 childSp = 0;
    BOOL bPreviousFrameSetUWOP_SET_FPREG = FALSE;

    // Align RSP and reserve shadow space + "call" slot
    context->Rsp &= ~0xFULL;
    context->Rsp -= 0x28;

    // Build frames from bottom → top
    for (int i = frameCount - 1; i >= 0; i--) {
        StackFrame* currentFrame = &targetCallStack[i];

        if (bPreviousFrameSetUWOP_SET_FPREG && currentFrame->pushRbp) {
            // totalStackSize = locals + nonvols + RET
            // We synthesize: [locals+nonvols_except_rbp][rbp][RET]

            ULONG used = 8; // rbp push
            ULONG remaining = currentFrame->totalStackSize - used - 8; // minus rbp, minus RET

            context->Rsp -= remaining;

            // push rbp (childSp)
            PushToStack(context, childSp);

            // push RET
            PushToStack(context, (ULONG64)currentFrame->returnAddress);

            bPreviousFrameSetUWOP_SET_FPREG = FALSE;
        } else {
            // totalStackSize = locals + nonvols + RET
            ULONG body = currentFrame->totalStackSize - 8; // minus RET

            context->Rsp -= body;
            PushToStack(context, (ULONG64)currentFrame->returnAddress);
        }

        if (currentFrame->setsFramePointer) {
            childSp = context->Rsp + 8; // rsp after RET
            bPreviousFrameSetUWOP_SET_FPREG = TRUE;
        }
    }

    // No explicit stop marker; unwinder will stop naturally
}

DWORD DummyFunction(LPVOID lpParam)
{
    printf("[+] Hello from dummy function!\n");
    return 0;
}

LONG CALLBACK VehCallback(PEXCEPTION_POINTERS ExceptionInfo)
{
    ULONG exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode != STATUS_ACCESS_VIOLATION) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    printf("[+] VEH Exception Handler called\n");
    printf("[+] Redirecting spoofed thread to RtlExitUserThread\n");

    ExceptionInfo->ContextRecord->Rip =
        (DWORD64)GetProcAddress(GetModuleHandleA("ntdll"),
                                "RtlExitUserThread");
    ExceptionInfo->ContextRecord->Rcx = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(int argc, char* argv[])
{
    StackFrame targetCallStack[MAX_STACK_FRAMES];
    int frameCount = 0;

    DWORD dwThreadId = 0;
    HANDLE hThread = NULL;
    CONTEXT context = { 0 };
    PVOID pHandler = NULL;
    DWORD suspendCount = 0;

    if (argc < 2 || strcmp(argv[1], "--svchost") == 0) {
        printf("[+] Target call stack profile: svchost (Dynamic Resolution)\n");

        StackProfileEntry svchostBlueprint[] = {
            { L"C:\\Windows\\System32\\kernelbase.dll", L"CtrlRoutine",              0x22,  FALSE },
            { L"C:\\Windows\\System32\\ntdll.dll",      "TpReleaseCleanupGroupMembers", 0x450, FALSE },
            { L"C:\\Windows\\System32\\kernel32.dll",   "BaseThreadInitThunk",     0x14,  FALSE },
            { L"C:\\Windows\\System32\\ntdll.dll",      "RtlUserThreadStart",      0x21,  FALSE }
        };

        BuildDynamicStack(svchostBlueprint,
                          sizeof(svchostBlueprint) / sizeof(svchostBlueprint[0]),
                          targetCallStack,
                          &frameCount);
    } else {
        printf("[-] Error: Incorrect argument. Options: --svchost\n");
        return -1;
    }

    if (frameCount == 0) {
        printf("[-] Error: Failed to resolve any frames.\n");
        return -1;
    }

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    if (!hUser32) {
        printf("[-] Failed to load user32.dll\n");
        return -1;
    }

    typedef int (WINAPI* PFN_MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
    PFN_MESSAGEBOXA pMessageBoxA =
        (PFN_MESSAGEBOXA)GetProcAddress(hUser32, "MessageBoxA");

    if (!pMessageBoxA) {
        printf("[-] Failed to resolve MessageBoxA\n");
        return -1;
    }

    hThread = CreateThread(
        NULL,
        MAX_STACK_SIZE,
        (LPTHREAD_START_ROUTINE)DummyFunction,
        NULL,
        CREATE_SUSPENDED,
        &dwThreadId);

    if (!hThread) {
        printf("[-] Failed to create suspended thread (Error: %lu)\n",
               GetLastError());
        return -1;
    }

    printf("[+] Created suspended thread: %lu\n", dwThreadId);

    context.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &context)) {
        printf("[-] Failed to get thread context\n");
        return -1;
    }

    printf("[+] Initialising spoofed thread state...\n");
    InitialiseFakeThreadState(&context, targetCallStack, frameCount);

    const char* szText    = "Hello from the spoofed thread context!";
    const char* szCaption = "Diagnostic Notification";

    context.Rcx = (DWORD64)NULL;
    context.Rdx = (DWORD64)szText;
    context.R8  = (DWORD64)szCaption;
    context.R9  = (DWORD64)(MB_OK | MB_ICONINFORMATION);
    context.Rip = (DWORD64)pMessageBoxA;

    printf("[+] Top synthetic RET: %p\n", *(PVOID*)context.Rsp);

    if (!SetThreadContext(hThread, &context)) {
        printf("[-] Failed to set thread context\n");
        return -1;
    }

    printf("[+] Thread context updated with spoofed stack layout.\n");

    printf("\n[!] TARGET THREAD IS SUSPENDED");
    printf("\n    -> Thread ID (Decimal): %lu", dwThreadId);
    printf("\n    -> Thread ID (Hex):     0x%X", dwThreadId);
    printf("\n[!] Attach WinDbg now, select this thread (~Ns), then run 'kp'. Press ENTER here to resume...\n");
    getchar();

    pHandler = AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VehCallback);

    printf("[+] Resuming suspended thread...\n");
    suspendCount = ResumeThread(hThread);

    if (hThread) CloseHandle(hThread);
    if (pHandler) RemoveVectoredExceptionHandler(pHandler);

    return 0;
}
