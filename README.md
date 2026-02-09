# Hell's Loom

**Fiber-Based Process Execution via Multi-Fiber Chaining**

A POC that aims to desmotrate uncodemented Windows Fiber API exploitaton.

## Overview

Hell's Loom is a POC that demonstrates a previously undocmented technique(at least in public malware research) that chains multiple fibers together to spawn processes.
## Why Fibers Over Threads?

### Thread-Based Injection Problems

Thread-based process injection has significant detection issues:

1. **Kernel Callbacks**: `CreateThread` and `CreateRemoteThread` trigger `PsSetCreateThreadNotifyRoutine` callbacks that EDRs tend to monitor
2. **Syscall Visibility**: Thread creation generates syscalls visible in ETW traces
3. **Call Stack Patterns**: Thread-based injection creates predictable call stacks that behavioral engines detect
4. **Sync Overhead**: Mutexes and events create additional kernel objects that generate telemetry

### Fiber Advantages

Fibers provide unique evasion capabilities:

1. **User-Mode Scheduling**: `SwitchToFiber` executes entirely in user-mode without kernel involvement, bypassing kernel callbacks
2. **No Thread Creation**: Fibers run within existing threads, eliminating `CreateThread`/`CreateRemoteThread` API calls
3. **Cooperative Multitasking**: Manual context switching provides precise execution control
4. **Small API Surface**: Only requires `ConvertThreadToFiber`, `CreateFiber`, and `SwitchToFiber`
5. **Stack Isolation**: Each fiber has its own stack without requiring memory protection calls
6. **No Synchronization Objects**: Eliminates mutexes, events, and semaphores that generate telemetry


## Multi-Fiber Chaining

This implementation uses an undocumented pattern of chaining three fibers together:

1. **Main Fiber**: Converted from the primary thread, acts as the control fiber
2. **Worker Fiber**: Spawns the target process in suspended state and captures thread context
3. **Helper Fiber**: Performs memory injection and resumes the target process

The worker fiber switches to the helper fiber instead of returning to main, creating a chain: Main → Worker → Helper → Main. 

### Execution Flow

```
Main Thread
    ↓
ConvertThreadToFiber (Main Fiber)
    ↓
CreateFiber (Worker Fiber)
    ↓
CreateFiber (Helper Fiber)
    ↓
SwitchToFiber (Worker) → CreateProcessW (SUSPENDED) + GetThreadContext
    ↓
SwitchToFiber (Helper) → VirtualAllocEx + WriteProcessMemory + ResumeThread
    ↓
SwitchToFiber (Main) → Cleanup
```
## Disclaimer

This code is for educational and security research purposes only. Unauthorized use is illegal. Use only in authorized testing environments.

## License

MIT License
