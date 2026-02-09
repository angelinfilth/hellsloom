#include "hells_loom.h"
#include <iostream>

void PrintBanner() {
    printf("\n");
    printf("  _   _      _ _ _       _                       \n");
    printf(" | | | | ___| | ( )___  | |    ___   ___  _ __ ___  \n");
    printf(" | |_| |/ _ \\ | |// __| | |   / _ \\ / _ \\| '_ ` _ \\ \n");
    printf(" |  _  |  __/ | | \\__ \\ | |__| (_) | (_) | | | | | |\n");
    printf(" |_| |_|\\___|_|_| |___/ |_____\\___/ \\___/|_| |_| |_|\n");
    printf("\n");
    printf("    Fiber-Based Process Execution via Multi-Fiber Chaining\n");
    printf("         https://github.com/angelinfilth/hellsloom\n");
    printf("\n");
}

int wmain(int argc, wchar_t* argv[]) {
    PrintBanner();
    
    printf("[*] Setting up fiber context...\n");
    
    ProcessManager manager(L"C:\\Windows\\System32\\calc.exe");
    
    printf("[*] Creating worker fibers...\n");
    
    if (manager.Run()) {
        printf("[+] Process spawned successfully\n");
        Sleep(2000);
        return 0;
    } else {
        printf("[-] Execution failed\n");
        return 1;
    }
}
