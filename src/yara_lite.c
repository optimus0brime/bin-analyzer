// yara_lite.c
#include <stdio.h>
#include <string.h>

void scan_with_embedded_yara(const unsigned char *data, size_t size) {
    printf("[+] Embedded YARA-like rule scan (malware IOCs):\n");

    const char *rules[] = {
        "UPX!", "This program cannot be run in DOS mode", // Common in PE
        "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
        "IsDebuggerPresent", "anti-debug", "sandbox",
        "http://", "https://", "cmd.exe", "powershell.exe",
        NULL
    };

    for (int i = 0; rules[i]; i++) {
        if (memmem(data, size, rules[i], strlen(rules[i]))) {
            printf("   !!!  Match: \"%s\"\n", rules[i]);
        }
    }
}
