#define _GNU_SOURCE   // ← This enables memmem()

#include <stdio.h>
#include <string.h>
#include "yara_lite.h"  // if you have a header

void scan_with_embedded_yara(const unsigned char *data, size_t size) {
    printf("[+] Embedded YARA-like rule scan (malware IOCs):\n");

    const char *rules[] = {
        "UPX!", "This program cannot be run in DOS mode",
        "VirtualAlloc", "CreateRemoteThread", "WriteProcessMemory",
        "IsDebuggerPresent", "anti-debug", "sandbox",
        "http://", "https://", "cmd.exe", "powershell.exe",
        "MZ", "PE\0\0",  // Raw bytes for PE signature
        NULL
    };

    for (int i = 0; rules[i]; i++) {
        const char *rule = rules[i];
        size_t rule_len = strlen(rule);

        if (memmem(data, size, rule, rule_len)) {
            printf("   !!!  Match: \"%s\"\n", rule);
        }
    }

    printf("[+] YARA-lite scan complete\n");
}
