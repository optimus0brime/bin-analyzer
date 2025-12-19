#define _POSIX_C_SOURCE 200809L   // Must be first!
#include "utils.h"

#include "view.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>   // for popen/pclose

void show_hex(const char *path, long offset, size_t len) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        printf("[-] Error: Cannot open file for hex dump\n");
        return;
    }
    fseek(file, offset, SEEK_SET);

    unsigned char buf[16];
    size_t read;
    long cur = offset;
    printf("[+] Hex dump (offset 0x%lx, length %zu bytes):\n", offset, len);
    while ((read = fread(buf, 1, 16, file)) > 0 && len > 0) {
        printf("%08lx  ", cur);
        for (size_t i = 0; i < read; ++i) {
            printf("%02x ", buf[i]);
            if (i == 7) printf(" ");
        }
        for (size_t i = read; i < 16; ++i) printf("   ");
        printf(" |");
        for (size_t i = 0; i < read; ++i) {
            printf("%c", isprint(buf[i]) ? buf[i] : '.');
        }
        printf("|\n");
        cur += read;
        if (len >= read) len -= read; else break;
    }
    fclose(file);
}

void show_binary(const char *path, long offset, size_t len) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        printf("[-] Error: Cannot open file for binary view\n");
        return;
    }
    fseek(file, offset, SEEK_SET);

    unsigned char buf[8];
    size_t read;
    long cur = offset;
    printf("[+] Binary bit view (offset 0x%lx, length %zu bytes):\n", offset, len);
    while ((read = fread(buf, 1, 8, file)) > 0 && len > 0) {
        printf("%08lx: ", cur);
        for (size_t i = 0; i < read; i++) {
            for (int b = 7; b >= 0; b--) {
                printf("%d", (buf[i] >> b) & 1);
            }
            printf(" ");
        }
        printf("\n");
        cur += read;
        if (len >= read) len -= read; else break;
    }
    fclose(file);
}

void show_entropy_histogram(const unsigned char *data, size_t size) {
    if (size == 0) {
        printf("[!] No data for histogram\n");
        return;
    }
    const int bins = 10;
    size_t bin_size = size / bins;
    printf("[+] Entropy histogram (%d bins):\n", bins);
    for (int i = 0; i < bins; i++) {
        size_t start = i * bin_size;
        size_t end = (i == bins - 1) ? size : start + bin_size;
        double e = calculate_entropy(data + start, end - start);
        int stars = (int)(e * 5);  // scale to max ~40 stars
        if (stars > 40) stars = 40;
        printf("  [%2d] 0x%08zx-0x%08zx: %.2f | ", i, start, end - 1, e);
        for (int j = 0; j < stars; j++) printf("*");
        printf("\n");
    }
}

void show_suspicious_strings(const char *path) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "strings -a -n 5 \"%s\" 2>/dev/null", path);

    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        printf("[-] Warning: Failed to execute 'strings' command\n");
        return;
    }

    printf("[+] Suspicious / Interesting Strings (filtered):\n");

    char line[1024];
    while (fgets(line, sizeof(line), pipe) != NULL) {
        line[strcspn(line, "\n")] = '\0';

        if (strlen(line) == 0) continue;

        // URLs
        if (strstr(line, "http://") || strstr(line, "https://") || strstr(line, "ftp://")) {
            printf("   [@] URL: %s\n", line);
            continue;
        }

        // Private IPs
        if (strstr(line, "192.168.") || strstr(line, "10.") ||
            (strstr(line, "172.") && (
             strstr(line, "172.16.") || strstr(line, "172.17.") || strstr(line, "172.18.") ||
             strstr(line, "172.19.") || strstr(line, "172.20.") || strstr(line, "172.21.") ||
             strstr(line, "172.22.") || strstr(line, "172.23.") || strstr(line, "172.24.") ||
             strstr(line, "172.25.") || strstr(line, "172.26.") || strstr(line, "172.27.") ||
             strstr(line, "172.28.") || strstr(line, "172.29.") || strstr(line, "172.30.") ||
             strstr(line, "172.31."))) ||
            strstr(line, "127.0.0.1")) {
            printf("   [!] Private/Local IP: %s\n", line);
            continue;
        }

        // Suspicious APIs
        const char *apis[] = {
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent", "LoadLibrary", "GetProcAddress", "URLDownloadToFile",
            NULL
        };
        int matched = 0;
        for (int i = 0; apis[i]; i++) {
            if (strstr(line, apis[i])) {
                printf("   !!! Suspicious API: %s\n", line);
                matched = 1;
                break;
            }
        }
        if (matched) continue;

        // Packers
        if (strstr(line, "UPX") || strstr(line, "Themida") || strstr(line, "VMProtect") ||
            strstr(line, "packed with")) {
            printf("   $ Packer Hint: %s\n", line);
        }
    }

    pclose(pipe);
}
