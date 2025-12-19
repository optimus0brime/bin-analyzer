#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "types.h"
#include "detect.h"
#include "analyze.h"
#include "view.h"
#include "utils.h"

void usage(const char *prog) {
    printf("BinAnalyzer — Multi-Format Binary Analysis Tool\n\n");
    printf("Usage: %s [options] <binary_file>\n\n", prog);
    printf("Options:\n");
    printf("  -A          Run all analyses (default if no options)\n");
    printf("  -f          Show format detection and basic header info\n");
    printf("  -h          Hex dump (first 256 bytes)\n");
    printf("  -b          Binary bit view (first 64 bytes)\n");
    printf("  -s          Extract printable strings\n");
    printf("  -e          Entropy analysis + histogram\n");
    printf("  -H          Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -A /bin/ls\n", prog);
    printf("  %s -s malware.exe\n", prog);
    printf("  %s -e packed.bin\n", prog);
}



int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    int opt;
    int flag_all = 0, flag_format = 0, flag_hex = 0, flag_bin = 0;
    int flag_strings = 0, flag_entropy = 0;

    while ((opt = getopt(argc, argv, "AfhbsHe")) != -1) {
        switch (opt) {
            case 'A': flag_all = 1; break;
            case 'f': flag_format = 1; break;
            case 'h': flag_hex = 1; break;
            case 'b': flag_bin = 1; break;
            case 's': flag_strings = 1; break;
            case 'e': flag_entropy = 1; break;
            case 'H': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: No file specified\n");
        return 1;
    }

    const char *path = argv[optind];

    // Default: run all if no flags
    if (!flag_format && !flag_hex && !flag_bin && !flag_strings && !flag_entropy) {
        flag_all = 1;
    }

    BinaryFormat format = detect_format(path);
    const char *names[] = {"Unknown","ELF","PE","Mach-O","MZ","a.out","COFF","COM"};
    
    print_header("BINARY ANALYSIS REPORT");
    printf("Target File: %s\n", path);
    printf("Detected Format: %s\n", names[format]);

    if (format == FORMAT_UNKNOWN) {
        printf("[-] Error: Unsupported or unrecognized binary format\n");
        return 1;
    }

    if (flag_all || flag_format) {
        print_header("FORMAT-SPECIFIC ANALYSIS");
        analyze_binary(path, format);
    }

    unsigned char *data = NULL;
    size_t size = 0;
    if (flag_all || flag_entropy || flag_strings || flag_hex || flag_bin) {
        data = load_file(path, &size);
        if (!data) {
            perror("Failed to load file into memory");
            return 1;
        }
    }

if (flag_all || flag_entropy) {
    print_header("ENTROPY ANALYSIS");
    double ent = calculate_entropy(data, size);
    printf("File Size: %zu bytes (%.2f KB)\n", size, size / 1024.0);
    printf("Overall Entropy: %.2f\n", ent);

    if (ent > 7.8) {
        printf("~####~ VERY HIGH ENTROPY — Almost certainly packed or encrypted\n");
        printf("   Common packers: UPX, ASPack, PECompact, Themida\n");
        printf("   Try: upx -d %s  or  detect-it-easy\n", path);
    } else if (ent > 7.0) {
        printf("~###~ HIGH ENTROPY — Likely packed (e.g., UPX, mPRESS)\n");
        printf("   Suggest running: strings %s | grep -i 'UPX\\|' 'This file was packed'\n", path);
    } else if (ent > 6.0) {
        printf("~##~ Medium-High — Possible light compression or obfuscation\n");
    } else {
        printf("~#~ Normal entropy — Likely unpacked native code\n");
    }

    show_entropy_histogram(data, size);
}

    if (flag_all || flag_strings) {
        print_header("EXTRACTED STRINGS");
        show_suspicious_strings(path);
    }

    if (flag_all || flag_hex) {
        print_header("HEX DUMP (First 256 bytes)");
        show_hex(path, 0, 256);
    }

    if (flag_all || flag_bin) {
        print_header("BIT VIEW (First 64 bytes)");
        show_binary(path, 0, 64);
    }

    if (data) free(data);

    print_hashes(path);

    printf("\nAnalysis complete.\n");
    return 0;
}
