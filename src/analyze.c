#include "analyze.h"
#include "utils.h"
#include "elf_structs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void analyze_pe(const char *path);
static void analyze_elf(const char *path);
static void analyze_macho(const char *path);
static void analyze_mz(const char *path);
static void analyze_aout(const char *path);
static void analyze_coff(const char *path);
static void analyze_com(const char *path);

void analyze_binary(const char *path, BinaryFormat format) {
    printf("[+] Starting detailed analysis...\n");
    switch (format) {
        case FORMAT_PE:     analyze_pe(path);     break;
        case FORMAT_ELF:    analyze_elf(path);    break;
        case FORMAT_MACHO:  analyze_macho(path);  break;
        case FORMAT_MZ:     analyze_mz(path);     break;
        case FORMAT_AOUT:   analyze_aout(path);   break;
        case FORMAT_COFF:   analyze_coff(path);   break;
        case FORMAT_COM:    analyze_com(path);    break;
        default: printf("[+] No detailed analysis for this format yet\n"); break;
    }
}

/* Implement at least one properly — others can be stubs */
static void analyze_pe(const char *path) {
    printf("[+] Format: PE (Portable Executable)\n");
    FILE *file = fopen(path, "rb");
    if (!file) return;

    uint32_t pe_offset;
    fseek(file, 0x3C, SEEK_SET);
    fread(&pe_offset, 4, 1, file);

    fseek(file, pe_offset + 4, SEEK_SET);
    uint16_t machine;
    fread(&machine, 2, 1, file);
    const char *arch = (machine == 0x8664) ? "x64" : (machine == 0x014c) ? "x86" : "Other";
    printf("[+] Architecture: %s\n", arch);

    // Add more later...
    fclose(file);
}

static void analyze_elf(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        printf("[-] Error opening file for ELF parsing\n");
        return;
    }

    // Read e_ident (16 bytes)
    unsigned char e_ident[16];
    fread(e_ident, 1, 16, file);

    // Basic validation already done in detection
    printf("[+] ELF Header Breakdown\n");

    // Class
    const char *class = (e_ident[4] == 1) ? "32-bit" : (e_ident[4] == 2) ? "64-bit" : "Invalid";
    // Endianness
    const char *endian = (e_ident[5] == 1) ? "Little-endian" : (e_ident[5] == 2) ? "Big-endian" : "Invalid";
    // ABI
    const char *abi = "System V"; // Most common; can expand later
    printf("  Class: %s\n", class);
    printf("  Data Encoding: %s\n", endian);
    printf("  OS/ABI: %s (version %d)\n", abi, e_ident[8]);

    // Determine if 64-bit
    int is_64 = (e_ident[4] == 2);

    if (is_64) {
        // 64-bit ELF header
        Elf64_Ehdr ehdr;
        fseek(file, 0, SEEK_SET);
        fread(&ehdr, sizeof(Elf64_Ehdr), 1, file);

        const char *type = (ehdr.e_type == 1) ? "Relocatable" :
                           (ehdr.e_type == 2) ? "Executable" :
                           (ehdr.e_type == 3) ? "Shared object" :
                           (ehdr.e_type == 4) ? "Core" : "Unknown";

        const char *machine = (ehdr.e_machine == 62) ? "x86_64" :
                              (ehdr.e_machine == 3) ? "x86" :
                              (ehdr.e_machine == 40) ? "ARM" : "Other";

        printf("  Type: %s\n", type);
        printf("  Machine: %s\n", machine);
        printf("  Entry Point: 0x%lx\n", (unsigned long)ehdr.e_entry);
        printf("  Program Headers: %d entries at offset 0x%lx\n", ehdr.e_phnum, (unsigned long)ehdr.e_phoff);
        printf("  Section Headers: %d entries at offset 0x%lx\n", ehdr.e_shnum, (unsigned long)ehdr.e_shoff);
        printf("  Flags: 0x%x\n", ehdr.e_flags);

        // Program Headers
        print_header("PROGRAM HEADERS (Segments)");
        fseek(file, ehdr.e_phoff, SEEK_SET);
        for (int i = 0; i < ehdr.e_phnum; i++) {
            Elf64_Phdr phdr;
            fread(&phdr, sizeof(Elf64_Phdr), 1, file);

            const char *ptype = (phdr.p_type == 1) ? "PT_LOAD" :
                                (phdr.p_type == 2) ? "PT_DYNAMIC" :
                                (phdr.p_type == 3) ? "PT_INTERP" :
                                (phdr.p_type == 6) ? "PT_PHDR" : "Other";

            char flags[4] = {0};
            if (phdr.p_flags & 4) flags[strlen(flags)] = 'R';
            if (phdr.p_flags & 2) flags[strlen(flags)] = 'W';
            if (phdr.p_flags & 1) flags[strlen(flags)] = 'X';

            printf("  [%2d] %s | Offset: 0x%lx | VAddr: 0x%lx | FileSz: 0x%lx | MemSz: 0x%lx | Flags: %s | Align: 0x%lx\n",
                   i, ptype, (unsigned long)phdr.p_offset, (unsigned long)phdr.p_vaddr,
                   (unsigned long)phdr.p_filesz, (unsigned long)phdr.p_memsz, flags, (unsigned long)phdr.p_align);

            // Special handling for PT_INTERP
            if (phdr.p_type == 3) {
                char interp[256] = {0};
                fseek(file, phdr.p_offset, SEEK_SET);
                fread(interp, 1, phdr.p_filesz - 1, file); // null-terminated
                printf("       Interpreter: %s\n", interp);
            }
        }

        // Section Headers (key ones)
        print_header("KEY SECTION HEADERS");
        fseek(file, ehdr.e_shoff, SEEK_SET);
        char strtab[8192] = {0}; // String table buffer
        uint64_t strtab_offset = 0;

        // First pass: find string table (shstrndx)
        uint16_t shstrndx = ehdr.e_shstrndx;
        fseek(file, ehdr.e_shoff + shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
        Elf64_Shdr str_shdr;
        fread(&str_shdr, sizeof(Elf64_Shdr), 1, file);
        fseek(file, str_shdr.sh_offset, SEEK_SET);
        fread(strtab, 1, str_shdr.sh_size > sizeof(strtab) ? sizeof(strtab) : str_shdr.sh_size, file);

        // Second pass: list key sections
        fseek(file, ehdr.e_shoff, SEEK_SET);
        for (int i = 0; i < ehdr.e_shnum; i++) {
            Elf64_Shdr shdr;
            fread(&shdr, sizeof(Elf64_Shdr), 1, file);

            const char *name = (shdr.sh_name < strlen(strtab)) ? &strtab[shdr.sh_name] : "<corrupt>";

            // Filter for interesting sections
            if (strstr(name, ".text") || strstr(name, ".data") || strstr(name, ".bss") ||
                strstr(name, ".rodata") || strstr(name, ".dynamic") || strstr(name, ".interp")) {

                const char *stype = (shdr.sh_type == 1) ? "PROGBITS" :
                                    (shdr.sh_type == 8) ? "NOBITS" : "Other";

                char sflags[4] = {0};
                if (shdr.sh_flags & 0x1) strcat(sflags, "W");
                if (shdr.sh_flags & 0x2) strcat(sflags, "A");
                if (shdr.sh_flags & 0x4) strcat(sflags, "X");

                printf("  [%2d] %-15s | Type: %-10s | Addr: 0x%lx | Offset: 0x%lx | Size: 0x%lx | Flags: %s | Align: %ld\n",
                       i, name, stype, (unsigned long)shdr.sh_addr, (unsigned long)shdr.sh_offset,
                       (unsigned long)shdr.sh_size, sflags, (unsigned long)shdr.sh_addralign);
            }
        }
    } else {
        // 32-bit version (similar, but with Elf32 structs — implement if needed)
        printf("  32-bit ELF parsing not fully implemented yet\n");
    }

    fclose(file);
}

static void analyze_macho(const char *path) { printf("[+] Mach-O analysis stub\n"); }
static void analyze_mz(const char *path) { printf("[+] Pure MZ DOS executable\n"); }
static void analyze_aout(const char *path) { printf("[+] a.out analysis stub\n"); }
static void analyze_coff(const char *path) { printf("[+] COFF analysis stub\n"); }
static void analyze_com(const char *path) { printf("[+] COM flat binary (no header)\n"); }
