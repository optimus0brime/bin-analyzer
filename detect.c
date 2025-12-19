#include "detect.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

BinaryFormat detect_format(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return FORMAT_UNKNOWN;

    unsigned char magic[64] = {0};  // Increased to 64 to safely read up to offset 0x3C + 4
    size_t read = fread(magic, 1, sizeof(magic), file);
    if (read < 4) {
        fclose(file);
        return FORMAT_UNKNOWN;
    }

    // ELF
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        fclose(file);
        return FORMAT_ELF;
    }

    // Mach-O
    uint32_t m = *(uint32_t*)magic;
    if (m == 0xfeedface || m == 0xcefaedfe || m == 0xfeedfacf || m == 0xcffaedfe ||
        m == 0xcafebabe || m == 0xbebafeca) {
        fclose(file);
        return FORMAT_MACHO;
    }

    // MZ -> check for PE
    if (magic[0] == 'M' && magic[1] == 'Z') {
        if (read >= 64) {  // Need at least 64 bytes for safe lfanew access
            uint32_t pe_offset = *(uint32_t*)(magic + 0x3C);
            if (pe_offset < 1024 && pe_offset + 4 <= read) {
                uint32_t pe_sig = *(uint32_t*)(magic + pe_offset);
                if (pe_sig == 0x00004550) {  // "PE\0\0"
                    fclose(file);
                    return FORMAT_PE;
                }
            }
        }
        fclose(file);
        return FORMAT_MZ;
    }

    // a.out
    uint32_t aout_magic = *(uint32_t*)magic;
    if (aout_magic == 0x01070107 || aout_magic == 0x01080108 || aout_magic == 0x010B010B) {
        fclose(file);
        return FORMAT_AOUT;
    }

    // COFF
    uint16_t machine = *(uint16_t*)magic;
    if (machine == 0x14c || machine == 0x8664 || machine == 0x0166 || machine == 0x01c0) {
        fclose(file);
        return FORMAT_COFF;
    }

    // COM
    if (magic[0] == 0xE9 || magic[0] == 0xEB) {
        fclose(file);
        return FORMAT_COM;
    }

    fclose(file);
    return FORMAT_UNKNOWN;
}
