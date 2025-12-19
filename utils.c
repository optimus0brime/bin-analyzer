#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

double calculate_entropy(const unsigned char *data, size_t size) {
    if (size == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

unsigned char *load_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    *out_size = ftell(f);
    rewind(f);

    unsigned char *data = malloc(*out_size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    fread(data, 1, *out_size, f);
    fclose(f);
    return data;
}

void print_hashes(const char *path) {
    printf("[+] Hashes: MD5/SHA256 placeholder (add OpenSSL or public-domain impl later)\n");
}

void print_header(const char *title) {
    printf("\n╔══════════════════════════════════════════════════════════╗\n");
    printf("║ %*s%s%*s      ║\n", 
           (int)(26 - strlen(title)/2), "", title, 
           (int)(25 - (strlen(title)+1)/2), "");
    printf("╚══════════════════════════════════════════════════════════╝\n");
}
