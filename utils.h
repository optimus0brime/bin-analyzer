#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

double calculate_entropy(const unsigned char *data, size_t size);
unsigned char *load_file(const char *path, size_t *out_size);
void print_hashes(const char *path);
void print_header(const char *title);

#endif
