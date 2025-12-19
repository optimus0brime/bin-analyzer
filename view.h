#ifndef VIEW_H
#define VIEW_H

#include <stddef.h>

void show_hex(const char *path, long offset, size_t len);
void show_binary(const char *path, long offset, size_t len);
void show_strings(const char *path);
void show_entropy_histogram(const unsigned char *data, size_t size);

/* NEW */
void show_suspicious_strings(const char *path);

#endif
