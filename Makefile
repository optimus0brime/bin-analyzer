CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -Iinclude
SRCDIR = src
BUILDDIR = build
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJS = $(SOURCES:$(SRCDIR)/%.c=$(BUILDDIR)/%.o)

# Default target
all: binanalyzer

# Create build directory
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Compile sources to objects
$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Link final executable
binanalyzer: $(OBJS)
	$(CC) $(CFLAGS) -o binanalyzer $(OBJS) -lm

# Clean build artifacts
clean:
	rm -rf $(BUILDDIR) binanalyzer

.PHONY: all clean

