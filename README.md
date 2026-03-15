# Bin-Analyzer — Lightweight Multi-Format Binary Analysis Tool

**C | ELF/PE/Mach-O | Reverse Engineering & Malware Analysis**

A fast, from-scratch command-line binary analyzer written in pure C. Parses ELF structures, detects packing via entropy, extracts suspicious strings, performs lightweight YARA-style IOC scanning, and provides hex/bit views — perfect for quick static analysis during CTFs, RE practice, or VAPT.

Live on GitHub: https://github.com/optimus0brime/bin-analyzer  

## Features
- Automatic binary format detection (ELF64, PE, Mach-O, MZ, etc.)
- Full ELF header + program header + section header parsing
- Entropy analysis + histogram with packing detection (UPX, Themida, etc.)
- Suspicious string extraction
- Hex dump & binary bit view (first N bytes)
- Embedded YARA-lite signature scanner (common IOCs, packers, APIs, anti-debug)
- File hashes (MD5/SHA1/SHA256)
- Clean modular code (analyze, detect, view, utils + ELF structs)

## Build & Run
```bash
make          # builds ./binanalyzer
./binanalyzer -A /bin/ls          # full analysis
./binanalyzer -e malware_sample   # entropy only
./binanalyzer -s packed.bin       # suspicious strings
./binanalyzer -H                  # help
