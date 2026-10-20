#!/usr/bin/env bash
# Real-compiler smoke test for hosts where cc/gcc/clang emits ELF objects.
set -euo pipefail

BIN="$1"
SOURCE_DIR="$2"
CC_BIN="${3:-cc}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CFLAGS=(-c -O0 -fno-pic -fno-pie -fno-common -fno-asynchronous-unwind-tables -fno-stack-protector)

"$CC_BIN" "${CFLAGS[@]}" "$SOURCE_DIR/a.c" -o "$WORK/a.o"
"$CC_BIN" "${CFLAGS[@]}" "$SOURCE_DIR/b.c" -o "$WORK/b.o"

"$BIN" inspect "$WORK/a.o" > "$WORK/inspect.txt"
grep -q 'R_X86_64_PLT32\|R_X86_64_PC32' "$WORK/inspect.txt"
grep -q 'entry_like_function' "$WORK/inspect.txt"
grep -q 'helper' "$WORK/inspect.txt"

# Compare the inspector's section, symbol, and relocation facts with GNU
# readelf when it is available on the host.
if command -v readelf >/dev/null 2>&1; then
    readelf -W -S "$WORK/a.o" > "$WORK/readelf-sections.txt"
    readelf -W -s "$WORK/a.o" > "$WORK/readelf-symbols.txt"
    readelf -W -r "$WORK/a.o" > "$WORK/readelf-relocations.txt"

    grep -q '\.text' "$WORK/inspect.txt"
    grep -q '\.rela\.text' "$WORK/readelf-sections.txt"
    grep -q 'entry_like_function' "$WORK/readelf-symbols.txt"
    grep -q 'helper' "$WORK/readelf-symbols.txt"
    grep -Eq 'R_X86_64_(PLT32|PC32).*symbol=helper' "$WORK/inspect.txt"
    grep -Eq 'R_X86_64_(PLT32|PC32).*helper' "$WORK/readelf-relocations.txt"
fi

"$BIN" link -o "$WORK/combined.bin" --map "$WORK/combined.map" --base 0x401000 "$WORK/a.o" "$WORK/b.o" > "$WORK/link.txt"
test -s "$WORK/combined.bin"
test -s "$WORK/combined.map"
grep -q 'helper' "$WORK/combined.map"
grep -q 'entry_like_function' "$WORK/combined.map"
grep -Eq 'Applied relocations: [1-9][0-9]*' "$WORK/combined.map"

# Preserve the real compiler-produced header but remove its section table.
# The parser must reject the malformed object cleanly rather than reading past
# the end of the file.
head -c 64 "$WORK/a.o" > "$WORK/truncated.o"
if "$BIN" inspect "$WORK/truncated.o" > "$WORK/truncated.txt" 2>&1; then
    echo "FAIL: inspector accepted an object with a truncated section table" >&2
    exit 1
fi
grep -q 'section table is outside the file' "$WORK/truncated.txt"

echo "PASS: real compiler object inspection and cross-object relocation"
