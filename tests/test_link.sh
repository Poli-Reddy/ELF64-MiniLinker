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

"$BIN" link -o "$WORK/combined.bin" --map "$WORK/combined.map" --base 0x401000 "$WORK/a.o" "$WORK/b.o" > "$WORK/link.txt"
test -s "$WORK/combined.bin"
test -s "$WORK/combined.map"
grep -q 'helper' "$WORK/combined.map"
grep -q 'entry_like_function' "$WORK/combined.map"
grep -Eq 'Applied relocations: [1-9][0-9]*' "$WORK/combined.map"

echo "PASS: real compiler object inspection and cross-object relocation"
