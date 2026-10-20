# ELF64 Object File Inspector and Mini Linker

An educational C++17 tool that reads ELF64 x86-64 relocatable objects (`ET_REL`),
prints their section/symbol/relocation metadata, and performs a restricted,
relocation-aware static layout of several objects into a flat memory image plus
a human-readable link map.

This is a study tool for how relocations and symbol resolution work. It is
**not** a general-purpose system linker and it does not emit a runnable ELF
executable.

## Purpose

Linkers are usually black boxes. This project exposes the middle of the
pipeline in a small, readable program:

1. Parse the ELF header, section headers, symbol table, string tables, and
   `SHT_RELA` relocation sections.
2. Merge the allocated `.text`, `.rodata`, `.data`, and `.bss` input sections
   into output sections, honoring section alignment.
3. Resolve global and weak symbols, reporting unresolved references and
   duplicate strong definitions.
4. Apply the supported x86-64 relocations.
5. Emit a flat byte image and a map that explains every address and
   contribution.

## Features

- `inspect` mode: sections with type, flags, size, and alignment; symbols with
  bind/type/section; relocations with type, symbol, and addend.
- `link` mode: multi-object merge into `.text`, `.rodata`, `.data`, and `.bss`,
  with per-section alignment and configurable base address.
- Section-name grouping: `.text.*` merges into `.text`, `.rodata.*` into
  `.rodata`, `.data.*` into `.data`, and `.bss.*` into `.bss` (so output from
  `-ffunction-sections`/`-fdata-sections` works).
- Symbol resolution with ELF weak-override semantics: one strong definition
  wins over weak ones; duplicate strong definitions are an error; unresolved
  strong references are an error; unresolved weak references resolve to zero
  (the usual static-link convention).
- Relocations: `R_X86_64_64`, `R_X86_64_PC32`, `R_X86_64_PLT32`,
  `R_X86_64_32`, `R_X86_64_32S`, plus `R_X86_64_NONE` (ignored).
- Deterministic map output: sections in layout order and definitions sorted by
  name, so repeated links produce identical maps.
- Portable source: uses the system `<elf.h>` where present and a small built-in
  ELF64 definition header elsewhere (for example, MSVC on Windows).
- Cross-platform Python test suite that generates valid ELF64 fixtures and does
  not require a C compiler.

## Architecture

| Path | Role |
| --- | --- |
| `src/elf64_mini_linker.cpp` | Parser, linker/layout engine, map writer, CLI. |
| `src/elf64_types.h` | Uses `<elf.h>` when available; otherwise defines the ELF64 subset used by the tool. |
| `tests/elf_fixtures.py` | Builds ELF64 relocatable objects in memory for tests, including malformed variants. |
| `tests/run_tests.py` | Cross-platform `unittest` suite that runs the executable on generated fixtures. |
| `tests/test_link.sh` | Optional smoke test using a real host C compiler that emits ELF objects. |
| `tests/a.c`, `tests/b.c` | Source files for the real-compiler smoke test. |
| `CMakeLists.txt` | Build and CTest registration. |

Pipeline inside `elf64_mini_linker.cpp`:

```
parse -> merge sections/align -> assign addresses -> collect definitions
      -> resolve symbols -> apply relocations -> write image + map
```

Key structures: `Object` (one parsed input), `Section`, `Symbol`,
`Relocation`, `OutputSection`, `Contribution`, and `Definition`.

## Supported input subset

- ELF64, little-endian, `EM_X86_64`, `ET_REL` (relocatable) objects.
- One `SHT_SYMTAB` per object, with its `SHT_STRTAB` string table.
- `SHT_RELA` relocation sections linked to that symbol table.
- Allocated sections named `.text`, `.rodata`, `.data`, `.bss` or with a
  matching dotted suffix, e.g. `.text.hot`, `.rodata.str1.1`, `.data.rel.local`,
  `.bss.zero`.

## Build

CMake (recommended):

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Direct compilation with GCC or Clang on Linux/macOS:

```bash
g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic src/elf64_mini_linker.cpp -o elf64-mini
```

Windows with Visual Studio Build Tools (PowerShell, CMake + Ninja):

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The program only needs the C++17 standard library in addition to the ELF
definitions.

## Usage

```text
Usage:
  elf64-mini inspect <object.o>
  elf64-mini link -o <image.bin> [--map <map.txt>] [--base <addr>] <object1.o> ...

Options:
  --map <path>   Write the link map here (default: <image>.map).
  --base <addr>  Base address of the flat image (default: 0x400000).
  -h, --help     Show this help.
```

Exit codes: `0` success, `1` runtime/input error, `2` usage error.

### Inspect an object

```bash
gcc -c -O0 -fno-pic -fno-pie -fno-common \
    -fno-asynchronous-unwind-tables -fno-stack-protector tests/a.c -o a.o
./build/elf64-mini inspect a.o
```

Example output (illustrative and abridged; exact indexes and sizes depend on the
compiler):

```
File: a.o
ELF64 x86-64 relocatable object (ET_REL)
Sections: 8, symbols: 6, relocations: 1

Sections:
  [ 1] .text       type=PROGBITS   flags=AX   size=17 align=1
...
Symbols:
  [  4] entry_like_function   value=0x0 size=17 GLOBAL FUNC section=.text
  [  5] helper                value=0x0 size=0 GLOBAL NOTYPE section=UND
Relocations:
  .text+0x7  R_X86_64_PLT32          symbol=helper addend=-4
```

### Link/layout several objects

```bash
gcc -c -O0 -fno-pic -fno-pie -fno-common \
    -fno-asynchronous-unwind-tables -fno-stack-protector tests/a.c -o a.o
gcc -c -O0 -fno-pic -fno-pie -fno-common \
    -fno-asynchronous-unwind-tables -fno-stack-protector tests/b.c -o b.o
./build/elf64-mini link -o combined.bin --map combined.map a.o b.o
```

Example map (illustrative and abridged):

```
ELF64 Mini Linker map
Base address: 0x400000
Output: flat memory image, not a directly executable ELF file

Sections:
  .text      addr=0x400000 file_off=0x0 size=22 align=16
...
Global and weak definitions:
  0x400000  entry_like_function        GLOBAL  (a.o)
  0x400010  helper                     GLOBAL  (b.o)
...
Applied relocations: 1
```

### Relocation semantics

| Type | Calculation | Notes |
| --- | --- | --- |
| `R_X86_64_64` | `S + A` (64-bit) | Absolute address. |
| `R_X86_64_PC32` | `S + A - P` (32-bit signed) | `P` is the field's runtime address. |
| `R_X86_64_PLT32` | treated as `PC32` | No PLT is built; in a static flat image the displacement is the same. |
| `R_X86_64_32` | `S + A` (32-bit zero-extended) | Fails if negative or above `0xFFFFFFFF`. |
| `R_X86_64_32S` | `S + A` (32-bit sign-extended) | Fails outside `[-2^31, 2^31-1]`. |
| `R_X86_64_NONE` | no-op | Ignored; it does not count toward the applied total. |

`S` is the resolved symbol address, `A` the addend, and `P` the place being
relocated. Because absolute addresses are used, the flat image is only
consistent when it is loaded at the chosen `--base`.

### Symbol resolution rules

- A local symbol resolves inside its own object.
- A global or weak defined symbol resolves through a per-name definition table,
  so a strong definition in one object overrides a weak one everywhere,
  including references from the object that defined the weak symbol.
- Two strong definitions of the same name are an error. Among weak
  definitions, the first one seen (input order) wins.
- An undefined strong symbol is an error; an undefined weak symbol resolves to
  `0`.
- `SHN_ABS` symbols keep their absolute value.

## Tests

Build first, then run the fixture suite directly:

```bash
python tests/run_tests.py build/elf64-mini
```

Or through CTest:

```bash
ctest --test-dir build --output-on-failure
```

CTest registers:

- `elf64-mini-fixtures`: the Python suite (runs everywhere Python 3 is found).
  It builds ELF64 fixtures in a temporary directory and checks inspection,
  all supported relocations and their overflow conditions, cross-object
  resolution, weak/strong overriding, undefined weak references, alignment and
  padding, `.text.*`-style section grouping, `NOBITS`, deterministic maps, many
  malformed-input cases, and CLI behavior.
- `elf64-mini-real-objects`: optional; enabled only on Unix-like systems other
  than macOS when `bash` and a compiler named `cc`, `gcc`, or `clang` are found.
  It compiles `tests/a.c` and `tests/b.c` and links the resulting real ELF
  objects, checks that a truncated compiler-produced object is rejected, and
  compares section, symbol, and relocation details with GNU `readelf` when it
  is available. (On Windows the executable is `build/elf64-mini.exe`; the
  fixture suite works with either name.)

If `pyelftools` is installed (`pip install pyelftools`), one additional test
uses it as an independent parser to confirm that the generated fixtures are
valid ELF objects. The test is skipped when `pyelftools` is absent.

## Supported scope and limitations

This tool intentionally implements a small, honest subset:

- Only ELF64 little-endian x86-64 relocatable objects. It rejects other
  classes, byte orders, machines, and `ET_EXEC`/`ET_DYN` files.
- Only `SHT_RELA`. `SHT_REL` targeting a merged section is rejected with an
  explicit error instead of being silently ignored. (x86-64 normally uses
  `RELA`.)
- Non-allocated and unselected sections (for example `.eh_frame`, debug
  sections, `.init_array`, GOT/PLT, TLS, and custom sections) are skipped. If a
  retained relocation references one of them, linking fails with a clear
  message rather than producing wrong bytes.
- Unsupported relocations fail explicitly; they are never guessed.
- No dynamic linking, shared libraries, archives, lazy binding, symbol
  versioning, COMDAT/section groups, relocation relaxation, TLS, GNU IFUNC, or
  common-symbol allocation. Compile with `-fno-common` and `-fno-pic`/
  `-fno-pie` for predictable results. Common symbols are rejected at link time
  (even when unreferenced) so their storage is never silently dropped; TLS and
  GNU IFUNC symbols are rejected when referenced.
- Extended section numbering and extended symbol section indexes
  (`e_shnum == 0`, `SHN_XINDEX`) are rejected.
- The output is a flat byte image plus a map, not an executable ELF file. It
  has no program headers, entry point metadata, or segment permissions. Do not
  treat it as runnable code without a separate loader or format wrapper.
- `.bss` is zero-filled and included in the flat image, since a flat image has
  no separate BSS concept.
- Absolute relocations embed the chosen `--base`; loading the image elsewhere
  invalidates them.

## Repository notes

- This project is an independent educational work; it is not affiliated with,
  or endorsed by, any hardware or software vendor.
- No performance, hardware, or correctness claims are made beyond the cases
  covered by the automated tests.
