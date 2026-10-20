#!/usr/bin/env python3
"""Cross-platform tests for the ELF64 mini linker.

Usage:
    python tests/run_tests.py build/elf64-mini

The suite builds ELF64 fixtures in a temporary directory, runs the executable,
and checks parser errors, relocation arithmetic, symbol resolution, alignment,
map output, and CLI behavior.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Optional, Tuple

import elf_fixtures as f

try:
    from elftools.elf.elffile import ELFFile

    HAVE_PYELFTOOLS = True
except Exception:  # pragma: no cover - option depends on the environment
    HAVE_PYELFTOOLS = False

BINARY: Optional[Path] = None

SECTION_RE = re.compile(
    r"^\s+(?P<name>\.\S+)\s+addr=0x(?P<addr>[0-9a-f]+)\s+"
    r"file_off=0x(?P<off>[0-9a-f]+)\s+size=(?P<size>\d+)\s+align=(?P<align>\d+)\s*$"
)
SYMBOL_RE = re.compile(
    r"^\s+0x(?P<addr>[0-9a-f]+)\s+(?P<name>\S+)\s+(?P<bind>WEAK|GLOBAL)\s+\((?P<path>.*)\)\s*$"
)
APPLIED_RE = re.compile(r"^Applied relocations:\s+(\d+)\s*$", re.MULTILINE)
BASE_RE = re.compile(r"^Base address:\s+0x([0-9a-f]+)\s*$", re.MULTILINE)


def parse_map(text: str) -> Tuple[Dict[str, Tuple[int, int, int, int]], Dict[str, Tuple[int, str, str]], int]:
    sections: Dict[str, Tuple[int, int, int, int]] = {}
    symbols: Dict[str, Tuple[int, str, str]] = {}
    for line in text.splitlines():
        section_match = SECTION_RE.match(line)
        if section_match:
            sections[section_match.group("name")] = (
                int(section_match.group("addr"), 16),
                int(section_match.group("off"), 16),
                int(section_match.group("size")),
                int(section_match.group("align")),
            )
            continue
        symbol_match = SYMBOL_RE.match(line)
        if symbol_match:
            symbols[symbol_match.group("name")] = (
                int(symbol_match.group("addr"), 16),
                symbol_match.group("bind"),
                symbol_match.group("path"),
            )
    applied_match = APPLIED_RE.search(text)
    applied = int(applied_match.group(1)) if applied_match else -1
    return sections, symbols, applied


class LinkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="elf64-mini-test-")
        self.directory = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write_object(self, name: str, **kwargs) -> Path:
        path = self.directory / name
        path.write_bytes(f.build_object(**kwargs))
        return path

    def write_bytes(self, name: str, data: bytes) -> Path:
        path = self.directory / name
        path.write_bytes(data)
        return path

    def invoke(self, *args: object) -> subprocess.CompletedProcess[str]:
        assert BINARY is not None
        return subprocess.run(
            [str(BINARY), *(str(arg) for arg in args)],
            cwd=str(self.directory),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )

    def assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(
            result.returncode,
            0,
            msg=f"command failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def assert_failure(self, result: subprocess.CompletedProcess[str], message: str) -> None:
        self.assertNotEqual(result.returncode, 0, msg=f"expected failure, stdout:\n{result.stdout}")
        self.assertIn(message, result.stderr)

    def read_map(self, path: Path):
        return parse_map(path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # CLI and documentation-level behavior
    # ------------------------------------------------------------------
    def test_help_usage_and_option_errors(self) -> None:
        result = self.invoke()
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stderr)

        result = self.invoke("--help")
        self.assert_success(result)
        self.assertIn("elf64-mini inspect", result.stdout)
        self.assertIn("--base", result.stdout)

        result = self.invoke("link", "--help")
        self.assert_success(result)
        self.assertIn("Usage:", result.stdout)

        result = self.invoke("unknown-command")
        self.assert_failure(result, "unknown command")

        result = self.invoke("inspect")
        self.assertEqual(result.returncode, 2)

        result = self.invoke("inspect", "a.o", "b.o")
        self.assert_failure(result, "exactly one object file")

        result = self.invoke("link")
        self.assert_failure(result, "requires -o")

        result = self.invoke("link", "-o", "out.bin")
        self.assert_failure(result, "at least one object file")

        result = self.invoke("link", "-o", "out.bin", "--base")
        self.assert_failure(result, "--base requires an address")

        obj = self.write_object("a.o", sections=[f.text(b"\x90")])
        for bad_address in ("nonsense", "0x", "-1", "+1", "12zz"):
            with self.subTest(address=bad_address):
                result = self.invoke("link", "-o", "out.bin", "--base", bad_address, obj)
                self.assert_failure(result, "invalid --base address")

        result = self.invoke("link", "-o", "out.bin", "--bogus", obj)
        self.assert_failure(result, "unknown or incomplete option")

        result = self.invoke("link", "-o", "same.bin", "--map", "same.bin", obj)
        self.assert_failure(result, "must differ")

        result = self.invoke("link", "-o", "out.bin", obj, "--base", obj)
        self.assert_failure(result, "invalid --base address")

    def test_default_map_and_separate_map_path(self) -> None:
        obj = self.write_object("simple.o", sections=[f.text(b"\xC3")], symbols=[
            f.SymbolSpec("start", ".text", 0, 1, f.STB_GLOBAL, f.STT_FUNC)
        ])
        result = self.invoke("link", "-o", "image.bin", obj)
        self.assert_success(result)
        self.assertTrue((self.directory / "image.bin").is_file())
        self.assertTrue((self.directory / "image.bin.map").is_file())
        self.assertIn("Map: image.bin.map", result.stdout)

        result = self.invoke("link", "-o", "image2.bin", "--map", "custom.map", "--base", "0x401000", obj)
        self.assert_success(result)
        text = (self.directory / "custom.map").read_text(encoding="utf-8")
        base_match = BASE_RE.search(text)
        self.assertIsNotNone(base_match)
        self.assertEqual(int(base_match.group(1), 16), 0x401000)
        sections, symbols, applied = parse_map(text)
        self.assertEqual(sections[".text"][0], 0x401000)
        self.assertEqual(symbols["start"][0], 0x401000)
        self.assertEqual(applied, 0)

        # Decimal bases are accepted as well as hexadecimal ones.
        result = self.invoke("link", "-o", "image3.bin", "--map", "decimal.map", "--base", "4194304", obj)
        self.assert_success(result)
        decimal_text = (self.directory / "decimal.map").read_text(encoding="utf-8")
        decimal_base = BASE_RE.search(decimal_text)
        self.assertIsNotNone(decimal_base)
        self.assertEqual(int(decimal_base.group(1), 16), 0x400000)

    def test_double_dash_allows_dash_prefixed_input(self) -> None:
        obj = self.write_object("-dash.o", sections=[f.text(b"\x90")])
        result = self.invoke("link", "-o", "dash.bin", "--", obj.name)
        self.assert_success(result)
        self.assertTrue((self.directory / "dash.bin").is_file())

    def test_missing_output_directory_reports_error(self) -> None:
        obj = self.write_object("a.o", sections=[f.text(b"\x90")])
        result = self.invoke("link", "-o", "missing-dir/out.bin", obj)
        self.assert_failure(result, "cannot write")

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------
    def test_inspect_prints_sections_symbols_and_relocations(self) -> None:
        obj = self.write_object(
            "inspect.o",
            sections=[f.text(b"\x90" * 4), f.rodata(b"abc")],
            symbols=[
                f.SymbolSpec("entry", ".text", 0, 4, f.STB_GLOBAL, f.STT_FUNC),
                f.SymbolSpec("external"),
                f.SymbolSpec("absolute", "ABS", 0x1234, 0, f.STB_GLOBAL, f.STT_OBJECT),
            ],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_PLT32, "external", -4)],
        )
        result = self.invoke("inspect", obj)
        self.assert_success(result)
        self.assertIn("ELF64 x86-64 relocatable object", result.stdout)
        self.assertIn(".text", result.stdout)
        self.assertIn(".rodata", result.stdout)
        self.assertIn("entry", result.stdout)
        self.assertIn("external", result.stdout)
        self.assertIn("absolute", result.stdout)
        self.assertIn("R_X86_64_PLT32", result.stdout)
        self.assertIn("section=UND", result.stdout)
        self.assertIn("section=ABS", result.stdout)
        self.assertIn("FUNC", result.stdout)

    def test_inspect_accepts_unknown_relocation_type(self) -> None:
        obj = self.write_object(
            "unknown-reloc.o",
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("target", ".text", 0, 1, f.STB_GLOBAL, f.STT_FUNC)],
            relocs=[f.RelocSpec(".text", 0, 123, "target")],
        )
        result = self.invoke("inspect", obj)
        self.assert_success(result)
        self.assertIn("UNKNOWN_R_X86_64(123)", result.stdout)

    # ------------------------------------------------------------------
    # Linking and relocation arithmetic
    # ------------------------------------------------------------------
    def test_cross_object_plt32_and_alignment(self) -> None:
        a = self.write_object(
            "a.o",
            sections=[f.text(b"\xE8\0\0\0\0" + b"\x90" * 11, align=16)],
            symbols=[f.SymbolSpec("entry", ".text", 0, 5, f.STB_GLOBAL, f.STT_FUNC),
                     f.SymbolSpec("helper")],
            relocs=[f.RelocSpec(".text", 1, f.R_X86_64_PLT32, "helper", -4)],
        )
        b = self.write_object(
            "b.o",
            sections=[f.text(b"\xB8\x2A\0\0\0\xC3", align=16)],
            symbols=[f.SymbolSpec("helper", ".text", 0, 6, f.STB_GLOBAL, f.STT_FUNC)],
        )
        result = self.invoke("link", "-o", "combined.bin", "--map", "combined.map", "--base", "0x401000", a, b)
        self.assert_success(result)
        self.assertIn("Applied relocations: 1", result.stdout)

        image = (self.directory / "combined.bin").read_bytes()
        sections, symbols, applied = self.read_map(self.directory / "combined.map")
        self.assertEqual(sections[".text"], (0x401000, 0, 22, 16))
        self.assertEqual(symbols["entry"][0], 0x401000)
        self.assertEqual(symbols["helper"][0], 0x401010)
        self.assertEqual(applied, 1)
        self.assertEqual(image[0], 0xE8)
        self.assertEqual(struct.unpack_from("<i", image, 1)[0], 0x401010 - 0x401001 - 4)
        self.assertEqual(image[16:22], b"\xB8\x2A\0\0\0\xC3")

    def test_all_supported_relocation_types(self) -> None:
        obj = self.write_object(
            "relocations.o",
            sections=[f.text(b"\0" * 32), f.data_section(bytes(range(1, 9)), align=8)],
            symbols=[f.SymbolSpec("target", ".data", 0, 8, f.STB_GLOBAL, f.STT_OBJECT),
                     f.SymbolSpec("zero", "ABS", 0)],
            relocs=[
                f.RelocSpec(".text", 0, f.R_X86_64_64, "target", 0x10),
                f.RelocSpec(".text", 8, f.R_X86_64_PC32, "target", -4),
                f.RelocSpec(".text", 12, f.R_X86_64_PLT32, "target", -4),
                f.RelocSpec(".text", 16, f.R_X86_64_32, "target", 0),
                f.RelocSpec(".text", 20, f.R_X86_64_32S, "target", 0x100),
                f.RelocSpec(".text", 24, f.R_X86_64_32S, "zero", -1),
            ],
        )
        result = self.invoke("link", "-o", "relocations.bin", "--map", "relocations.map", obj)
        self.assert_success(result)
        image = (self.directory / "relocations.bin").read_bytes()
        sections, symbols, applied = self.read_map(self.directory / "relocations.map")

        self.assertEqual(sections[".text"][0], 0x400000)
        self.assertEqual(sections[".data"][0], 0x400020)
        self.assertEqual(symbols["target"][0], 0x400020)
        self.assertEqual(applied, 6)
        self.assertEqual(struct.unpack_from("<Q", image, 0)[0], 0x400030)
        self.assertEqual(struct.unpack_from("<i", image, 8)[0], 0x14)
        self.assertEqual(struct.unpack_from("<i", image, 12)[0], 0x10)
        self.assertEqual(struct.unpack_from("<I", image, 16)[0], 0x400020)
        self.assertEqual(struct.unpack_from("<I", image, 20)[0], 0x400120)
        self.assertEqual(struct.unpack_from("<I", image, 24)[0], 0xFFFFFFFF)
        self.assertEqual(image[32:40], bytes(range(1, 9)))

    def test_absolute_symbol_relocation(self) -> None:
        obj = self.write_object(
            "absolute.o",
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("fixed", "ABS", 0x12345678)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "fixed")],
        )
        result = self.invoke("link", "-o", "absolute.bin", obj)
        self.assert_success(result)
        self.assertEqual(struct.unpack_from("<Q", (self.directory / "absolute.bin").read_bytes(), 0)[0], 0x12345678)

    def test_none_relocation_is_ignored(self) -> None:
        obj = self.write_object(
            "none.o",
            sections=[f.text(b"\xAA\xBB\xCC\xDD" + b"\0" * 4)],
            symbols=[f.SymbolSpec("unresolved")],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_NONE, "unresolved")],
        )
        result = self.invoke("link", "-o", "none.bin", "--map", "none.map", obj)
        self.assert_success(result)
        image = (self.directory / "none.bin").read_bytes()
        _, _, applied = self.read_map(self.directory / "none.map")
        self.assertEqual(image[:4], b"\xAA\xBB\xCC\xDD")
        self.assertEqual(applied, 0)

    # ------------------------------------------------------------------
    # Symbol resolution
    # ------------------------------------------------------------------
    def test_strong_definition_overrides_weak_everywhere(self) -> None:
        a = self.write_object(
            "weak_a.o",
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("weakfn", ".text", 0, 8, f.STB_WEAK, f.STT_FUNC)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "weakfn")],
        )
        b = self.write_object(
            "weak_b.o",
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("weakfn", ".text", 0, 8, f.STB_GLOBAL, f.STT_FUNC)],
        )
        result = self.invoke("link", "-o", "weak.bin", "--map", "weak.map", "--base", "0x500000", a, b)
        self.assert_success(result)
        image = (self.directory / "weak.bin").read_bytes()
        _, symbols, applied = self.read_map(self.directory / "weak.map")
        self.assertEqual(applied, 1)
        self.assertEqual(symbols["weakfn"][0], 0x500008)
        self.assertTrue(symbols["weakfn"][2].endswith("weak_b.o"))
        self.assertEqual(struct.unpack_from("<Q", image, 0)[0], 0x500008)

    def test_undefined_weak_symbol_resolves_to_zero(self) -> None:
        obj = self.write_object(
            "weak-undef.o",
            sections=[f.text(b"\0" * 16)],
            symbols=[f.SymbolSpec("missing", None, 0, 0, f.STB_WEAK, f.STT_FUNC)],
            relocs=[
                f.RelocSpec(".text", 0, f.R_X86_64_64, "missing"),
                f.RelocSpec(".text", 8, f.R_X86_64_PC32, "missing", -4),
            ],
        )
        result = self.invoke("link", "-o", "weak-undef.bin", "--base", "0x400000", obj)
        self.assert_success(result)
        image = (self.directory / "weak-undef.bin").read_bytes()
        self.assertEqual(struct.unpack_from("<Q", image, 0)[0], 0)
        self.assertEqual(struct.unpack_from("<i", image, 8)[0], -0x40000C)

    def test_unresolved_strong_symbol_fails(self) -> None:
        obj = self.write_object(
            "unresolved.o",
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("missing")],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "missing")],
        )
        result = self.invoke("link", "-o", "unresolved.bin", obj)
        self.assert_failure(result, "unresolved symbol 'missing'")
        self.assertFalse((self.directory / "unresolved.bin").exists())

    def test_duplicate_strong_definitions_fail(self) -> None:
        a = self.write_object(
            "dup-a.o",
            sections=[f.text(b"\x90")],
            symbols=[f.SymbolSpec("duplicate", ".text", 0, 1, f.STB_GLOBAL, f.STT_FUNC)],
        )
        b = self.write_object(
            "dup-b.o",
            sections=[f.text(b"\x90")],
            symbols=[f.SymbolSpec("duplicate", ".text", 0, 1, f.STB_GLOBAL, f.STT_FUNC)],
        )
        result = self.invoke("link", "-o", "dup.bin", a, b)
        self.assert_failure(result, "duplicate strong definition of symbol 'duplicate'")

    def test_duplicate_weak_definitions_keep_first(self) -> None:
        a = self.write_object(
            "weak-dup-a.o",
            sections=[f.text(b"\x90")],
            symbols=[f.SymbolSpec("weakdup", ".text", 0, 1, f.STB_WEAK, f.STT_FUNC)],
        )
        b = self.write_object(
            "weak-dup-b.o",
            sections=[f.text(b"\x90")],
            symbols=[f.SymbolSpec("weakdup", ".text", 0, 1, f.STB_WEAK, f.STT_FUNC)],
        )
        result = self.invoke("link", "-o", "weak-dup.bin", "--map", "weak-dup.map", a, b)
        self.assert_success(result)
        _, symbols, _ = self.read_map(self.directory / "weak-dup.map")
        self.assertEqual(symbols["weakdup"][0], 0x400000)
        self.assertTrue(symbols["weakdup"][2].endswith("weak-dup-a.o"))

    # ------------------------------------------------------------------
    # Layout, NOBITS, suffix sections, determinism
    # ------------------------------------------------------------------
    def test_suffix_sections_nobits_and_cross_section_relocations(self) -> None:
        obj = self.write_object(
            "suffixes.o",
            sections=[
                f.text(b"\xAA" * 8, ".text.hot"),
                f.text(b"\xBB" * 2, ".text"),
                f.rodata(b"xyz", ".rodata.str1.1"),
                f.data_section(b"\x01" * 8, ".data.rel.local"),
                f.bss(8, ".bss.zero", align=8),
            ],
            symbols=[
                f.SymbolSpec("hot", ".text.hot", 0, 8, f.STB_GLOBAL, f.STT_FUNC),
                f.SymbolSpec("message", ".rodata.str1.1", 0, 3, f.STB_GLOBAL, f.STT_OBJECT),
            ],
            relocs=[
                f.RelocSpec(".text.hot", 0, f.R_X86_64_64, ("section", ".rodata.str1.1")),
                f.RelocSpec(".data.rel.local", 0, f.R_X86_64_64, "hot"),
            ],
        )
        result = self.invoke("link", "-o", "suffixes.bin", "--map", "suffixes.map", "--base", "0x600000", obj)
        self.assert_success(result)
        image = (self.directory / "suffixes.bin").read_bytes()
        sections, _, applied = self.read_map(self.directory / "suffixes.map")

        self.assertEqual(sections[".text"], (0x600000, 0, 10, 1))
        self.assertEqual(sections[".rodata"], (0x60000A, 10, 3, 1))
        self.assertEqual(sections[".data"], (0x60000D, 13, 8, 1))
        self.assertEqual(sections[".bss"], (0x600018, 24, 8, 8))
        self.assertEqual(applied, 2)
        self.assertEqual(struct.unpack_from("<Q", image, 0)[0], 0x60000A)
        self.assertEqual(struct.unpack_from("<Q", image, 13)[0], 0x600000)
        self.assertEqual(image[24:32], b"\0" * 8)
        self.assertEqual(len(image), 32)

    def test_inter_object_alignment_adds_padding(self) -> None:
        first = self.write_object(
            "align-a.o",
            sections=[f.data_section(b"\xAA", align=1)],
        )
        second = self.write_object(
            "align-b.o",
            sections=[f.data_section(b"\x11\x22\x33\x44", align=8)],
        )
        result = self.invoke("link", "-o", "align.bin", "--map", "align.map", first, second)
        self.assert_success(result)
        image = (self.directory / "align.bin").read_bytes()
        sections, _, _ = self.read_map(self.directory / "align.map")
        self.assertEqual(sections[".data"], (0x400000, 0, 12, 8))
        self.assertEqual(image[0], 0xAA)
        self.assertEqual(image[1:8], b"\0" * 7)
        self.assertEqual(image[8:12], b"\x11\x22\x33\x44")

    def test_unaligned_base_and_zero_sized_section(self) -> None:
        obj = self.write_object(
            "base.o",
            sections=[f.text(b"", ".text", align=16), f.data_section(b"\xAA")],
        )
        result = self.invoke("link", "-o", "base.bin", "--map", "base.map", "--base", "0x400001", obj)
        self.assert_success(result)
        image = (self.directory / "base.bin").read_bytes()
        sections, _, _ = self.read_map(self.directory / "base.map")
        self.assertEqual(sections[".text"], (0x400010, 0xF, 0, 16))
        self.assertEqual(sections[".data"], (0x400010, 0xF, 1, 1))
        self.assertEqual(len(image), 16)
        self.assertEqual(image[-1], 0xAA)

    def test_map_output_is_deterministic(self) -> None:
        obj = self.write_object(
            "deterministic.o",
            sections=[f.text(b"\x90" * 4), f.data_section(b"data")],
            symbols=[
                f.SymbolSpec("zeta", ".text", 0, 1),
                f.SymbolSpec("alpha", ".text", 1, 1),
                f.SymbolSpec("beta", ".data", 0, 1),
            ],
        )
        first = self.invoke("link", "-o", "one.bin", "--map", "one.map", obj)
        second = self.invoke("link", "-o", "two.bin", "--map", "two.map", obj)
        self.assert_success(first)
        self.assert_success(second)
        self.assertEqual(
            (self.directory / "one.map").read_text(encoding="utf-8"),
            (self.directory / "two.map").read_text(encoding="utf-8"),
        )

    # ------------------------------------------------------------------
    # Relocation errors
    # ------------------------------------------------------------------
    def test_unsupported_and_overflowing_relocations(self) -> None:
        cases = [
            ("unsupported.o", f.R_X86_64_64, "ABS", 0, "unsupported relocation"),
            ("u32.o", f.R_X86_64_32, "ABS", 0x100000000, "R_X86_64_32 overflow"),
            ("s32.o", f.R_X86_64_32S, "ABS", 0x80000000, "R_X86_64_32S overflow"),
            ("pc32.o", f.R_X86_64_PC32, "ABS", 0x90000000, "R_X86_64_PC32 overflow"),
            ("u32neg.o", f.R_X86_64_32, "ABS", 0, "R_X86_64_32 overflow"),
        ]
        for name, reloc_type, section, value, message in cases:
            with self.subTest(case=name):
                if name == "unsupported.o":
                    relocs = [f.RelocSpec(".text", 0, 42, "target")]
                    symbols = [f.SymbolSpec("target", ".text", 0, 1)]
                elif name == "u32neg.o":
                    relocs = [f.RelocSpec(".text", 0, reloc_type, "target", -1)]
                    symbols = [f.SymbolSpec("target", section, value)]
                else:
                    relocs = [f.RelocSpec(".text", 0, reloc_type, "target")]
                    symbols = [f.SymbolSpec("target", section, value)]
                obj = self.write_object(
                    name,
                    sections=[f.text(b"\0" * 8)],
                    symbols=symbols,
                    relocs=relocs,
                )
                result = self.invoke("link", "-o", f"{name}.bin", obj)
                self.assert_failure(result, message)

    def test_relocation_outside_target_section_fails(self) -> None:
        obj = self.write_object(
            "outside.o",
            sections=[f.text(b"\0" * 4)],
            symbols=[f.SymbolSpec("target", ".text", 0, 1)],
            relocs=[f.RelocSpec(".text", 8, f.R_X86_64_64, "target")],
        )
        result = self.invoke("link", "-o", "outside.bin", obj)
        self.assert_failure(result, "is outside the section")

    def test_tls_and_ifunc_symbols_fail(self) -> None:
        for name, symbol_type, message in (
            ("tls.o", f.STT_TLS, "TLS symbol"),
            ("ifunc.o", f.STT_GNU_IFUNC, "GNU IFUNC symbol"),
        ):
            with self.subTest(case=name):
                obj = self.write_object(
                    name,
                    sections=[f.text(b"\0" * 8)],
                    symbols=[f.SymbolSpec("special", ".text", 0, 1, f.STB_GLOBAL, symbol_type)],
                    relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "special")],
                )
                result = self.invoke("link", "-o", f"{name}.bin", obj)
                self.assert_failure(result, message)

    def test_common_symbol_fails_with_actionable_message(self) -> None:
        unused = self.write_object(
            "common-unused.o",
            sections=[f.text(b"\x90")],
            symbols=[f.SymbolSpec("common", "COMMON", 8, 4)],
        )
        result = self.invoke("link", "-o", "common-unused.bin", unused)
        self.assert_failure(result, "common symbol 'common' is not supported; compile with -fno-common")

        obj = self.write_object(
            "common.o",
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("common", "COMMON", 8, 4)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "common")],
        )
        result = self.invoke("link", "-o", "common.bin", obj)
        self.assert_failure(result, "common symbol 'common' is not supported; compile with -fno-common")

    def test_reference_to_unselected_section_fails(self) -> None:
        obj = self.write_object(
            "custom.o",
            sections=[
                f.text(b"\0" * 8),
                f.SectionSpec(".custom", b"\x01" * 4, f.SHT_PROGBITS, f.SHF_ALLOC, 1),
            ],
            symbols=[f.SymbolSpec("custom", ".custom", 0, 4)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "custom")],
        )
        result = self.invoke("link", "-o", "custom.bin", obj)
        self.assert_failure(result, "unsupported section '.custom'")

    # ------------------------------------------------------------------
    # Invalid ELF structures
    # ------------------------------------------------------------------
    def test_invalid_or_truncated_files(self) -> None:
        good = f.build_object(sections=[f.text(b"\x90")])
        cases = [
            ("empty.o", b"", "too small"),
            ("short.o", good[:32], "too small"),
            ("magic.o", bytes([good[0] ^ 0xFF]) + good[1:], "invalid ELF magic"),
            ("class.o", good[:4] + b"\x01" + good[5:], "only ELF64"),
            ("data.o", good[:5] + b"\x02" + good[6:], "little-endian"),
            ("machine.o", f.patch_u16(good, 18, 183), "only x86-64"),
            ("type.o", f.patch_u16(good, 16, f.ET_EXEC), "expected a relocatable object"),
            ("version.o", f.patch_u32(good, 20, 99), "unsupported ELF version"),
            ("shoff.o", f.patch_u64(good, f.E_SHoff_OFFSET, len(good) + 100), "section table is outside"),
            ("shnum.o", f.patch_u16(good, f.E_SHNUM_OFFSET, 0), "extended section numbering"),
            ("shstrx.o", f.patch_u16(good, f.E_SHSTRNDX_OFFSET, f.SHN_XINDEX), "extended section-name indexing"),
            ("shstridx.o", f.patch_u16(good, f.E_SHSTRNDX_OFFSET, 999), "invalid section-name string table index"),
        ]
        for name, data, message in cases:
            with self.subTest(case=name):
                path = self.write_bytes(name, data)
                result = self.invoke("inspect", path)
                self.assert_failure(result, message)

        result = self.invoke("inspect", self.directory / "does-not-exist.o")
        self.assert_failure(result, "cannot open input")
        result = self.invoke("inspect", self.directory)
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_section_tables(self) -> None:
        good = f.build_object(
            sections=[f.text(b"\x90" * 4)],
            symbols=[f.SymbolSpec("func", ".text", 0, 4)],
        )
        cases = [
            ("shstrtype.o", f.patch_section_field(good, ".shstrtab", "type", f.SHT_PROGBITS), "section-name table is not SHT_STRTAB"),
            ("textoffset.o", f.patch_section_field(good, ".text", "offset", len(good) + 100), "extends beyond the file"),
            ("textalign.o", f.patch_section_field(good, ".text", "align", 3), "invalid alignment"),
            ("symalign.o", f.patch_section_field(good, ".symtab", "entsize", 8), "malformed symbol table"),
            ("strlink.o", f.patch_section_field(good, ".symtab", "link", 999), "invalid string table"),
        ]
        for name, data, message in cases:
            with self.subTest(case=name):
                path = self.write_bytes(name, data)
                result = self.invoke("inspect", path)
                self.assert_failure(result, message)

        group = f.build_object(
            sections=[
                f.text(b"\x90"),
                f.SectionSpec(".group", b"\0" * 4, f.SHT_GROUP, 0, 4),
            ],
            symbols=[f.SymbolSpec("func", ".text", 0, 1)],
        )
        result = self.invoke("inspect", self.write_bytes("group.o", group))
        self.assert_failure(result, "section groups/COMDAT are not supported")

        no_symtab = f.build_object(sections=[f.text(b"\x90")], include_symtab=False)
        result = self.invoke("inspect", self.write_bytes("nosymtab.o", no_symtab))
        self.assert_failure(result, "missing SHT_SYMTAB")

    def test_sht_rel_is_rejected(self) -> None:
        obj = f.build_object(
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("target", ".text", 0, 1)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "target")],
            use_rel=True,
        )
        result = self.invoke("link", "-o", "rel.bin", self.write_bytes("rel.o", obj))
        self.assert_failure(result, "SHT_REL relocations are not supported")

    def test_malformed_relocation_entries(self) -> None:
        good = f.build_object(
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("target", ".text", 0, 1)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, "target")],
        )
        cases = [
            ("relinfo.o", f.patch_section_field(good, ".rela.text", "info", 999), "target section index out of range"),
            ("relsize.o", f.patch_section_field(good, ".rela.text", "entsize", 8), "malformed RELA section"),
        ]
        for name, data, message in cases:
            with self.subTest(case=name):
                result = self.invoke("inspect", self.write_bytes(name, data))
                self.assert_failure(result, message)

        bad_symbol = f.build_object(
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("target", ".text", 0, 1)],
            relocs=[f.RelocSpec(".text", 0, f.R_X86_64_64, ("index", 999))],
        )
        result = self.invoke("inspect", self.write_bytes("badsym.o", bad_symbol))
        self.assert_failure(result, "invalid symbol index")

    @unittest.skipUnless(HAVE_PYELFTOOLS, "pyelftools is not installed")
    def test_generated_fixtures_are_valid_elf(self) -> None:
        obj = self.write_object(
            "valid-elf.o",
            sections=[
                f.text(b"\x90" * 4, ".text.hot"),
                f.data_section(b"abcd", align=4),
                f.bss(8, align=8),
            ],
            symbols=[
                f.SymbolSpec("func", ".text.hot", 0, 4, f.STB_GLOBAL, f.STT_FUNC),
                f.SymbolSpec("external"),
            ],
            relocs=[f.RelocSpec(".text.hot", 0, f.R_X86_64_PLT32, "external", -4)],
        )
        with obj.open("rb") as handle:
            elf = ELFFile(handle)
            self.assertEqual(elf.header["e_type"], "ET_REL")
            self.assertEqual(elf.header["e_machine"], "EM_X86_64")
            names = [section.name for section in elf.iter_sections()]
            self.assertIn(".text.hot", names)
            self.assertIn(".rela.text.hot", names)
            symtab = elf.get_section_by_name(".symtab")
            reloc_section = elf.get_section_by_name(".rela.text.hot")
            relocations = list(reloc_section.iter_relocations())
            self.assertEqual(len(relocations), 1)
            self.assertEqual(relocations[0]["r_info_type"], f.R_X86_64_PLT32)
            self.assertEqual(symtab.get_symbol(relocations[0]["r_info_sym"]).name, "external")
            self.assertEqual(relocations[0]["r_addend"], -4)

    def test_extended_symbol_index_is_rejected(self) -> None:
        obj = f.build_object(
            sections=[f.text(b"\0" * 8)],
            symbols=[f.SymbolSpec("target", "XINDEX", 0, 1)],
        )
        result = self.invoke("inspect", self.write_bytes("xindex.o", obj))
        self.assert_failure(result, "extended symbol section indexes are not supported")

    def test_base_address_overflow_fails(self) -> None:
        obj = self.write_object(
            "overflow-base.o",
            sections=[f.text(b"\x90")],
        )
        result = self.invoke("link", "-o", "overflow-base.bin", "--base", "0xFFFFFFFFFFFFFFFF", obj)
        self.assert_failure(result, "overflow")


def main() -> int:
    global BINARY
    parser = argparse.ArgumentParser(description="Run ELF64 mini linker tests")
    parser.add_argument("binary", help="path to the elf64-mini executable")
    args = parser.parse_args()
    BINARY = Path(args.binary).resolve()
    if not BINARY.is_file():
        print(f"error: binary not found: {BINARY}", file=sys.stderr)
        return 2

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(LinkerTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
