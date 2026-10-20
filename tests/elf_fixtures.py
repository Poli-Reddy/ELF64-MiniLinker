"""Small ELF64 relocatable-object generator used by the test suite.

The tests must not depend on the host compiler producing ELF files (for
example, MSVC emits COFF).  This module writes the exact ELF structures the
linker consumes, so malformed-input cases can also be tested precisely.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

# ELF constants
EI_NIDENT = 16
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

ET_REL = 1
ET_EXEC = 2

EM_X86_64 = 62

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9
SHT_GROUP = 17

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHN_UNDEF = 0
SHN_ABS = 0xFFF1
SHN_COMMON = 0xFFF2
SHN_XINDEX = 0xFFFF

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_TLS = 6
STT_GNU_IFUNC = 10

R_X86_64_NONE = 0
R_X86_64_64 = 1
R_X86_64_PC32 = 2
R_X86_64_PLT32 = 4
R_X86_64_32 = 10
R_X86_64_32S = 11

ELF_HEADER_SIZE = 64
SECTION_HEADER_SIZE = 64
SYMBOL_SIZE = 24
RELA_SIZE = 24
REL_SIZE = 16

E_SHoff_OFFSET = 40
E_SHNUM_OFFSET = 60
E_SHSTRNDX_OFFSET = 62

SHDR_FIELDS = {
    "name": 0,
    "type": 4,
    "flags": 8,
    "addr": 16,
    "offset": 24,
    "size": 32,
    "link": 40,
    "info": 44,
    "align": 48,
    "entsize": 56,
}


def align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


@dataclass
class SectionSpec:
    name: str
    data: bytes = b""
    type: int = SHT_PROGBITS
    flags: int = SHF_ALLOC
    align: int = 1
    size: Optional[int] = None
    # Filled in by build_object().
    offset: int = field(default=0, init=False)
    link: int = field(default=0, init=False)
    info: int = field(default=0, init=False)
    entsize: int = field(default=0, init=False)

    @property
    def byte_size(self) -> int:
        return len(self.data) if self.size is None else self.size


def text(data: bytes, name: str = ".text", align: int = 1) -> SectionSpec:
    return SectionSpec(name, data, SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, align)


def rodata(data: bytes, name: str = ".rodata", align: int = 1) -> SectionSpec:
    return SectionSpec(name, data, SHT_PROGBITS, SHF_ALLOC, align)


def data_section(data: bytes, name: str = ".data", align: int = 1) -> SectionSpec:
    return SectionSpec(name, data, SHT_PROGBITS, SHF_ALLOC | SHF_WRITE, align)


def bss(size: int, name: str = ".bss", align: int = 1) -> SectionSpec:
    return SectionSpec(name, b"", SHT_NOBITS, SHF_ALLOC | SHF_WRITE, align, size)


@dataclass
class SymbolSpec:
    name: str
    section: Optional[str] = None
    value: int = 0
    size: int = 0
    bind: int = STB_GLOBAL
    type: int = STT_NOTYPE


@dataclass
class RelocSpec:
    section: str
    offset: int
    type: int
    symbol: Union[str, Tuple[str, object]]
    addend: int = 0


def _string_table(names: Iterable[str]) -> Tuple[bytes, Dict[str, int]]:
    table = bytearray(b"\0")
    offsets: Dict[str, int] = {"": 0}
    for name in names:
        if not name or name in offsets:
            continue
        offsets[name] = len(table)
        table.extend(name.encode("utf-8") + b"\0")
    return bytes(table), offsets


def _section_token(section: int) -> int:
    return section & 0xFFFF


def build_object(
    sections: Optional[Sequence[SectionSpec]] = None,
    symbols: Optional[Sequence[SymbolSpec]] = None,
    relocs: Optional[Sequence[RelocSpec]] = None,
    *,
    include_symtab: bool = True,
    use_rel: bool = False,
    e_type: int = ET_REL,
    e_machine: int = EM_X86_64,
    ei_class: int = ELFCLASS64,
    ei_data: int = ELFDATA2LSB,
    e_version: int = EV_CURRENT,
) -> bytes:
    """Build a relocatable ELF64 object.

    Sections are placed in the order supplied.  Local section symbols are
    inserted automatically so relocations can refer to them with
    ("section", ".text") in RelocSpec.symbol.
    """
    sections = list(sections or [])
    symbols = list(symbols or [])
    relocs = list(relocs or [])

    names = [section.name for section in sections]
    if any(name == "" for name in names):
        raise ValueError("content section names must not be empty")
    if len(set(names)) != len(names):
        raise ValueError("duplicate section names are not supported by this fixture builder")
    if not include_symtab and (symbols or relocs):
        raise ValueError("symbols and relocations require include_symtab=True")

    # Index 0 is the mandatory SHT_NULL section.
    specs: List[SectionSpec] = [SectionSpec("", b"", SHT_NULL, 0, 0, 0)]
    specs.extend(sections)
    content_count = len(specs)
    section_index = {section.name: i for i, section in enumerate(specs) if i != 0}

    # Build the symbol table (if requested) before relocation sections.
    symbol_indices: Dict[object, int] = {}
    symtab_index: Optional[int] = None
    strtab_index: Optional[int] = None
    if include_symtab:
        symbol_entries: List[Tuple[int, int, int, int, int, int]] = [
            (0, 0, 0, 0, 0, 0)  # STN_UNDEF
        ]
        local_count = 1
        for i, section in enumerate(specs):
            if i == 0:
                continue
            symbol_indices[("section", section.name)] = len(symbol_entries)
            symbol_entries.append((0, (STB_LOCAL << 4) | STT_SECTION, 0, i, 0, 0))
            local_count += 1

        user_names: List[str] = []
        for symbol in symbols:
            if not symbol.name:
                raise ValueError("user symbols must have a name")
            if symbol.name in user_names:
                raise ValueError(f"duplicate user symbol {symbol.name!r}")
            user_names.append(symbol.name)
        strtab_data, strtab_offsets = _string_table(user_names)

        for symbol in symbols:
            if symbol.section is None or symbol.section == "UNDEF":
                shndx = SHN_UNDEF
            elif symbol.section == "ABS":
                shndx = SHN_ABS
            elif symbol.section == "COMMON":
                shndx = SHN_COMMON
            elif symbol.section == "XINDEX":
                shndx = SHN_XINDEX
            else:
                shndx = section_index[symbol.section]
            symbol_indices[symbol.name] = len(symbol_entries)
            symbol_entries.append(
                (
                    strtab_offsets[symbol.name],
                    (symbol.bind << 4) | symbol.type,
                    0,
                    _section_token(shndx),
                    symbol.value,
                    symbol.size,
                )
            )

        symtab_data = bytearray()
        for entry in symbol_entries:
            symtab_data.extend(struct.pack("<IBBHQQ", *entry))

        symtab_index = len(specs)
        specs.append(
            SectionSpec(
                ".symtab",
                bytes(symtab_data),
                SHT_SYMTAB,
                0,
                8,
                None,
            )
        )
        specs[-1].info = local_count
        specs[-1].entsize = SYMBOL_SIZE
        strtab_index = len(specs)
        specs.append(SectionSpec(".strtab", strtab_data, SHT_STRTAB, 0, 1))
        specs[-1].entsize = 0
        specs[symtab_index].link = strtab_index

    # Group relocation entries by target section and emit one section per group.
    if relocs:
        if symtab_index is None:
            raise ValueError("relocations require a symbol table")
        grouped: Dict[str, List[RelocSpec]] = {}
        for reloc in relocs:
            if reloc.section not in section_index:
                raise ValueError(f"relocation target section not found: {reloc.section}")
            grouped.setdefault(reloc.section, []).append(reloc)

        for target_name, entries in grouped.items():
            payload = bytearray()
            for reloc in entries:
                if isinstance(reloc.symbol, str):
                    if reloc.symbol not in symbol_indices:
                        raise ValueError(f"relocation symbol not found: {reloc.symbol}")
                    sym_index = symbol_indices[reloc.symbol]
                elif isinstance(reloc.symbol, tuple) and reloc.symbol[0] == "section":
                    key = ("section", reloc.symbol[1])
                    if key not in symbol_indices:
                        raise ValueError(f"section symbol not found: {reloc.symbol[1]}")
                    sym_index = symbol_indices[key]
                elif isinstance(reloc.symbol, tuple) and reloc.symbol[0] == "index":
                    sym_index = int(reloc.symbol[1])
                else:
                    raise ValueError(f"unsupported relocation symbol spec: {reloc.symbol!r}")
                info = (sym_index << 32) | (reloc.type & 0xFFFFFFFF)
                if use_rel:
                    payload.extend(struct.pack("<QQ", reloc.offset, info))
                else:
                    payload.extend(struct.pack("<QQq", reloc.offset, info, reloc.addend))
            specs.append(
                SectionSpec(
                    (".rel" if use_rel else ".rela") + target_name,
                    bytes(payload),
                    SHT_REL if use_rel else SHT_RELA,
                    0,
                    8,
                )
            )
            specs[-1].link = symtab_index
            specs[-1].info = section_index[target_name]
            specs[-1].entsize = REL_SIZE if use_rel else RELA_SIZE

    # Add the section-name table last.  Its own name must be in the table too.
    shstr_names = [spec.name for spec in specs if spec.name] + [".shstrtab"]
    shstr_data, shstr_offsets = _string_table(shstr_names)
    shstr_index = len(specs)
    specs.append(SectionSpec(".shstrtab", shstr_data, SHT_STRTAB, 0, 1))

    # Lay out file contents.  NOBITS sections occupy address space but no file
    # bytes; alignment padding is explicit so the parser sees valid offsets.
    file_data = bytearray(b"\0" * ELF_HEADER_SIZE)
    for spec in specs[1:]:
        spec.offset = align_up(len(file_data), max(1, spec.align))
        if spec.type != SHT_NOBITS:
            file_data.extend(b"\0" * (spec.offset - len(file_data)))
            file_data.extend(spec.data)

    section_header_offset = align_up(len(file_data), 8)
    file_data.extend(b"\0" * (section_header_offset - len(file_data)))
    for spec in specs:
        file_data.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                shstr_offsets.get(spec.name, 0),
                spec.type,
                spec.flags,
                0,
                spec.offset,
                spec.byte_size,
                spec.link,
                spec.info,
                spec.align,
                spec.entsize,
            )
        )

    ident = (
        b"\x7fELF"
        + bytes([ei_class, ei_data, 1, 0])
        + b"\0" * 8
    )
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        e_type,
        e_machine,
        e_version,
        0,  # e_entry
        0,  # e_phoff
        section_header_offset,
        0,  # e_flags
        ELF_HEADER_SIZE,
        0,  # e_phentsize
        0,  # e_phnum
        SECTION_HEADER_SIZE,
        len(specs),
        shstr_index,
    )
    file_data[:ELF_HEADER_SIZE] = header
    return bytes(file_data)


def read_u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def patch_u16(data: bytes, offset: int, value: int) -> bytes:
    result = bytearray(data)
    struct.pack_into("<H", result, offset, value)
    return bytes(result)


def patch_u32(data: bytes, offset: int, value: int) -> bytes:
    result = bytearray(data)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


def patch_u64(data: bytes, offset: int, value: int) -> bytes:
    result = bytearray(data)
    struct.pack_into("<Q", result, offset, value)
    return bytes(result)


def section_count(data: bytes) -> int:
    return read_u16(data, E_SHNUM_OFFSET)


def section_header_offset(data: bytes, index: int) -> int:
    return read_u64(data, E_SHoff_OFFSET) + index * SECTION_HEADER_SIZE


def section_field_offset(data: bytes, index: int, field: str) -> int:
    return section_header_offset(data, index) + SHDR_FIELDS[field]


def section_names(data: bytes) -> List[str]:
    count = section_count(data)
    shstr_index = read_u16(data, E_SHSTRNDX_OFFSET)
    shstr_header = section_header_offset(data, shstr_index)
    shstr_offset = read_u64(data, shstr_header + SHDR_FIELDS["offset"])
    shstr_size = read_u64(data, shstr_header + SHDR_FIELDS["size"])
    shstr = data[shstr_offset : shstr_offset + shstr_size]

    def read_name(offset: int) -> str:
        end = shstr.find(b"\0", offset)
        if end < 0:
            return ""
        return shstr[offset:end].decode("utf-8", "replace")

    names = []
    for index in range(count):
        name_offset = read_u32(data, section_header_offset(data, index))
        names.append(read_name(name_offset) if index != 0 else "")
    return names


def section_index(data: bytes, name: str) -> int:
    names = section_names(data)
    try:
        return names.index(name)
    except ValueError as exc:
        raise KeyError(f"section {name!r} not found; have {names!r}") from exc


def patch_section_field(data: bytes, name: str, field: str, value: int) -> bytes:
    index = section_index(data, name)
    width = 8 if field in {"flags", "addr", "offset", "size", "align", "entsize"} else 4
    offset = section_field_offset(data, index, field)
    return patch_u64(data, offset, value) if width == 8 else patch_u32(data, offset, value)
