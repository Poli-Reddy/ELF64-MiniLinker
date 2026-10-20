#pragma once

/*
 * Minimal ELF64 definitions used by the inspector/linker.
 *
 * Linux and other Unix-like systems provide <elf.h>.  Windows compilers do
 * not, so this header supplies the small, fixed subset needed by the tool.
 * Keeping the fallback here means the program can still read and write ELF
 * files when it is built on a non-ELF host.
 */

#if defined(__has_include)
#  if __has_include(<elf.h>)
#    include <elf.h>
#    define ELF64_MINI_HAVE_SYSTEM_ELF_H 1
#  endif
#endif

#ifndef ELF64_MINI_HAVE_SYSTEM_ELF_H

#include <cstdint>

#define EI_NIDENT 16
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6

#define ELFMAG "\177ELF"
#define SELFMAG 4

#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1

#define ET_REL 1

#define EM_X86_64 62

#define SHT_NULL 0
#define SHT_PROGBITS 1
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define SHT_RELA 4
#define SHT_NOBITS 8
#define SHT_REL 9
#define SHT_GROUP 17

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4

#define SHN_UNDEF 0
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_XINDEX 0xffff

#define STB_LOCAL 0
#define STB_GLOBAL 1
#define STB_WEAK 2

#define STT_NOTYPE 0
#define STT_OBJECT 1
#define STT_FUNC 2
#define STT_SECTION 3
#define STT_FILE 4
#define STT_TLS 6
#define STT_GNU_IFUNC 10

#define R_X86_64_NONE 0
#define R_X86_64_64 1
#define R_X86_64_PC32 2
#define R_X86_64_PLT32 4
#define R_X86_64_32 10
#define R_X86_64_32S 11

struct Elf64_Ehdr {
    unsigned char e_ident[EI_NIDENT];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;
    std::uint64_t e_phoff;
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    std::uint32_t sh_name;
    std::uint32_t sh_type;
    std::uint64_t sh_flags;
    std::uint64_t sh_addr;
    std::uint64_t sh_offset;
    std::uint64_t sh_size;
    std::uint32_t sh_link;
    std::uint32_t sh_info;
    std::uint64_t sh_addralign;
    std::uint64_t sh_entsize;
};

struct Elf64_Sym {
    std::uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    std::uint16_t st_shndx;
    std::uint64_t st_value;
    std::uint64_t st_size;
};

struct Elf64_Rela {
    std::uint64_t r_offset;
    std::uint64_t r_info;
    std::int64_t r_addend;
};

#define ELF64_ST_BIND(val) static_cast<unsigned>((val) >> 4)
#define ELF64_ST_TYPE(val) static_cast<unsigned>((val) & 0x0f)
#define ELF64_R_SYM(val) static_cast<std::uint32_t>((val) >> 32)
#define ELF64_R_TYPE(val) static_cast<std::uint32_t>((val) & 0xffffffffu)

#endif
