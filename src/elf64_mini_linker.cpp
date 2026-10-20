#include "elf64_types.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

static_assert(sizeof(Elf64_Ehdr) == 64, "unexpected Elf64_Ehdr layout");
static_assert(sizeof(Elf64_Shdr) == 64, "unexpected Elf64_Shdr layout");
static_assert(sizeof(Elf64_Sym) == 24, "unexpected Elf64_Sym layout");
static_assert(sizeof(Elf64_Rela) == 24, "unexpected Elf64_Rela layout");

namespace {

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

using Bytes = std::vector<std::uint8_t>;

constexpr std::array<const char*, 4> kOutputSectionNames = {".text", ".rodata", ".data", ".bss"};

bool isPowerOfTwo(std::uint64_t value) {
    return value != 0 && (value & (value - 1)) == 0;
}

std::uint64_t alignUp(std::uint64_t value, std::uint64_t alignment) {
    if (alignment <= 1) return value;
    std::uint64_t remainder = value % alignment;
    if (remainder == 0) return value;
    std::uint64_t increase = alignment - remainder;
    if (value > std::numeric_limits<std::uint64_t>::max() - increase) throw Error("alignment overflow");
    return value + increase;
}

// True when a 64-bit value fits in a target size type.  Keeping the size type
// as a template parameter lets the compiler discard the unreachable branch,
// so strict warning sets do not flag an always-true comparison on 64-bit hosts.
template <typename SizeType>
bool fitsInSizeTypeAs(std::uint64_t value) {
    if constexpr (sizeof(SizeType) >= sizeof(std::uint64_t)) {
        (void)value;
        return true;
    } else {
        return value <= static_cast<std::uint64_t>(std::numeric_limits<SizeType>::max());
    }
}

bool fitsInSizeType(std::uint64_t value) {
    return fitsInSizeTypeAs<std::size_t>(value);
}

std::string hexString(std::uint64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << value;
    return out.str();
}

template <typename T>
T readPod(const Bytes& bytes, std::uint64_t offset, const std::string& what) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - static_cast<std::size_t>(offset))
        throw Error("truncated ELF while reading " + what);
    T value{};
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

void writeLittle(Bytes& output, std::uint64_t offset, std::uint64_t value, unsigned width) {
    if (offset > output.size() || width > output.size() - static_cast<std::size_t>(offset))
        throw Error("relocation write extends beyond output section");
    for (unsigned i = 0; i < width; ++i)
        output[static_cast<std::size_t>(offset) + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xffU);
}

std::string readString(const Bytes& table, std::uint64_t offset, const std::string& what) {
    if (offset >= table.size()) throw Error("invalid string-table offset for " + what);
    std::size_t end = static_cast<std::size_t>(offset);
    while (end < table.size() && table[end] != 0) ++end;
    if (end == table.size()) throw Error("unterminated string in " + what);
    return std::string(reinterpret_cast<const char*>(table.data() + offset), end - static_cast<std::size_t>(offset));
}

Bytes loadBytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw Error("cannot open input: " + path);
    file.seekg(0, std::ios::end);
    const std::streamoff length = file.tellg();
    if (length < 0) throw Error("cannot determine size of " + path);
    file.seekg(0);
    Bytes bytes(static_cast<std::size_t>(length));
    if (!bytes.empty() && !file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        throw Error("failed reading " + path);
    return bytes;
}

void saveBytes(const std::string& path, const Bytes& bytes) {
    std::ofstream file(path, std::ios::binary);
    if (!file) throw Error("cannot write " + path);
    if (!bytes.empty()) file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) throw Error("failed writing " + path);
}

void saveText(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) throw Error("cannot write " + path);
    file << content;
    if (!file) throw Error("failed writing " + path);
}

struct Section {
    Elf64_Shdr header{};
    std::string name;
    Bytes content;
};

struct Symbol {
    Elf64_Sym header{};
    std::string name;
    std::size_t index = 0;
};

struct Relocation {
    std::size_t sectionIndex = 0;
    Elf64_Rela rela{};
    std::string targetName;
};

struct Object {
    std::string path;
    Bytes bytes;
    Elf64_Ehdr header{};
    std::vector<Section> sections;
    std::vector<Symbol> symbols;
    std::size_t symtabIndex = SIZE_MAX;
    std::vector<Relocation> relocations;
    // Input section index -> offset inside its merged output section.
    // UINT64_MAX means the section is not part of the output.
    std::vector<std::uint64_t> contributionOffset;
};

std::optional<std::size_t> outputSectionIndex(std::string_view name) {
    for (std::size_t i = 0; i < kOutputSectionNames.size(); ++i) {
        std::string_view base(kOutputSectionNames[i]);
        if (name == base) return i;
        if (name.size() > base.size() && name.substr(0, base.size()) == base && name[base.size()] == '.') return i;
    }
    return std::nullopt;
}

bool isSelectedSection(const Section& section) {
    return (section.header.sh_flags & SHF_ALLOC) != 0 && outputSectionIndex(section.name).has_value();
}

Object parseObject(const std::string& path) {
    Object object;
    object.path = path;
    object.bytes = loadBytes(path);

    if (object.bytes.size() < sizeof(Elf64_Ehdr)) throw Error(path + ": file is too small to be ELF64");
    object.header = readPod<Elf64_Ehdr>(object.bytes, 0, "ELF header");
    const Elf64_Ehdr& header = object.header;

    if (std::memcmp(header.e_ident, ELFMAG, SELFMAG) != 0) throw Error(path + ": invalid ELF magic");
    if (header.e_ident[EI_CLASS] != ELFCLASS64) throw Error(path + ": only ELF64 is supported");
    if (header.e_ident[EI_DATA] != ELFDATA2LSB) throw Error(path + ": only little-endian ELF is supported");
    if (header.e_version != EV_CURRENT) throw Error(path + ": unsupported ELF version");
    if (header.e_machine != EM_X86_64) throw Error(path + ": only x86-64 ELF objects are supported");
    if (header.e_type != ET_REL) throw Error(path + ": expected a relocatable object (ET_REL)");
    if (header.e_ehsize < sizeof(Elf64_Ehdr)) throw Error(path + ": invalid ELF header size");
    if (header.e_shnum == 0) throw Error(path + ": extended section numbering is not supported");
    if (header.e_shstrndx == SHN_XINDEX) throw Error(path + ": extended section-name indexing is not supported");
    if (header.e_shentsize < sizeof(Elf64_Shdr)) throw Error(path + ": unsupported or missing section table");
    if (header.e_shoff < sizeof(Elf64_Ehdr) || header.e_shoff > object.bytes.size() ||
        static_cast<std::uint64_t>(header.e_shnum) * header.e_shentsize > object.bytes.size() - header.e_shoff)
        throw Error(path + ": section table is outside the file");

    std::vector<Elf64_Shdr> headers;
    headers.reserve(header.e_shnum);
    for (std::size_t i = 0; i < header.e_shnum; ++i)
        headers.push_back(readPod<Elf64_Shdr>(object.bytes, header.e_shoff + i * header.e_shentsize, "section header"));

    if (header.e_shstrndx >= headers.size()) throw Error(path + ": invalid section-name string table index");
    const Elf64_Shdr& shstrHeader = headers[header.e_shstrndx];
    if (shstrHeader.sh_type != SHT_STRTAB) throw Error(path + ": section-name table is not SHT_STRTAB");
    if (shstrHeader.sh_offset > object.bytes.size() || shstrHeader.sh_size > object.bytes.size() - shstrHeader.sh_offset)
        throw Error(path + ": invalid section-name string table");
    const Bytes shstr(object.bytes.begin() + static_cast<std::ptrdiff_t>(shstrHeader.sh_offset),
                      object.bytes.begin() + static_cast<std::ptrdiff_t>(shstrHeader.sh_offset + shstrHeader.sh_size));

    object.sections.reserve(headers.size());
    for (std::size_t i = 0; i < headers.size(); ++i) {
        Section section;
        section.header = headers[i];
        section.name = readString(shstr, section.header.sh_name, "section name");
        if (section.header.sh_addralign != 0 && !isPowerOfTwo(section.header.sh_addralign))
            throw Error(path + ": section '" + section.name + "' has invalid alignment");
        if (section.header.sh_type == SHT_GROUP)
            throw Error(path + ": section groups/COMDAT are not supported (section '" + section.name + "')");
        if (section.header.sh_type != SHT_NOBITS) {
            if (section.header.sh_offset > object.bytes.size() ||
                section.header.sh_size > object.bytes.size() - section.header.sh_offset)
                throw Error(path + ": section '" + section.name + "' extends beyond the file");
            if (!fitsInSizeType(section.header.sh_size))
                throw Error(path + ": section '" + section.name + "' is too large for this build");
            section.content.assign(object.bytes.begin() + static_cast<std::ptrdiff_t>(section.header.sh_offset),
                                   object.bytes.begin() + static_cast<std::ptrdiff_t>(section.header.sh_offset + section.header.sh_size));
        }
        object.sections.push_back(std::move(section));
    }

    for (std::size_t i = 0; i < object.sections.size(); ++i) {
        if (object.sections[i].header.sh_type != SHT_SYMTAB) continue;
        if (object.symtabIndex != SIZE_MAX) throw Error(path + ": multiple symbol tables are not supported");
        object.symtabIndex = i;
        const Elf64_Shdr& sh = object.sections[i].header;
        if (sh.sh_link >= object.sections.size()) throw Error(path + ": symbol table points to an invalid string table");
        const Section& stringTable = object.sections[sh.sh_link];
        if (stringTable.header.sh_type != SHT_STRTAB)
            throw Error(path + ": symbol table does not reference a SHT_STRTAB section");
        if (sh.sh_entsize < sizeof(Elf64_Sym) || sh.sh_entsize == 0 || sh.sh_size % sh.sh_entsize != 0)
            throw Error(path + ": malformed symbol table");
        if (sh.sh_size == 0) throw Error(path + ": empty symbol table");
        for (std::uint64_t offset = 0; offset < sh.sh_size; offset += sh.sh_entsize) {
            Symbol symbol;
            symbol.header = readPod<Elf64_Sym>(object.bytes, sh.sh_offset + offset, "symbol table entry");
            if (symbol.header.st_shndx == SHN_XINDEX)
                throw Error(path + ": extended symbol section indexes are not supported");
            symbol.index = object.symbols.size();
            symbol.name = symbol.header.st_name == 0 ? "" : readString(stringTable.content, symbol.header.st_name, "symbol name");
            object.symbols.push_back(std::move(symbol));
        }
    }
    if (object.symtabIndex == SIZE_MAX)
        throw Error(path + ": missing SHT_SYMTAB; compile with a normal relocatable-object command");

    for (std::size_t i = 0; i < object.sections.size(); ++i) {
        const Section& section = object.sections[i];
        if (section.header.sh_type != SHT_RELA && section.header.sh_type != SHT_REL) continue;
        if (section.header.sh_info >= object.sections.size())
            throw Error(path + ": relocation target section index out of range");
        if (isSelectedSection(object.sections[section.header.sh_info]) && section.header.sh_type == SHT_REL)
            throw Error(path + ": SHT_REL relocations are not supported; only SHT_RELA is supported (section '" + section.name + "')");
        if (section.header.sh_type != SHT_RELA) continue;
        if (section.header.sh_link != object.symtabIndex)
            throw Error(path + ": relocation section '" + section.name + "' references an unsupported symbol table");
        if (section.header.sh_entsize < sizeof(Elf64_Rela) || section.header.sh_size % section.header.sh_entsize != 0)
            throw Error(path + ": malformed RELA section '" + section.name + "'");
        for (std::uint64_t offset = 0; offset < section.header.sh_size; offset += section.header.sh_entsize) {
            Relocation relocation;
            relocation.sectionIndex = section.header.sh_info;
            relocation.targetName = object.sections[relocation.sectionIndex].name;
            relocation.rela = readPod<Elf64_Rela>(object.bytes, section.header.sh_offset + offset, "RELA entry");
            const std::size_t symbolIndex = ELF64_R_SYM(relocation.rela.r_info);
            if (symbolIndex >= object.symbols.size())
                throw Error(path + ": relocation in section '" + relocation.targetName + "' has an invalid symbol index");
            object.relocations.push_back(relocation);
        }
    }

    object.contributionOffset.assign(object.sections.size(), UINT64_MAX);
    return object;
}

struct OutputSection {
    std::string name;
    std::uint64_t alignment = 1;
    std::uint64_t address = 0;
    std::uint64_t fileOffset = 0;
    Bytes data;
    bool present = false;
};

struct Definition {
    std::size_t objectIndex;
    std::size_t symbolIndex;
    unsigned binding;
};

std::string relocName(std::uint32_t type) {
    switch (type) {
        case R_X86_64_NONE: return "R_X86_64_NONE";
        case R_X86_64_64: return "R_X86_64_64";
        case R_X86_64_PC32: return "R_X86_64_PC32";
        case R_X86_64_PLT32: return "R_X86_64_PLT32";
        case R_X86_64_32: return "R_X86_64_32";
        case R_X86_64_32S: return "R_X86_64_32S";
        default: return "UNKNOWN_R_X86_64(" + std::to_string(type) + ")";
    }
}

std::string displaySymbolName(const Symbol& symbol) {
    return symbol.name.empty() ? "<anonymous>" : symbol.name;
}

struct SignedMagnitude {
    bool negative = false;
    std::uint64_t magnitude = 0;
};

bool addSigned(std::uint64_t value, std::int64_t addend, SignedMagnitude& result) {
    if (addend >= 0) {
        const std::uint64_t positive = static_cast<std::uint64_t>(addend);
        if (value > std::numeric_limits<std::uint64_t>::max() - positive) return false;
        result = {false, value + positive};
        return true;
    }
    const std::uint64_t magnitude = static_cast<std::uint64_t>(-(addend + 1)) + 1;
    if (value >= magnitude) result = {false, value - magnitude};
    else result = {true, magnitude - value};
    return true;
}

std::uint64_t placeSection(std::uint64_t baseAddress, std::uint64_t cursor, std::uint64_t alignment) {
    if (baseAddress > std::numeric_limits<std::uint64_t>::max() - cursor)
        throw Error("base address plus image size overflows 64 bits");
    const std::uint64_t absolute = alignUp(baseAddress + cursor, alignment);
    return absolute - baseAddress;
}

struct LinkResult {
    Bytes image;
    std::string map;
    std::size_t applied = 0;
};

LinkResult linkObjects(std::vector<Object>& objects, std::uint64_t baseAddress) {
    std::vector<OutputSection> output;
    output.reserve(kOutputSectionNames.size());
    for (const char* name : kOutputSectionNames) {
        OutputSection section;
        section.name = name;
        output.push_back(std::move(section));
    }

    for (std::size_t objectIndex = 0; objectIndex < objects.size(); ++objectIndex) {
        Object& object = objects[objectIndex];
        for (std::size_t sectionIndex = 0; sectionIndex < object.sections.size(); ++sectionIndex) {
            const Section& section = object.sections[sectionIndex];
            if ((section.header.sh_flags & SHF_ALLOC) == 0) continue;
            const std::optional<std::size_t> index = outputSectionIndex(section.name);
            if (!index.has_value()) continue;

            OutputSection& target = output[*index];
            const std::uint64_t alignment = section.header.sh_addralign == 0 ? 1 : section.header.sh_addralign;
            const std::uint64_t offset = alignUp(static_cast<std::uint64_t>(target.data.size()), alignment);
            if (!fitsInSizeType(offset)) throw Error("section too large");
            target.data.resize(static_cast<std::size_t>(offset), 0);
            object.contributionOffset[sectionIndex] = offset;

            const std::uint64_t size = section.header.sh_size;
            if (size > std::numeric_limits<std::size_t>::max() - target.data.size()) throw Error("section size overflow");
            if (section.header.sh_type == SHT_NOBITS) {
                target.data.resize(target.data.size() + static_cast<std::size_t>(size), 0);
            } else {
                target.data.insert(target.data.end(), section.content.begin(), section.content.end());
            }
            target.alignment = std::max(target.alignment, alignment);
            target.present = true;
        }
    }

    std::uint64_t cursor = 0;
    for (OutputSection& section : output) {
        if (!section.present) continue;
        const std::uint64_t placed = placeSection(baseAddress, cursor, section.alignment);
        if (!fitsInSizeType(placed)) throw Error("output image too large");
        section.fileOffset = placed;
        section.address = baseAddress + placed;
        if (section.data.size() > std::numeric_limits<std::uint64_t>::max() - placed)
            throw Error("output image size overflow");
        cursor = placed + static_cast<std::uint64_t>(section.data.size());
        if (baseAddress > std::numeric_limits<std::uint64_t>::max() - cursor)
            throw Error("base address plus image size overflows 64 bits");
    }

    std::map<std::string, Definition> definitions;
    for (std::size_t objectIndex = 0; objectIndex < objects.size(); ++objectIndex) {
        const Object& object = objects[objectIndex];
        for (const Symbol& symbol : object.symbols) {
            const unsigned binding = ELF64_ST_BIND(symbol.header.st_info);
            if (symbol.name.empty() || binding == STB_LOCAL || symbol.header.st_shndx == SHN_UNDEF) continue;
            if (symbol.header.st_shndx == SHN_COMMON)
                throw Error(object.path + ": common symbol '" + symbol.name +
                            "' is not supported; compile with -fno-common");
            const bool hasAddress = symbol.header.st_shndx == SHN_ABS ||
                (symbol.header.st_shndx < object.sections.size() &&
                 object.contributionOffset[symbol.header.st_shndx] != UINT64_MAX);
            if (!hasAddress) continue;

            const auto inserted = definitions.emplace(symbol.name, Definition{objectIndex, symbol.index, binding});
            if (inserted.second) continue;
            Definition& existing = inserted.first->second;
            const bool existingStrong = existing.binding != STB_WEAK;
            const bool newStrong = binding != STB_WEAK;
            if (existingStrong && newStrong) {
                throw Error("duplicate strong definition of symbol '" + symbol.name + "' in " +
                            objects[existing.objectIndex].path + " and " + object.path);
            }
            if (!existingStrong && newStrong) existing = {objectIndex, symbol.index, binding};
        }
    }

    auto sectionAddress = [&](std::size_t objectIndex, std::size_t sectionIndex) -> std::uint64_t {
        const Object& object = objects.at(objectIndex);
        if (sectionIndex >= object.sections.size()) throw Error(object.path + ": invalid section index");
        const Section& section = object.sections[sectionIndex];
        const std::uint64_t offset = object.contributionOffset[sectionIndex];
        if (offset == UINT64_MAX)
            throw Error(object.path + ": relocation or symbol refers to unsupported section '" + section.name + "'");
        const std::optional<std::size_t> index = outputSectionIndex(section.name);
        if (!index.has_value() || !output[*index].present) throw Error(object.path + ": internal section mapping error");
        return output[*index].address + offset;
    };

    auto symbolInSection = [&](std::size_t objectIndex, std::size_t sectionIndex, const Symbol& symbol) -> std::uint64_t {
        const Section& section = objects.at(objectIndex).sections.at(sectionIndex);
        if (symbol.header.st_value > section.header.sh_size)
            throw Error(objects.at(objectIndex).path + ": symbol '" + displaySymbolName(symbol) +
                        "' points outside section '" + section.name + "'");
        const std::uint64_t base = sectionAddress(objectIndex, sectionIndex);
        if (base > std::numeric_limits<std::uint64_t>::max() - symbol.header.st_value)
            throw Error("symbol address overflow for '" + displaySymbolName(symbol) + "'");
        return base + symbol.header.st_value;
    };

    auto definitionAddress = [&](const Definition& definition) -> std::uint64_t {
        const Object& object = objects.at(definition.objectIndex);
        const Symbol& symbol = object.symbols.at(definition.symbolIndex);
        if (symbol.header.st_shndx == SHN_ABS) return symbol.header.st_value;
        return symbolInSection(definition.objectIndex, symbol.header.st_shndx, symbol);
    };

    auto symbolAddress = [&](std::size_t objectIndex, std::size_t symbolIndex) -> std::uint64_t {
        const Object& object = objects.at(objectIndex);
        if (symbolIndex >= object.symbols.size())
            throw Error(object.path + ": relocation symbol index out of range");
        const Symbol& symbol = object.symbols[symbolIndex];
        const unsigned binding = ELF64_ST_BIND(symbol.header.st_info);
        const unsigned type = ELF64_ST_TYPE(symbol.header.st_info);

        if (type == STT_TLS)
            throw Error(object.path + ": TLS symbol '" + displaySymbolName(symbol) + "' is not supported");
        if (type == STT_GNU_IFUNC)
            throw Error(object.path + ": GNU IFUNC symbol '" + displaySymbolName(symbol) + "' is not supported");

        if (symbol.header.st_shndx == SHN_UNDEF) {
            if (symbol.name.empty())
                throw Error(object.path + ": unresolved anonymous symbol in relocation");
            const auto definition = definitions.find(symbol.name);
            if (definition == definitions.end()) {
                if (binding == STB_WEAK) return 0; // ELF convention: unresolved weak reference is zero.
                throw Error(object.path + ": unresolved symbol '" + symbol.name + "'");
            }
            return definitionAddress(definition->second);
        }
        if (symbol.header.st_shndx == SHN_COMMON)
            throw Error(object.path + ": common symbol '" + symbol.name +
                        "' is not supported; compile with -fno-common");
        if (symbol.header.st_shndx == SHN_XINDEX)
            throw Error(object.path + ": extended symbol section indexes are not supported");
        if (symbol.header.st_shndx == SHN_ABS) return symbol.header.st_value;
        if (symbol.header.st_shndx >= object.sections.size())
            throw Error(object.path + ": special or invalid section index for symbol '" + displaySymbolName(symbol) + "'");

        // Global and weak definitions resolve through the definition table so a
        // strong definition in another object overrides a weak one everywhere.
        if (binding != STB_LOCAL && !symbol.name.empty()) {
            const auto definition = definitions.find(symbol.name);
            if (definition != definitions.end()) return definitionAddress(definition->second);
        }
        return symbolInSection(objectIndex, symbol.header.st_shndx, symbol);
    };

    std::size_t applied = 0;
    for (std::size_t objectIndex = 0; objectIndex < objects.size(); ++objectIndex) {
        Object& object = objects[objectIndex];
        for (const Relocation& relocation : object.relocations) {
            if (relocation.sectionIndex >= object.sections.size() ||
                object.contributionOffset[relocation.sectionIndex] == UINT64_MAX)
                continue;
            const Section& target = object.sections[relocation.sectionIndex];
            const std::optional<std::size_t> outputIndex = outputSectionIndex(target.name);
            if (!outputIndex.has_value()) continue;
            OutputSection& outputSection = output[*outputIndex];

            const std::uint32_t type = ELF64_R_TYPE(relocation.rela.r_info);
            if (type == R_X86_64_NONE) continue;
            unsigned width = 0;
            if (type == R_X86_64_64) width = 8;
            else if (type == R_X86_64_PC32 || type == R_X86_64_PLT32 || type == R_X86_64_32 || type == R_X86_64_32S) width = 4;
            else
                throw Error(object.path + ": unsupported relocation " + relocName(type) + " in section '" +
                            target.name + "' at offset " + hexString(relocation.rela.r_offset));

            if (relocation.rela.r_offset > target.header.sh_size ||
                width > target.header.sh_size - relocation.rela.r_offset) {
                throw Error(object.path + ": relocation at offset " + hexString(relocation.rela.r_offset) +
                            " in section '" + target.name + "' is outside the section");
            }

            const std::size_t symbolIndex = ELF64_R_SYM(relocation.rela.r_info);
            const std::uint64_t symbolValue = symbolAddress(objectIndex, symbolIndex);
            const std::uint64_t place = outputSection.address +
                object.contributionOffset[relocation.sectionIndex] + relocation.rela.r_offset;
            const std::int64_t addend = relocation.rela.r_addend;
            const std::string symbolName = object.symbols[symbolIndex].name;
            std::uint64_t value = 0;

            if (type == R_X86_64_64) {
                value = symbolValue + static_cast<std::uint64_t>(addend);
            } else if (type == R_X86_64_PC32 || type == R_X86_64_PLT32) {
                SignedMagnitude targetValue;
                if (!addSigned(symbolValue, addend, targetValue))
                    throw Error(object.path + ": " + relocName(type) + " overflow for symbol '" + symbolName + "'");
                bool negative = false;
                std::uint64_t magnitude = 0;
                if (!targetValue.negative) {
                    if (targetValue.magnitude >= place) {
                        magnitude = targetValue.magnitude - place;
                    } else {
                        negative = true;
                        magnitude = place - targetValue.magnitude;
                    }
                } else {
                    negative = true;
                    if (targetValue.magnitude > std::numeric_limits<std::uint64_t>::max() - place)
                        throw Error(object.path + ": " + relocName(type) + " overflow for symbol '" + symbolName + "'");
                    magnitude = targetValue.magnitude + place;
                }
                constexpr std::uint64_t kMinMagnitude = 2147483648ULL; // |INT32_MIN|
                if (negative) {
                    if (magnitude > kMinMagnitude)
                        throw Error(object.path + ": " + relocName(type) + " overflow for symbol '" + symbolName + "'");
                    value = 0 - magnitude;
                } else {
                    if (magnitude > 2147483647ULL)
                        throw Error(object.path + ": " + relocName(type) + " overflow for symbol '" + symbolName + "'");
                    value = magnitude;
                }
            } else if (type == R_X86_64_32 || type == R_X86_64_32S) {
                SignedMagnitude targetValue;
                if (!addSigned(symbolValue, addend, targetValue))
                    throw Error(object.path + ": " + relocName(type) + " overflow for symbol '" + symbolName + "'");
                constexpr std::uint64_t kMinMagnitude = 2147483648ULL;
                if (type == R_X86_64_32) {
                    if (targetValue.negative || targetValue.magnitude > 0xffffffffULL)
                        throw Error(object.path + ": R_X86_64_32 overflow for symbol '" + symbolName + "'");
                    value = targetValue.magnitude;
                } else {
                    if (targetValue.negative) {
                        if (targetValue.magnitude > kMinMagnitude)
                            throw Error(object.path + ": R_X86_64_32S overflow for symbol '" + symbolName + "'");
                        value = 0 - targetValue.magnitude;
                    } else {
                        if (targetValue.magnitude > 2147483647ULL)
                            throw Error(object.path + ": R_X86_64_32S overflow for symbol '" + symbolName + "'");
                        value = targetValue.magnitude;
                    }
                }
            }

            writeLittle(outputSection.data,
                        object.contributionOffset[relocation.sectionIndex] + relocation.rela.r_offset, value, width);
            ++applied;
        }
    }

    Bytes image(static_cast<std::size_t>(cursor), 0);
    for (const OutputSection& section : output) {
        if (!section.present) continue;
        if (section.fileOffset > image.size() || section.data.size() > image.size() - static_cast<std::size_t>(section.fileOffset))
            throw Error("internal image layout error");
        if (!section.data.empty())
            std::memcpy(image.data() + static_cast<std::size_t>(section.fileOffset), section.data.data(), section.data.size());
    }

    std::ostringstream map;
    map << "ELF64 Mini Linker map\n"
        << "Base address: " << hexString(baseAddress) << "\n"
        << "Output: flat memory image, not a directly executable ELF file\n\n"
        << "Sections:\n";
    for (const OutputSection& section : output) {
        if (!section.present) continue;
        map << "  " << std::left << std::setw(10) << section.name << std::right
            << " addr=" << hexString(section.address)
            << " file_off=" << hexString(section.fileOffset)
            << " size=" << section.data.size()
            << " align=" << section.alignment << "\n";
    }

    map << "\nInput section contributions:\n";
    for (std::size_t objectIndex = 0; objectIndex < objects.size(); ++objectIndex) {
        const Object& object = objects[objectIndex];
        for (std::size_t sectionIndex = 0; sectionIndex < object.sections.size(); ++sectionIndex) {
            const std::uint64_t offset = object.contributionOffset[sectionIndex];
            if (offset == UINT64_MAX) continue;
            const auto outputIndex = outputSectionIndex(object.sections[sectionIndex].name);
            if (!outputIndex.has_value()) continue;
            map << "  " << object.path << " [" << sectionIndex << "] " << object.sections[sectionIndex].name
                << " -> " << output[*outputIndex].name << "+" << hexString(offset)
                << " size=" << object.sections[sectionIndex].header.sh_size << "\n";
        }
    }

    map << "\nGlobal and weak definitions:\n";
    if (definitions.empty()) map << "  (none)\n";
    for (const auto& entry : definitions) {
        const Definition& definition = entry.second;
        const Object& object = objects[definition.objectIndex];
        map << "  " << hexString(definitionAddress(definition)) << "  "
            << std::left << std::setw(28) << entry.first << std::right
            << (definition.binding == STB_WEAK ? "WEAK" : "GLOBAL")
            << "  (" << object.path << ")\n";
    }

    map << "\nInput objects:\n";
    for (const Object& object : objects) {
        map << "  " << object.path << "  sections=" << object.sections.size()
            << " symbols=" << object.symbols.size() << " relocations=" << object.relocations.size() << "\n";
    }
    map << "\nApplied relocations: " << applied << "\n";

    return {std::move(image), map.str(), applied};
}

std::string sectionTypeName(std::uint32_t type) {
    switch (type) {
        case SHT_NULL: return "NULL";
        case SHT_PROGBITS: return "PROGBITS";
        case SHT_SYMTAB: return "SYMTAB";
        case SHT_STRTAB: return "STRTAB";
        case SHT_RELA: return "RELA";
        case SHT_NOBITS: return "NOBITS";
        case SHT_REL: return "REL";
        case SHT_GROUP: return "GROUP";
        default: return "TYPE_" + std::to_string(type);
    }
}

std::string sectionFlagName(std::uint64_t flags) {
    std::string result;
    if (flags & SHF_ALLOC) result += 'A';
    if (flags & SHF_WRITE) result += 'W';
    if (flags & SHF_EXECINSTR) result += 'X';
    return result.empty() ? "-" : result;
}

std::string symbolBindName(unsigned binding) {
    switch (binding) {
        case STB_LOCAL: return "LOCAL";
        case STB_GLOBAL: return "GLOBAL";
        case STB_WEAK: return "WEAK";
        default: return "BIND_" + std::to_string(binding);
    }
}

std::string symbolTypeName(unsigned type) {
    switch (type) {
        case STT_NOTYPE: return "NOTYPE";
        case STT_OBJECT: return "OBJECT";
        case STT_FUNC: return "FUNC";
        case STT_SECTION: return "SECTION";
        case STT_FILE: return "FILE";
        case STT_TLS: return "TLS";
        case STT_GNU_IFUNC: return "IFUNC";
        default: return "TYPE_" + std::to_string(type);
    }
}

std::string symbolSectionName(const Object& object, const Symbol& symbol) {
    if (symbol.header.st_shndx == SHN_UNDEF) return "UND";
    if (symbol.header.st_shndx == SHN_ABS) return "ABS";
    if (symbol.header.st_shndx == SHN_COMMON) return "COMMON";
    if (symbol.header.st_shndx == SHN_XINDEX) return "XINDEX";
    if (symbol.header.st_shndx < object.sections.size()) return object.sections[symbol.header.st_shndx].name;
    return "SPECIAL_" + std::to_string(symbol.header.st_shndx);
}

void inspect(const Object& object) {
    std::cout << "File: " << object.path << "\n"
              << "ELF64 x86-64 relocatable object (ET_REL)\n"
              << "Sections: " << object.sections.size()
              << ", symbols: " << object.symbols.size()
              << ", relocations: " << object.relocations.size() << "\n\nSections:\n";
    for (std::size_t i = 0; i < object.sections.size(); ++i) {
        const Section& section = object.sections[i];
        std::cout << "  [" << std::setw(2) << i << "] " << std::left << std::setw(24) << section.name << std::right
                  << " type=" << std::left << std::setw(10) << sectionTypeName(section.header.sh_type) << std::right
                  << " flags=" << std::left << std::setw(4) << sectionFlagName(section.header.sh_flags) << std::right
                  << " size=" << section.header.sh_size
                  << " align=" << section.header.sh_addralign << "\n";
    }

    std::cout << "\nSymbols:\n";
    for (const Symbol& symbol : object.symbols) {
        std::cout << "  [" << std::setw(3) << symbol.index << "] " << std::left << std::setw(30)
                  << (symbol.name.empty() ? "<section/local>" : symbol.name) << std::right
                  << " value=" << hexString(symbol.header.st_value)
                  << " size=" << symbol.header.st_size
                  << " " << symbolBindName(ELF64_ST_BIND(symbol.header.st_info))
                  << " " << symbolTypeName(ELF64_ST_TYPE(symbol.header.st_info))
                  << " section=" << symbolSectionName(object, symbol) << "\n";
    }

    std::cout << "\nRelocations:\n";
    if (object.relocations.empty()) std::cout << "  (none)\n";
    for (const Relocation& relocation : object.relocations) {
        const std::uint32_t type = ELF64_R_TYPE(relocation.rela.r_info);
        const std::size_t symbolIndex = ELF64_R_SYM(relocation.rela.r_info);
        const std::string name = object.symbols[symbolIndex].name;
        std::cout << "  " << relocation.targetName << "+" << hexString(relocation.rela.r_offset) << "  "
                  << std::left << std::setw(22) << relocName(type) << std::right
                  << " symbol=" << (name.empty() ? "<anonymous>" : name)
                  << " addend=" << relocation.rela.r_addend << "\n";
    }
}

void printUsage(std::ostream& stream) {
    stream << "Usage:\n"
           << "  elf64-mini inspect <object.o>\n"
           << "  elf64-mini link -o <image.bin> [--map <map.txt>] [--base <addr>] <object1.o> ...\n"
           << "\nOptions:\n"
           << "  --map <path>   Write the link map here (default: <image>.map).\n"
           << "  --base <addr>  Base address of the flat image (default: 0x400000).\n"
           << "  -h, --help     Show this help.\n";
}

std::uint64_t parseAddress(const std::string& text, const std::string& option) {
    if (text.empty() || text.front() == '-' || text.front() == '+')
        throw Error("invalid " + option + " address '" + text + "'");
    std::size_t consumed = 0;
    try {
        const unsigned long long value = std::stoull(text, &consumed, 0);
        if (consumed != text.size()) throw Error("invalid " + option + " address '" + text + "'");
        return static_cast<std::uint64_t>(value);
    } catch (const std::invalid_argument&) {
        throw Error("invalid " + option + " address '" + text + "'");
    } catch (const std::out_of_range&) {
        throw Error(option + " address is out of range: '" + text + "'");
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 2) {
            printUsage(std::cerr);
            return 2;
        }
        const std::string command = argv[1];
        if (command == "-h" || command == "--help") {
            printUsage(std::cout);
            return 0;
        }
        if (command == "inspect") {
            if (argc < 3) {
                printUsage(std::cerr);
                return 2;
            }
            if (argc != 3) throw Error("inspect requires exactly one object file");
            const Object object = parseObject(argv[2]);
            inspect(object);
            return 0;
        }
        if (command != "link") {
            printUsage(std::cerr);
            throw Error("unknown command '" + command + "'");
        }

        std::string outputPath;
        std::string mapPath;
        std::uint64_t baseAddress = 0x400000;
        std::vector<std::string> inputs;
        bool endOfOptions = false;
        for (int i = 2; i < argc; ++i) {
            const std::string argument = argv[i];
            if (!endOfOptions && argument == "--") {
                endOfOptions = true;
            } else if (!endOfOptions && (argument == "-h" || argument == "--help")) {
                printUsage(std::cout);
                return 0;
            } else if (!endOfOptions && argument == "-o") {
                if (i + 1 >= argc) throw Error("-o requires an output path");
                outputPath = argv[++i];
            } else if (!endOfOptions && argument == "--map") {
                if (i + 1 >= argc) throw Error("--map requires a path");
                mapPath = argv[++i];
            } else if (!endOfOptions && argument == "--base") {
                if (i + 1 >= argc) throw Error("--base requires an address");
                baseAddress = parseAddress(argv[++i], "--base");
            } else if (!endOfOptions && !argument.empty() && argument.front() == '-') {
                throw Error("unknown or incomplete option: " + argument);
            } else {
                inputs.push_back(argument);
            }
        }
        if (outputPath.empty()) throw Error("link requires -o output.bin");
        if (inputs.empty()) throw Error("link requires at least one object file");
        if (mapPath.empty()) mapPath = outputPath + ".map";
        if (mapPath == outputPath) throw Error("output image and map paths must differ");

        std::vector<Object> objects;
        objects.reserve(inputs.size());
        for (const std::string& path : inputs) objects.push_back(parseObject(path));

        LinkResult result = linkObjects(objects, baseAddress);
        saveBytes(outputPath, result.image);
        saveText(mapPath, result.map);

        std::cout << "Linked " << objects.size() << " object(s) into flat image " << outputPath
                  << " (" << result.image.size() << " bytes).\n"
                  << "Applied relocations: " << result.applied << "\n"
                  << "Map: " << mapPath << "\n"
                  << "Note: output is a flat educational memory image, not a directly executable ELF file.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    }
}
