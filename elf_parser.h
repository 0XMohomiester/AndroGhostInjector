#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

// Parses an ELF file and returns the st_value (offset) of a specific symbol
// Searches both .dynsym and .symtab tables.
// Returns 0 on failure or if symbol is not found.
unsigned long long get_symbol_offset(const char *elf_path,
                                     const char *symbol_name);

#ifdef __cplusplus
}
#endif

#endif // ELF_PARSER_H
