#include "elf_parser.h"
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

unsigned long long get_symbol_offset(const char *elf_path,
                                     const char *symbol_name) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    return 0;
  }

  int fd = open(elf_path, O_RDONLY);
  if (fd < 0) {
    return 0;
  }

  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
  if (!elf) {
    close(fd);
    return 0;
  }

  unsigned long long offset = 0;
  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;

  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    gelf_getshdr(scn, &shdr);
    if (shdr.sh_type == SHT_DYNSYM || shdr.sh_type == SHT_SYMTAB) {
      Elf_Data *data = elf_getdata(scn, NULL);
      int count = shdr.sh_size / shdr.sh_entsize;

      for (int i = 0; i < count; i++) {
        GElf_Sym sym;
        gelf_getsym(data, i, &sym);

        const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
        if (name && strcmp(name, symbol_name) == 0) {
          offset = sym.st_value;
          break;
        }
      }
    }
    if (offset)
      break;
  }

  elf_end(elf);
  close(fd);
  return offset;
}
