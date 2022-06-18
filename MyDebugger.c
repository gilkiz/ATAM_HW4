#include <stdio.h>
#include "elf64.h"

/********************************
 *          Our Macros          *
 ********************************/
#define ISEXE 1
#define ISNOTEXE 0
#define SHT_SYMTAB 2
#define ET_EXEC 2
#define GLOBAL "GLOBAL"
#define NOT_FOUND_IN_SYMTAB 0
#define FOUND_IN_SYMTAB_BUT_LOCAL 1
#define FOUND_IN_SYMTAB_AND_GLOBAL 2
#define FAILURE
#define SUCCESS

/********************************
 *          Functions           *
 ********************************/
int isExe(FILE* f);

int main(char* func, char* file) 
{
    Elf64_Ehdr header;
    FILE* exe = fopen(func, "r");
    fread(&header, sizeof(header), 1, exe);
    if(!isExe(&header)) {
        printf("PRF:: %s not an executable! :(\n", header.e_ident);
        fclose(exe);
        return FAILURE;
    }

    if(funcExists(func, &header) == NOT_FOUND_IN_SYMTAB) {
        printf("PRF:: %s not found!\n", func);
        fclose(exe);
        return FAILURE;
    }
    else if(funcExists(func, &header) == FOUND_IN_SYMTAB_BUT_LOCAL) {
        printf("PRF:: %s is not a global symbol! :(\n", func);
        fclose(exe);
        return FAILURE;
    }
    
    fclose(exe);
    return SUCCESS;
}

int isExe(Elf64_Ehdr* header) {
    if(header->e_type != ET_EXEC)
        return ISNOTEXE;
    return ISEXE;
}

int funcExists(char* func, Elf64_Ehdr* header) {
    Elf64_Shdr* sec_table = (Elf64_Shdr*)((char*)header + header->e_shoff);
    Elf64_Sym *symtab;
    int symbol_table_size;
    for (int i = 0; i < header->e_shnum; i++) {
        if (sec_table[i].sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym *)((char *)header + sec_table[i].sh_offset);
            symbol_table_size = sec_table[i].sh_size;
            break;
        }
    }
    
    for(int i = 0; i < symbol_table_size; i++) {
        if(strcmp(func, symtab[i].st_name)) {
            if (strcmp(ELF64_ST_BIND(symtab[i].st_info), GLOBAL))
                return FOUND_IN_SYMTAB_AND_GLOBAL;
            else
                return FOUND_IN_SYMTAB_BUT_LOCAL;
        }
    }
    return NOT_FOUND_IN_SYMTAB;
}