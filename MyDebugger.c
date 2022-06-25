#include <stdio.h>
#include "elf64.h"

/********************************
 *          Our Macros          *
 ********************************/
#define IS_EXE 1
#define IS_NOT_EXE 0
#define SHT_SYMTAB 2
#define SHT_DYNSYM 11
#define ET_EXEC 2
#define GLOBAL "GLOBAL"
#define NOT_FOUND_IN_SYMTAB 0
#define FOUND_IN_SYMTAB_BUT_LOCAL 1
#define FOUND_IN_SYMTAB_AND_GLOBAL 2
#define FAILURE 1
#define SUCCESS 0
#define UNDEFINED "UND"

/********************************
 *          Functions           *
 ********************************/
int isExe(FILE* f);
int funcExists(char* func, Elf64_Ehdr* header, Elf64_Addr* address);
Elf64_Addr* getAddress(Elf64_Sym *symtab, Elf64_Ehdr* header);

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

    Elf64_Addr* address;

    int funcExistness = funcExists(func, &header, address);
    if(funcExistness == NOT_FOUND_IN_SYMTAB) {
        printf("PRF:: %s not found!\n", func);
        fclose(exe);
        return FAILURE;
    }
    else if(funcExistness == FOUND_IN_SYMTAB_BUT_LOCAL) {
        printf("PRF:: %s is not a global symbol! :(\n", func);
        fclose(exe);
        return FAILURE;
    }
    
    // if we're here then address is initialized

    fclose(exe);
    return SUCCESS;
}

int isExe(Elf64_Ehdr* header) {
    if(header->e_type != ET_EXEC)
        return IS_NOT_EXE;
    return IS_EXE;
}

int funcExists(char* func, Elf64_Ehdr* header, Elf64_Addr* address) {
    Elf64_Shdr* sec_table = (Elf64_Shdr*)((char*)header + header->e_shoff);
    Elf64_Sym *symtab;
    int symbol_table_size;
    int not_found = 0;
    for (int i = 0; i < header->e_shnum; i++) {
        if (sec_table[i].sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym *)((char *)header + sec_table[i].sh_offset);
            symbol_table_size = sec_table[i].sh_size;
            break;
        }

        if(i ==  header->e_shnum-1)
            not_found = 1;
    }

    if(not_found)
        return NOT_FOUND_IN_SYMTAB;

    
    for(int i = 0; i < symbol_table_size; i++) {
        if(strcmp(func, symtab[i].st_name)) {
            if (strcmp(ELF64_ST_BIND(symtab[i].st_info), GLOBAL)) {
                *address = getAddress(&symtab[i], header);
                return FOUND_IN_SYMTAB_AND_GLOBAL;
            }
            else
                return FOUND_IN_SYMTAB_BUT_LOCAL;
        }
    }
    return NOT_FOUND_IN_SYMTAB;
}

Elf64_Addr* getAddress(Elf64_Sym *symtab, Elf64_Ehdr* header) {
    if(symtab->st_shndx != UNDEFINED) {
        return symtab->st_value;
    }
    else {
        Elf64_Shdr* sec_table = (Elf64_Shdr*)((char*)header + header->e_shoff);
        Elf64_Dyn *dynsym;
        int dynamic_symbol_size;

        for (int i = 0; i < header->e_shnum; i++) {
            if (sec_table[i].sh_type == SHT_DYNSYM) {
                dynsym = (Elf64_Dyn *)((char *)header + sec_table[i].sh_offset);
                dynamic_symbol_size = sec_table[i].sh_size;
                break;
            }
        }
        // now holding the dynamic symbol table

        for(int j=0; j<dynamic_symbol_size; j++)
        {
            if(dynsym[j] == symtab)
                retrun 
        }

    }
}