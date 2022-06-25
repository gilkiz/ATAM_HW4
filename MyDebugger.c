#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf64.h"

/********************************
 *          Our Macros          *
 ********************************/
#define IS_EXE 1
#define IS_NOT_EXE 0
#define SHT_SYMTAB 2
#define SHT_DYNSYM 11
#define ET_EXEC 2
#define GLOBAL 1
#define NOT_FOUND_IN_SYMTAB 0
#define FOUND_IN_SYMTAB_BUT_LOCAL 1
#define FOUND_IN_SYMTAB_AND_GLOBAL 2
#define FAILURE 1
#define SUCCESS 0
#define UNDEFINED 0 //from stackoverflow- not sure if this is right!!


/********************************
 *          Functions           *
 ********************************/
int isExe(Elf64_Ehdr* header);
int funcExists(char* func_name, Elf64_Ehdr* header,FILE* exe, Elf64_Addr* address);
Elf64_Addr getAddress(char* func_name, Elf64_Sym *symtab, Elf64_Ehdr* header);

int main(int argc, char* argv[]) 
{
    
    char* func_name = argv[1]; //maybe inddex 1
    char* program = argv[2];
    Elf64_Ehdr* header = (Elf64_Ehdr*)malloc(sizeof(*header));
    FILE* exe = fopen(program, "r");
    fread(header, sizeof(*header), 1, exe);
    if(!isExe(header)) {
        printf("PRF:: %s not an executable! :(\n", header->e_ident);
        fclose(exe);
        return FAILURE;
    }

    Elf64_Addr* address;

    int funcExistness = funcExists(func_name, header, exe, address);
    if(funcExistness == NOT_FOUND_IN_SYMTAB) {
        printf("PRF:: %s not found!\n", func_name);
        fclose(exe);
        return FAILURE;
    }
    else if(funcExistness == FOUND_IN_SYMTAB_BUT_LOCAL) {
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        fclose(exe);
        return FAILURE;
    }
    
    // if we're here then address is initialized (allegedly)

    //starting debug



    fclose(exe);
    return SUCCESS;
}

int isExe(Elf64_Ehdr* header) {
    if(header->e_type != ET_EXEC)
        return IS_NOT_EXE;
    return IS_EXE;
}

int funcExists(char* func_name, Elf64_Ehdr* header,FILE* exe, Elf64_Addr* address) {
    Elf64_Shdr* sec_table = (Elf64_Shdr*)((char*)header + header->e_shoff);
    fseek(exe, header->e_shstrndx, SEEK_SET);
    Elf64_Shdr* strtab = (Elf64_Shdr*)malloc(sizeof(Elf64_Shdr));
    fread(&strtab, sizeof(strtab), 1, exe);
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

    if(not_found) {
        return NOT_FOUND_IN_SYMTAB;
        free(strtab);
    }

    fseek(exe, strtab->sh_size, SEEK_SET);
    for(int i = 0; i < symbol_table_size; i++) {
        const char* strname = (const char*)malloc(sizeof(strtab->sh_entsize));
        fseek(exe, strtab->sh_entsize, SEEK_CUR);
        fread(&strname, sizeof(strname), 1, exe);
        if(strcmp(func_name, strname)) {
            if (ELF64_ST_BIND(symtab[i].st_info) == GLOBAL) {
                *address = getAddress(func_name, &symtab[i], header);
                free(strtab);
                return FOUND_IN_SYMTAB_AND_GLOBAL;
            }
            else {
                return FOUND_IN_SYMTAB_BUT_LOCAL;
                free(strtab);
            }
        }
    }
    free(strtab);
    return NOT_FOUND_IN_SYMTAB;
}

Elf64_Addr getAddress(char* func_name, Elf64_Sym *symtab, Elf64_Ehdr* header) {
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
            if(strcmp("dynsym[j].d_tag", func_name) == 0) //bad!!!!! 
            {
                return dynsym[j].d_un.d_ptr;
            }
        }

        //If we got here then something is wrong
        
        return 0;
        
    }
}