#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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
bool checkFunc(char* elf_file, char* func_name, Elf64_Addr* addr_func, bool* is_static, bool* found_but_not_global);
Elf64_Addr getAddress(char* func_name, Elf64_Sym *symtab, Elf64_Ehdr* header);
Elf64_Addr stage5(char* elf_file, char* func_name, Elf64_Off dynsymoff, Elf64_Xword dynsymsize, Elf64_Off dynstroff,Elf64_Off reladynoff, Elf64_Xword reladynsize);

int main(int argc, char* argv[]) 
{
    
    char* func_name = argv[1];
    char* program = argv[2];
    Elf64_Ehdr* header = (Elf64_Ehdr*)malloc(sizeof(*header));
    FILE* exe = fopen(program, "r");
    if(exe  == NULL)
        return 1;
    fread(header, sizeof(*header), 1, exe);
    if(isExe(header) == IS_NOT_EXE) {
        printf("PRF:: %s not an executable! :(\n", argv[2]);
        fclose(exe);
        free(header);
        return FAILURE;
    }

    Elf64_Addr* address;
    bool is_funciton_static, found_but_not_global;
    bool function_is_OK = checkFunc(argv[2], argv[1], address, &is_funciton_static, &found_but_not_global);

    if(function_is_OK)
    {
        //do something
    }
    else // function is not OK 
    { 
        if(found_but_not_global)
        {//found but not global
            printf("PRF:: %s is not a global symbol! :(\n", func_name);
            fclose(exe);
            free(header);
            return FAILURE;
        }
        //not found at all
        printf("PRF:: %s not found!\n", func_name);
        fclose(exe);
        free(header);
        return FAILURE;
    }
    
    // if we're here then address is initialized (allegedly)

    //starting debug



    fclose(exe);
    free(header);
    return SUCCESS;
}

int isExe(Elf64_Ehdr* header) {
    if(header->e_type != ET_EXEC)
        return IS_NOT_EXE;
    return IS_EXE;
}

bool checkFunc(char* elf_file, char* func_name, Elf64_Addr* addr_func, bool* is_static, bool* found_but_not_global)
{
    Elf64_Ehdr header;
    FILE* file = fopen(elf_file, "rb");
    FILE* file_copy = fopen(elf_file, "rb");

    bool is_func=false;
    Elf64_Shdr shstrtab, itsh;
    char shstr_name[11];
    Elf64_Off strtaboff, symoff, dynsymoff, dynstroff, reladynoff;
    Elf64_Xword symsize, dynsymsize,reladynsize;
    if(file && file_copy)
    {
        fread(&header, sizeof(header), 1, file);
        int res=fseek(file,header.e_shoff+header.e_shstrndx*header.e_shentsize,SEEK_SET);
        if(res==0)
        {
            fread(&shstrtab, sizeof(shstrtab), 1, file);
        }
        else
        {//failure
            fclose(file);
            return false;
        }
        
        res=fseek(file_copy,header.e_shoff,SEEK_SET);
        bool to_stop = false;
        for(int i=0; i<header.e_shnum; i++)
        {
            fread(&itsh, sizeof(itsh), 1, file_copy);
            if(itsh.sh_type==0x3)//SHT_STRTAB
            {
                res=fseek(file,shstrtab.sh_offset+itsh.sh_name,SEEK_SET);
                fgets(shstr_name, sizeof(shstr_name), file); //maybe without &
                if(strcmp(shstr_name, ".strtab") == 0)
                {
                    strtaboff = itsh.sh_offset;
                   // if(to_stop == true)
                    //    break;
                   // to_stop = true;
                }
                if(strcmp(shstr_name, ".dynstr")==0)
                {
                    dynstroff = itsh.sh_offset;
                }
            }
            else if(itsh.sh_type == 0x2)//SHR_SYMTAB
            {
                symoff = itsh.sh_offset;
                symsize = itsh.sh_size;
               // if(to_stop == true)
                //    break;
                //to_stop = true;
            }
            else if(itsh.sh_type == 0x0B) // SHT_DYNSYM
            {
                dynsymoff = itsh.sh_offset;
                dynsymsize = itsh.sh_size;
            }
            else if(itsh.sh_type == 0x04) // RELA
            {
                res=fseek(file,shstrtab.sh_offset+itsh.sh_name,SEEK_SET);
                fgets(shstr_name, sizeof(shstr_name), file); //maybe without &
                if(strcmp(shstr_name, ".rela.plt")==0)
                {
                    reladynoff = itsh.sh_offset;
                    reladynsize = itsh.sh_size;
                }
            }
        }

        res=fseek(file_copy,symoff,SEEK_SET);
        Elf64_Sym itsym;
        Elf64_Addr static_addr;
        char * sym_name = (char*)malloc(strlen(func_name)+1);
        bool is_global=false;
        for(int i=0; i<(symsize/sizeof(Elf64_Sym)); i++)
        {
            fread(&itsym, sizeof(itsym), 1, file_copy);
            res=fseek(file,strtaboff+itsym.st_name,SEEK_SET);
            fgets(sym_name, strlen(func_name)+2, file); //maybe without &
            if(sym_name!="" && strcmp(sym_name, func_name) == 0)
            {
                if(ELF64_ST_BIND(itsym.st_info)==1)
                {
                    static_addr = itsym.st_value; 
                   // fclose(file);
                   // fclose(file_copy);
                    //free(sym_name);
                    is_global = true;
                    break;
                }
                else
                {
                    *found_but_not_global = true;
                    return false;
                }

            }
        }

        fclose(file);
        fclose(file_copy);
        free(sym_name);
        //Elf64_Addr addr_func;
        if(is_global)
        {
            if(itsym.st_shndx == 0) //stage 5
            {
                *addr_func = stage5(elf_file,func_name,dynsymoff, dynsymsize,dynstroff,reladynoff,reladynsize);
                *is_static = false;
            }
            else //stage 6
            {
                *addr_func = static_addr;
                *is_static = true;
            }
            return true;
        }

        *found_but_not_global = false;
        return false;
    }

}


Elf64_Addr stage5(char* elf_file, char* func_name, Elf64_Off dynsymoff, Elf64_Xword dynsymsize, Elf64_Off dynstroff,Elf64_Off reladynoff, Elf64_Xword reladynsize)
{
    Elf64_Ehdr header;
    FILE* file = fopen(elf_file, "rb");
    FILE* file_copy = fopen(elf_file, "rb");

    Elf64_Sym itsym;
    fseek(file_copy,dynsymoff,SEEK_SET);
    char * sym_name = (char*)malloc(strlen(func_name)+1);
    int index_dynsym_tab = -1;

    for(int i=0; i<(dynsymsize/sizeof(Elf64_Sym)); i++)
    {
        fread(&itsym, sizeof(itsym), 1, file_copy);
        fseek(file,dynstroff+itsym.st_name,SEEK_SET);
        fgets(sym_name, strlen(func_name)+2, file); //maybe without &
        if(sym_name!="" && strcmp(sym_name, func_name) == 0)
        {
            index_dynsym_tab = i;
            break;
        }
    }

    Elf64_Rela itrela;

    if(index_dynsym_tab!=-1)
    {
        //look in real plt : find sym name and take offset
        fseek(file_copy,reladynoff,SEEK_SET);
        for(int i=0; i<(reladynsize/sizeof(Elf64_Rela)); i++)
        {
            fread(&itrela, sizeof(itrela), 1, file_copy);
            long a =  ELF64_R_SYM(itrela.r_info);
            if(ELF64_R_SYM(itrela.r_info) == index_dynsym_tab)
            {
                free(sym_name);
                fclose(file);
                fclose(file_copy);
                return itrela.r_offset;
            }
        }
    }

    free(sym_name);
    fclose(file);
    fclose(file_copy);
    return -1;
}

/*
int funcExists(char* func_name, Elf64_Ehdr* header,FILE* exe, Elf64_Addr* address) {
    Elf64_Shdr* sec_table = (Elf64_Shdr*)malloc(sizeof(*sec_table));
    // sec_table = (Elf64_Shdr*)((char*)header + header->e_shoff);
    fseek(exe, header->e_shoff, SEEK_SET);
    fread(sec_table, sizeof(*sec_table), 1, exe);
    // fread(header, sizeof(*header), 1, exe);

    Elf64_Sym *symtab = (Elf64_Sym*)malloc(sizeof(*symtab));

    int symbol_table_size;
    int not_found = 1;
    int entry_num;
    for (int i = 0; i < header->e_shnum; i++) {
        if ((sec_table + i*sec_table->sh_entsize)->sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym *)((char *)header + sec_table[i].sh_offset);
            symbol_table_size = sec_table[i].sh_size;
            not_found = 0;
            break;
        }

        if(sec_table->sh_type == SHT_SYMTAB) {
            fread(symtab, sizeof(*symtab), 1, exe);
            symbol_table_size = symtab->st_size;
            not_found = 0;
            entry_num = symtab->st_name;
            break;
        }

        fread(sec_table, sizeof(*sec_table), 1, exe);
    }

    if(not_found) {
        return NOT_FOUND_IN_SYMTAB;
    }

    Elf64_Shdr* strtab = (Elf64_Shdr*)malloc(sizeof(*strtab));
    fseek(exe, header->e_shstrndx, SEEK_SET);
    fseek(exe, entry_num*sizeof(char), SEEK_CUR);
    fread(strtab, sizeof(*strtab), 1, exe);

    //fseek(exe, strtab->sh_size, SEEK_SET);
    // for(int i = 0; i < symbol_table_size; i++) {
    //     char* strname = (char*)malloc(sizeof(strtab->sh_entsize));
    //     fseek(exe, strtab->sh_entsize, SEEK_CUR);
    //     fread(strname, sizeof(*strname), 1, exe);

    char* strname = (char*)malloc(sizeof(strtab->sh_entsize));
    fread(strname, sizeof(*strname), 1, exe);
    if(strcmp(func_name, strname)) {
        // printf("%s, %s", func_name, strname);
        if (ELF64_ST_BIND(symtab->st_info) == GLOBAL) {
            *address = getAddress(func_name, symtab, header);
            free(strtab);
            return FOUND_IN_SYMTAB_AND_GLOBAL;
        }
        else {
            free(strtab);
            return FOUND_IN_SYMTAB_BUT_LOCAL;
        }
    }
    //}
    free(strtab);
    return NOT_FOUND_IN_SYMTAB;
}

*/

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