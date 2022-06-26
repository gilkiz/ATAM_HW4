#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "elf64.h"
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

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
void our_debug_aux(pid_t child_pid, Elf64_Addr function_address, int call_counter);
pid_t run_target(const char* executble_to_run);
void run_our_debugger(pid_t child_pid, bool is_function_static, Elf64_Addr function_address);

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
        int child_pid = run_target(argv[2]);
        run_our_debugger(child_pid, is_funciton_static, *address);
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
    

    fclose(exe);
    free(header);
    return SUCCESS;
}

pid_t run_target(const char* executble_to_run)
{
    pid_t pid;
    pid = fork();
    if(pid > 0)
    {
        return pid;
    }
    else if(pid == 0)
    {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL))
        {
            perror("ptrace");
            exit(1);
        }
        execl(executble_to_run, executble_to_run, NULL);
    }
    else
    {
        perror("fork");
        exit(1);
    }
}

void print_function(struct user_regs_struct reg, int call_counter)
{
    printf("PRF:: run #%d returned with %lld\n", call_counter, reg.rax);
}

void run_our_debugger(pid_t child_pid, bool is_function_static, Elf64_Addr function_address)
{
    int wait_status;
    int call_counter = 0;
    struct user_regs_struct regs;
    printf("1");
    //find all adresses

    if(is_function_static) //STATIC
    {
        int wait_status;
        wait(&wait_status);
        our_debug_aux(child_pid, function_address,call_counter);
    }
    else //GLOBAL 
    {
        Elf64_Addr jump_to_function;
        wait(&wait_status);
        jump_to_function = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)function_address, NULL);
        long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)jump_to_function, NULL);
        long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC ;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)function_address, (void*)data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        printf("1");
        if(!WIFEXITED(wait_status))
        {
            printf("2");
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)jump_to_function, (void*)data);
            call_counter++;
            regs.rip--;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

            Elf64_Addr adress_in_top_stack = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
            long data2 = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)adress_in_top_stack,NULL);
            long data2_trap = (data2 & 0xFFFFFFFFFFFFFF00) | 0xCC ;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)adress_in_top_stack, (void*)data2_trap);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            wait(&wait_status);
            printf("3");
            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            print_function(regs,call_counter);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)adress_in_top_stack, (void*)data2);
            regs.rip--;
            ptrace(PTRACE_SETREGS, child_pid, NULL, &regs); 

            Elf64_Addr real_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void*) function_address, NULL);
            our_debug_aux(child_pid, real_address, call_counter);
        }

    }
}

void our_debug_aux(pid_t child_pid, Elf64_Addr function_address, int call_counter)
{
    int wait_status;
    struct user_regs_struct regs;
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)function_address, NULL);
    long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC ;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)function_address, (void*)data_trap);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    while(!WIFEXITED(wait_status))
    {
        call_counter++;
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rip--;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)function_address, (void*)data);
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
        
        Elf64_Addr adress_in_top_stack = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
        long data_of_caller = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)adress_in_top_stack, NULL);
        long data_of_caller_trap = (data_of_caller & 0xFFFFFFFFFFFFFF00) | 0xCC ;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)adress_in_top_stack, (void*)data_of_caller_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        print_function(regs, call_counter);

        regs.rip--;
        ptrace(PTRACE_POKETEXT, child_pid, (void*)adress_in_top_stack, (void*)data_of_caller);
        ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        ptrace(PTRACE_POKETEXT, child_pid, (void*)function_address, (void*)data_trap);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }
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
    FILE* file2 = fopen(elf_file, "rb");

    bool is_func=false;
    Elf64_Shdr shstrtab, itsh;
    char shstr_name[11];
    Elf64_Off strtab_offset, sym_offset, dynsym_offset, dynstr_offset, reladyn_offset;
    Elf64_Xword symsize, dynsymsize,reladynsize;
    if(file && file2)
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
        
        res=fseek(file2,header.e_shoff,SEEK_SET);
        bool to_stop = false;
        for(int i=0; i<header.e_shnum; i++)
        {
            fread(&itsh, sizeof(itsh), 1, file2);
            if(itsh.sh_type==0x3)//SHT_STRTAB
            {
                res=fseek(file,shstrtab.sh_offset+itsh.sh_name,SEEK_SET);
                fgets(shstr_name, sizeof(shstr_name), file); //maybe without &
                if(strcmp(shstr_name, ".strtab") == 0)
                {
                    strtab_offset = itsh.sh_offset;
                }
                if(strcmp(shstr_name, ".dynstr")==0)
                {
                    dynstr_offset = itsh.sh_offset;
                }
            }
            else if(itsh.sh_type == 2)
            {
                sym_offset = itsh.sh_offset;
                symsize = itsh.sh_size;
            }
            else if(itsh.sh_type == 11) 
            {
                dynsym_offset = itsh.sh_offset;
                dynsymsize = itsh.sh_size;
            }
            else if(itsh.sh_type == 4) 
            {
                res=fseek(file,shstrtab.sh_offset+itsh.sh_name,SEEK_SET);
                fgets(shstr_name, sizeof(shstr_name), file); //maybe without &
                if(strcmp(shstr_name, ".rela.plt")==0)
                {
                    reladyn_offset = itsh.sh_offset;
                    reladynsize = itsh.sh_size;
                }
            }
        }

        res=fseek(file2,sym_offset,SEEK_SET);
        Elf64_Sym itsym;
        Elf64_Addr static_addr;
        char * sym_name = (char*)malloc(strlen(func_name)+1);
        bool is_global=false;
        for(int i=0; i<(symsize/sizeof(Elf64_Sym)); i++)
        {
            fread(&itsym, sizeof(itsym), 1, file2);
            res=fseek(file,strtab_offset+itsym.st_name,SEEK_SET);
            fgets(sym_name, strlen(func_name)+2, file); //maybe without &
            if(sym_name!="" && strcmp(sym_name, func_name) == 0)
            {
                if(ELF64_ST_BIND(itsym.st_info)==1)
                {
                    static_addr = itsym.st_value; 
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
        fclose(file2);
        free(sym_name);
        if(is_global)
        {
            if(itsym.st_shndx == 0) //stage 5
            {
                *addr_func = stage5(elf_file,func_name,dynsym_offset, dynsymsize,dynstr_offset,reladyn_offset,reladynsize);
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