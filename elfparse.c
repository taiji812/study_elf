#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Open an elf file
 * mmap the file content to memory
 * parsing it...
 *
 */

struct map_em_string
{
    unsigned short em;
    char *string;
};
struct map_em_string em_maps[] = {
    {EM_X86_64, "Advanced Micro Devices X86-64"}
};

#define size_of_array(x) sizeof(x)/sizeof(x[0])

static inline char *get_em_string(unsigned short em)
{
    int i = 0 ;
    for ( ; i < size_of_array(em_maps); i++)
    {
        if(em_maps[i].em == em)
            return em_maps[i].string;
    }
    return "Unknown machine";
}

void print_elf_string(int indent, char *desc, int maxsize, char *value)
{
    int blank = maxsize-strlen(desc);
    printf("%*s%s%*s: %s\n", indent, "", desc, blank, "", value);
}

void print_elf_desc_only(int indent, char *desc, int maxsize)
{
    int blank = maxsize-strlen(desc);
    printf("%*s%s%*s: ", indent, "", desc, blank, "");
}

void print_file_header(unsigned char *elf)
{
#define MAX_DESC_SECTION_SIZE 34
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    
    if (ehdr->e_version == EV_NONE)
    {
        printf("Invalid file version\n");
        exit(0);
    }

    printf("ELF Header :\n");
    print_elf_desc_only(2, "Magic", MAX_DESC_SECTION_SIZE);
    int i = 0;
    for ( ; i<EI_NIDENT; i++)
        printf("%02x ", ehdr->e_ident[i]);
    printf("\n");

    unsigned char class = ehdr->e_ident[EI_CLASS];
    if (class < ELFCLASSNUM && class > ELFCLASSNONE)
    {
        print_elf_string(2, "Class", MAX_DESC_SECTION_SIZE, (class == ELFCLASS32)?"ELF32":"ELF64");
    }
    unsigned char data = ehdr->e_ident[EI_DATA];
    if (data > ELFDATANONE)
    {
#define DATA_VALUE_FMT  "2's complement, %s endian"
        char e_data_value[32] = {0};
        snprintf(e_data_value, sizeof(e_data_value), DATA_VALUE_FMT, 
                        data==ELFDATA2LSB?"little":"big");
        print_elf_string(2, "Data", MAX_DESC_SECTION_SIZE, e_data_value);
    }

    char *type_value = NULL;
    switch (ehdr->e_type)
    {
        case ET_NONE:  
        case ET_REL: 
            //printf("REL (relocatable file)\n");
            type_value = "REL (relocatable file)";
            break;
        case ET_EXEC:  
            //printf("EXEC (Executable file)\n");
            type_value = "EXEC (Executable file)";
            break;
        case ET_DYN: 
            //printf("DYN (Shared object file)\n");
            type_value = "DYN (Shared object file)";
            break;
        case ET_CORE:  
            //printf("CORE (Core file)\n");
            type_value = "CORE (Core file)";
            break;
        case ET_LOPROC:
        case ET_HIPROC:
        default:
            //printf("Wrong Type\n");
            type_value = "Wrong Type";
            break;
    }
    print_elf_string(2, "Type", MAX_DESC_SECTION_SIZE, type_value);

    print_elf_string(2, "Machine", MAX_DESC_SECTION_SIZE, get_em_string(ehdr->e_machine));

    char version_value[16] = {0};
    if (ehdr->e_version == EV_CURRENT)
        snprintf(version_value, sizeof(version_value), "0x%x (current)", ehdr->e_version);
    else
        snprintf(version_value, sizeof(version_value), "0x%x", ehdr->e_version);

    print_elf_string(2, "Version", MAX_DESC_SECTION_SIZE, version_value);

    unsigned char osabi = ehdr->e_ident[EI_OSABI];
    char *osabi_string = NULL;
    switch (osabi)
    {
        case ELFOSABI_NONE:
            osabi_string = "UNIX System V ABI";
            break;
        case ELFOSABI_LINUX:
            osabi_string = "Linux ABI";
            break;
        default: 
            osabi_string = "Unknown type";
            break;
    }
    print_elf_string(2, "OS/ABI", MAX_DESC_SECTION_SIZE, osabi_string);

    print_elf_desc_only(2, "ABI Version", MAX_DESC_SECTION_SIZE); 
    printf("%hhu\n", ehdr->e_ident[EI_ABIVERSION]);

    print_elf_desc_only(2, "Entry point address", MAX_DESC_SECTION_SIZE);
    printf("0x%X\n", (unsigned int)ehdr->e_entry);

    print_elf_desc_only(2, "Start of program headers", MAX_DESC_SECTION_SIZE);
    printf("%lu (bytes into file)\n", ehdr->e_phoff);

    print_elf_desc_only(2, "Start of section headers", MAX_DESC_SECTION_SIZE);
    printf("%lu (bytes into file)\n", ehdr->e_shoff);

    print_elf_desc_only(2, "Flags", MAX_DESC_SECTION_SIZE);
    printf("0x%x\n", ehdr->e_flags);

    print_elf_desc_only(2, "Size of this header", MAX_DESC_SECTION_SIZE);
    printf("%hu (bytes)\n", ehdr->e_ehsize);

    print_elf_desc_only(2, "Size of program headers", MAX_DESC_SECTION_SIZE);
    printf("%hu (bytes)\n", ehdr->e_phentsize);

    print_elf_desc_only(2, "Number of program headers", MAX_DESC_SECTION_SIZE);
    printf("%hu\n", ehdr->e_phnum);

    print_elf_desc_only(2, "Size of section headers", MAX_DESC_SECTION_SIZE);
    printf("%hu (bytes)\n", ehdr->e_shentsize);

    print_elf_desc_only(2, "Number of section headers", MAX_DESC_SECTION_SIZE);
    printf("%hu\n", ehdr->e_shnum);

    print_elf_desc_only(2, "Section header string table index", MAX_DESC_SECTION_SIZE);
    printf("%hu\n", ehdr->e_shstrndx);
}

struct map_pt_string
{
    Elf64_Word pt;
    char *string;
};
static inline char *get_pt_string(Elf64_Word pt)
{
    struct map_pt_string pt_string[] = {
        {PT_NULL   , "NULL"},
        {PT_LOAD   , "LOAD"},
        {PT_DYNAMIC, "DYNAMIC"},
        {PT_INTERP , "INTERP"},
        {PT_NOTE   , "NOTE"},
        {PT_SHLIB  , "SHLIB"},
        {PT_PHDR   , "PHDR"},
        {PT_TLS    , "TLS"},
        {PT_NUM    , "NUM"},
        {PT_LOOS   , "LOOS"},
        {PT_GNU_EH_FRAME, "GNU_EH_FRAME"},
        {PT_GNU_STACK, "GNU_STACK"},
        {PT_GNU_RELRO, "GNU_RELRO"}
    };
    int i = 0;
    for ( ; i<sizeof(pt_string)/sizeof(pt_string[0]); i++)
    {
        if (pt_string[i].pt == pt)
            return pt_string[i].string;
    }
    return "NULL";
}

#define P_FLAGS_STR_SIZE 4
char pflags_string[P_FLAGS_STR_SIZE] = {0};

static inline char* get_pflags_string(Elf64_Word pflags)
{
    memset(pflags_string, 0x00, P_FLAGS_STR_SIZE);
    pflags_string[0] = pflags&PF_R?'R':' ';
    pflags_string[1] = pflags&PF_W?'W':' ';
    pflags_string[2] = pflags&PF_X?'E':' ';

    return pflags_string;
}

void print_program_header(unsigned char *elf)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    Elf64_Phdr *phdr  = (Elf64_Phdr *)(elf+ehdr->e_phoff);
    printf("Program Headers:\n");
    printf("%*s%-15s%-19s%-19s%-19s%-19s%-19s%-6s %-8s\n",
            2,"", "Type", "Offset", "VirtAddr", "PhysAddr",
                 "FileSiz", "MemSiz", "Flags", "Align");
    int i = 0;             
    for ( ; i < ehdr->e_phnum; i++)
    {
        printf("%*s%-15s0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx %-6s %-8lx\n",
            2, "", get_pt_string(phdr[i].p_type), phdr[i].p_offset,
            phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz,
            get_pflags_string(phdr[i].p_flags), phdr[i].p_align
              );
    }
}



struct map_sht_string
{
    Elf64_Word sht;
    char *string;
};

struct map_sht_string sht_string[] = {
    {SHT_NULL	           ,"NULL"},	       
    {SHT_PROGBITS          ,"PROGBITS"},
    {SHT_SYMTAB	           ,"SYMTAB"},	
    {SHT_STRTAB	           ,"STRTAB"},	
    {SHT_RELA	           ,"RELA"},	
    {SHT_HASH	           ,"HASH"},	
    {SHT_DYNAMIC	       ,"DYNAMIC"},	
    {SHT_NOTE	           ,"NOTE"},	
    {SHT_NOBITS	           ,"NOBITS"},	
    {SHT_REL		       ,"REL"},		
    {SHT_SHLIB	           ,"SHLIB"},	
    {SHT_DYNSYM	           ,"DYNSYM"},
    {SHT_INIT_ARRAY	       ,"INIT_ARRAY"},	 
    {SHT_FINI_ARRAY	       ,"FINI_ARRAY"},	 
    {SHT_PREINIT_ARRAY     ,"PREINIT_ARRAY"},
    {SHT_GROUP             ,"GROUP"},
    {SHT_SYMTAB_SHNDX      ,"SYMTAB_SHNDX"},
    {SHT_NUM	           ,"NUM"},	
    {SHT_LOOS              ,"LOOS"},
    {SHT_GNU_ATTRIBUTES    ,"GNU_ATTRIBUTES"},
    {SHT_GNU_HASH	       ,"GNU_HASH"},	  
    {SHT_GNU_LIBLIST	   ,"GNU_LIBLIST"},   
    {SHT_CHECKSUM	       ,"CHECKSUM"},	  
    {SHT_LOSUNW	           ,"LOSUNW"},	 
    {SHT_SUNW_move         ,"SUNW_move"},
    {SHT_SUNW_COMDAT       ,"SUNW_COMDAT"}, 
    {SHT_SUNW_syminfo      ,"SUNW_syminfo"},
    {SHT_GNU_verdef	       ,"GNU_verdef"},	
    {SHT_GNU_verneed	   ,"GNU_verneed"},   
    {SHT_GNU_versym	       ,"GNU_versym"},	
};

static inline char* get_sht_string(Elf64_Word sht)
{
    int i = 0;
    for ( ; i < sizeof(sht_string)/sizeof(sht_string[0]) ;i++)
    {
        if (sht_string[i].sht == sht)
            return sht_string[i].string;
    }
    return "NULL";
}

/*
 * Key to Flags:
 *   W (write), A (alloc), X (execute), M (merge), S (strings), l (large)
 *   I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
 *   O (extra OS processing required) o (OS specific), p (processor specific)
 */
struct map_shf_string
{
	Elf64_Xword shf;
	char key;	
};

struct map_shf_string shf_string[] = {
	{SHF_WRITE	            ,'W'},	// 1
	{SHF_ALLOC	            ,'A'},	// 2
	{SHF_EXECINSTR          ,'X'},	// 4
	{SHF_MERGE	            ,'M'},	// 16
	{SHF_STRINGS	        ,'S'},	// 32
	{SHF_INFO_LINK          ,'I'},	// 64
	{SHF_LINK_ORDER         ,'L'},	// 128
	{SHF_GROUP	            ,'G'},	// 512 
	{SHF_TLS		        ,'T'},  // 1024
	{SHF_OS_NONCONFORMING   ,'O'},  // 256
	{SHF_MASKOS	            ,'o'},  // 0x0ff00000
	{SHF_MASKPROC           ,'p'},  // 0xf0000000
	{SHF_EXCLUDE            ,'E'},
//	{SHF_COMPRESSED         ,"COMPRESSED
//	{SHF_ORDERED	        ,"ORDERED	  
};

static char shflag_string[4];
static inline char *get_shf_string(Elf64_Xword shf)
{
	//TODO figure out exact string size for sh_flags
	memset(shflag_string, 0x00, 4);
	int i = 0;
	int j = 0;
	for( ; i<sizeof(shf_string)/sizeof(shf_string[0]) && j<3; i++)
	{
		if (shf_string[i].shf & shf)
		{
			shflag_string[j] = shf_string[i].key;
			j++;
		}
	}
	return shflag_string;
}

void print_section_header(unsigned char *elf)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(elf+ehdr->e_shoff);
    char *sh_str_table = &elf[shdr[ehdr->e_shstrndx].sh_offset];
    printf("Section Headers:\n");
    /*
    [Nr] Name              Type             Address           Offset
           Size              EntSize          Flags  Link  Info  Align
    [ 1] .interp           PROGBITS         0000000000400238  00000238
           000000000000001c  0000000000000000   A       0     0     1

    */
    printf("%*s[NR] %-18s %-18s %-16s %-8s %-16s %-16s %-5s %-4s %-4s %-5s\n",
            2,"", "Name", "Type", "Address", "Offset",
            "Size", "EntSize", "Flags", "Link", "Info", "Align");
    int i = 0;
    for ( ; i < ehdr->e_shnum; i++)
    {
		printf("%*s[%2d] ", 2, "", i);
        printf("%-18s ", sh_str_table+shdr[i].sh_name);
        printf("%-18s ", get_sht_string(shdr[i].sh_type));
        printf("%016lx ", shdr[i].sh_addr);
		printf("%08lx ", shdr[i].sh_offset);
		printf("%016lx ", shdr[i].sh_size);
		printf("%016lx ", shdr[i].sh_entsize);
		printf("%3s  ", get_shf_string(shdr[i].sh_flags));
		printf("%*s%2u ", 2, "", shdr[i].sh_link);
		printf("%*s%2u ", 2, "", shdr[i].sh_info);
		printf("%*s%-2u", 4,"",(unsigned int)shdr[i].sh_addralign);
		printf("\n");
   	} 
}


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <elf file> \n", argv[0]);
        exit(0);
    }

    int fd = 0;
    char *target = argv[1];
    fd = open(target, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "file open fail (%s)\n", argv[1]);
        exit(0);
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        fprintf(stderr, "file stat error\n");
        exit(0);
    }
    int size = st.st_size;

    unsigned char *elf_mem  = NULL;
    elf_mem = mmap(elf_mem, size, PROT_READ, MAP_PRIVATE, fd, 0);

    print_file_header(elf_mem);    
    print_program_header(elf_mem);
    print_section_header(elf_mem);
}
