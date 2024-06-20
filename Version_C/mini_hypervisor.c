// Prevođenje:
//    make
// Pokretanje:
//    ./kvm_zadatak3 guest.img
//
// Koristan link: https://www.kernel.org/doc/html/latest/virt/kvm/api.html
//                https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf
//
// Zadatak: Omogućiti ispravno izvršavanje gost C programa. Potrebno je pokrenuti gosta u long modu.
//          Podržati stranice veličine 4KB i 2MB.
//
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <pthread.h>
#include "../Guest/file.h"

// #define MEM_SIZE 0x200000 // Veličina memorije će biti 2MB
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	struct kvm_run *kvm_run;
};

enum State{
    OPEN,
    CLOSE,
    READ_FD,
    READ_CNT,
    READ_OFFSET,
    READ_RET,
    WRITE_FD,
    WRITE_DATA,
    NONE
};

struct vm_file_args{
    int fd;
    char *buffer;
    int count;
    int offset;
    enum State state;
    int id;
    int *localCopies;
};

void* vm_thread(void *arg);
int handleFileOperation(struct vm *vm, struct vm_file_args *file_args);
void returnValueToGuest(struct vm* vm, struct vm_file_args *file_args);

int init_vm(struct vm *vm, size_t mem_size)
{
	struct kvm_userspace_memory_region region;
	int kvm_run_mmap_size;

	vm->kvm_fd = open("/dev/kvm", O_RDWR);
	if (vm->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

	vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = mem_size;
	region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, vm->vcpu_fd, 0);
	if (vm->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1, // Prisutan ili učitan u memoriji
		.type = 11, // Code: execute, read, accessed
		.dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
		.db = 0, // Default size - ima vrednost 0 u long modu
		.s = 1, // Code/data tip segmenta
		.l = 1, // Long mode - 1
		.g = 1, // 4KB granularnost
	};

	sregs->cs = seg;

	seg.type = 3; // Data: read, write, accessed
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static uint64_t getAndIncrementAdr(uint64_t *adr, uint32_t size)
{
    uint64_t ret = *adr;
    *adr += size;
    return ret;
}

// Omogucavanje long moda.
// Vise od long modu mozete prociati o stranicenju u glavi 5:
// https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf
// Pogledati figuru 5.1 na stranici 128.
static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs, uint32_t page_size, uint32_t mem_size)
{
	// Postavljanje 4 niva ugnjezdavanja.
	// Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB. 
	uint64_t adr = 0x1000;
    uint64_t page = 0;

    uint32_t numPages = mem_size / page_size;
    
    uint64_t pml4_addr = getAndIncrementAdr(&adr, 0x1000); // Adrese su proizvoljne.
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = getAndIncrementAdr(&adr, 0x1000);
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = getAndIncrementAdr(&adr, 0x1000);
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

    if(page_size == 0x200000) {
        // 2MB page size
	    for(int i = 0; i < numPages; i++) {
            pd[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
            page += 0x200000;
        }
    }
    else{
        // 4KB page size
        // -----------------------------------------------------
        uint64_t pt_addr;
        uint64_t *pt;

        for(int i = 0; i < numPages; i++) {
            if(i % 512 == 0) {
                pt_addr = getAndIncrementAdr(&adr, 0x1000);
	            pt = (void *)(vm->mem + pt_addr);
                pd[i / 512] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
            }
            pt[i % 512] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            page += 0x1000;
        }

        // pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
        // // PC vrednost se mapira na ovu stranicu.
        // pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        // // SP vrednost se mapira na ovu stranicu. Vrednost 0x6000 je proizvoljno tu postavljena.
        // pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER; 

        // FOR petlja služi tome da mapiramo celu memoriju sa stranicama 4KB.
        // Zašti je uslov i < 512? Odgovor: jer je memorija veličine 2MB.
        // for(int i = 0; i < 512; i++) {
        // 	pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
        // 	page += 0x1000;
        // }
        // -----------------------------------------------------
    }

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
	sregs->cr3  = pml4_addr; 
	sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
	sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging" 
	sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

	// Inicijalizacija segmenata procesora.
	setup_64bit_code_segment(sregs);
}


struct vm_thread_args {
    size_t mem_size;
    size_t page_size;
    FILE* img;
    int id;
};

int* shared_files = NULL;
int shared_files_count = 0;
char** shared_files_names = NULL;

int main(int argc, char *argv[])
{
    uint32_t MEM_SIZE;
    uint32_t PAGE_SIZE; 

	if (argc < 7) {
    	printf("The program requests 3 parameters: memory size (-m or --memory),\
                page size (-p or --page) and guest images (-g or --guest),\
                you can add additional parameter for files that are shared (-f or --file)\n");
    	return 1;
  	}

    for (int i = 1; i < 5; i += 2) {
        if(strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--memory") == 0) {
            MEM_SIZE = atoi(argv[i + 1]);
            MEM_SIZE <<= 20; //velicina u MB
        }
        else if(strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--page") == 0) {
            if (strcmp(argv[i + 1], "4KB") == 0) {
                // 4KB page size
                PAGE_SIZE = 0x1000;
            }
            else if (strcmp(argv[i + 1], "2MB") == 0) {
                // 2MB page size
                PAGE_SIZE = 0x200000;
            }
            else {
                printf("Invalid page size\n");
                return -1;
            }
        }
        else {
            printf("Invalid parameter\n");
            return -1;
        }
    }

    if(strcmp(argv[5], "-g") != 0 && strcmp(argv[5], "--guest") != 0){
        printf("Invalid parameter\n");
        return -1;
    }

    int nn = 6;
    while(nn < argc && (strcmp(argv[nn], "-f") != 0 && strcmp(argv[nn], "--file") != 0)){
        nn++;
    }

    int numImages = nn - 6;

    if(numImages == 0){
        printf("No guest images\n");
        return -1;
    }

    FILE **imgs = malloc(sizeof(FILE *) * numImages);

    for(int i = 6 ; i < nn;  i++) {
        FILE* img = fopen(argv[i], "r");
        if (img == NULL) {
            printf("Can not open binary file %s\n", argv[i]);
            for(int j = 6; j < i; j++) {
                fclose(imgs[j - 6]);
            }
            return -1;
        }
        imgs[i - 6] = img;
    }

    if(nn < argc - 1){
        shared_files = malloc(sizeof(int *) * (argc - nn - 1));
        shared_files_names = malloc(sizeof(char *) * (argc - nn - 1));
        shared_files_count = argc - nn - 1;
        for(int i = nn + 1; i < argc; i++){
            int fd = open(argv[i], O_RDWR, 0644);
            if (fd == -1) {
                for(int j = 0; j < i - nn - 1; j++) {
                    close(shared_files[j]);
                }
                perror("open");
                return -1;
            }
            shared_files[i - nn - 1] = fd;
            shared_files_names[i - nn - 1] = argv[i];
        }
    }

    pthread_t *tids = malloc(sizeof(pthread_t) * numImages);

    for(int i = 0 ; i < numImages; i++) {
        struct vm_thread_args *args = malloc(sizeof(struct vm_thread_args));
        args->mem_size = MEM_SIZE;
        args->page_size = PAGE_SIZE;
        args->img = imgs[i];
        args->id = i;

        char dir_name[50];
        sprintf(dir_name, "VM_%d", args->id);

        if(mkdir(dir_name, 0777) == -1) {
            perror("Failed to create directory");
        }

        pthread_create(&tids[i], NULL, vm_thread, args);
    }

    for(int i = 0; i < numImages; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);
    free(imgs);

    for(int i = 0; i < shared_files_count; i++){
        close(shared_files[i]);
    }

    free(shared_files);
    free(shared_files_names);

    return 0;
	
}

int getIndexSharedFile(char* name){
    for(int i = 0; i < shared_files_count; i++){
        if(strcmp(shared_files_names[i], name) == 0){
            return i;
        }
    }
    return -1;
}

int getIndexSharedFileFd(int fd){
    for(int i = 0; i < shared_files_count; i++){
        if(shared_files[i] == fd){
            return i;
        }
    }
    return -1;
}

// telo niti za vm
void* vm_thread(void *arg){
    struct vm_thread_args *args = (struct vm_thread_args *)arg;

    struct vm vm;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;

//svaka nit/VM ima svoje lokalne promenljive za fajlove
    struct vm_file_args* file_args = malloc(sizeof(struct vm_file_args));
    file_args->fd = -1;
    file_args->buffer = malloc(1024);
    file_args->count = 0;
    file_args->offset = 0;
    file_args->state = NONE;

    int *localCopies = malloc(sizeof(int) * shared_files_count);
    for(int i = 0; i < shared_files_count; i++){
        localCopies[i] = -1; //podrazumevano koristi shared dok ne uradi upis
    }

    uint32_t mem_size = args->mem_size;
    uint32_t page_size = args->page_size;
    FILE* img = args->img;
    int id = args->id;

    file_args->id = id;
    file_args->localCopies = localCopies;

    free(args);

    if (init_vm(&vm, mem_size)) {
		printf("Failed to init the VM\n");
        free(file_args->buffer);
        free(file_args);
        free(localCopies);
		return NULL;
	}

	if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
        free(file_args->buffer);
        free(file_args);
        free(localCopies);
		return NULL;
	}

	setup_long_mode(&vm, &sregs, page_size, mem_size);

    if (ioctl(vm.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
        free(file_args->buffer);
        free(file_args);
        free(localCopies);
		return NULL;
	}

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 2;
	regs.rip = 0;
	// SP raste nadole
	regs.rsp = mem_size; //da stek krece od vrha i raste nadole

	if (ioctl(vm.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
        free(file_args->buffer);
        free(file_args);
        free(localCopies);
		return NULL;
	}

	char *p = vm.mem;
  	while(feof(img) == 0) {
    	int r = fread(p, 1, 1024, img);
    	p += r;
  	}
  	fclose(img);

	while(stop == 0) {
		ret = ioctl(vm.vcpu_fd, KVM_RUN, 0);
		if (ret == -1) {
            printf("KVM_RUN failed\n");
            free(file_args->buffer);
            free(file_args);
            free(localCopies);
            return NULL;
		}

		switch (vm.kvm_run->exit_reason) {
			case KVM_EXIT_IO:
				if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0xE9) {
					char *p = (char *)vm.kvm_run;
					printf("%c", *(p + vm.kvm_run->io.data_offset));
                    fflush(stdout);
                }
                else if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0x0278) {
                    handleFileOperation(&vm, file_args);
                }
                else if(vm.kvm_run->io.direction == KVM_EXIT_IO_IN && vm.kvm_run->io.port == 0x0278) {
                    returnValueToGuest(&vm, file_args);
                }
				continue;
			case KVM_EXIT_HLT:
				printf("KVM_EXIT_HLT\n");
				stop = 1;
				break;
			case KVM_EXIT_INTERNAL_ERROR:
				printf("Internal error: suberror = 0x%x\n", vm.kvm_run->internal.suberror);
				stop = 1;
				break;
			case KVM_EXIT_SHUTDOWN:
				printf("Shutdown\n");
				stop = 1;
				break;
			default:
				printf("Exit reason: %d\n", vm.kvm_run->exit_reason);
				break;
    	}
  	}

    free(file_args->buffer);
    free(file_args);
    free(localCopies);

    return NULL;
}


void setup_directory(struct vm_file_args *file_args){
    sprintf(file_args->buffer, "VM_%d/", file_args->id);
    file_args->count = 5; //podrazumevamo id od 0 do 9
}



int handleFileOperation(struct vm* vm, struct vm_file_args *file_args){
    char *p = (char *)vm->kvm_run;

    if(file_args->state == NONE){
        uint8_t command = *(p + vm->kvm_run->io.data_offset);

        switch(command){
            case 1:
                // printf("%d: OPEN\n", file_args->id);
                file_args->state = OPEN;
                setup_directory(file_args);
                break;
            case 2:
                // printf("%d: CLOSE\n", file_args->id);
                file_args->state = CLOSE;
                break;
            case 3:
                // printf("%d: READ\n", file_args->id);
                file_args->state = READ_FD;
                break;
            case 4:
                // printf("%d: WRITE\n", file_args->id);
                file_args->state = WRITE_FD;
                break;
            default:
                break;
        }
        return 0;
    }

    

    switch (file_args->state) {
        case OPEN: { // open
            char c = *(p + vm->kvm_run->io.data_offset);
            // printf("%d: %c\n", file_args->id, c);
            file_args->buffer[file_args->count++] = c;

            if(c == '\0'){

                int index = getIndexSharedFile(file_args->buffer + 5);//preskacemo "VM_X/"

                if(index != -1 && file_args->localCopies[index] == -1){
                    file_args->fd = shared_files[index];
                }
                else if(index != -1){
                    file_args->fd = open(file_args->buffer, O_RDWR | O_CREAT, 0644);
                    if (file_args->fd == -1) {
                        perror("open");
                    }
                    file_args->localCopies[index] = file_args->fd;
                }
                else{
                    file_args->fd = open(file_args->buffer, O_RDWR | O_CREAT, 0644);
                    if (file_args->fd == -1) {
                        perror("open");
                    }
                }

                // printf("%s: %d\n", file_args->buffer,  file_args->fd);
                // outl(0x0278, fd);
                file_args->count = 0;
            }

            break;
        }
        case CLOSE: { 
            file_args->fd = *(int *)(p + vm->kvm_run->io.data_offset);
            // printf("%d: %d\n", file_args->id, file_args->fd);

            int index = getIndexSharedFileFd(file_args->fd);
            if(index == -1){
                close(file_args->fd);
            }
            else if(file_args->localCopies[index] != -1){
                //close local copy
                close(file_args->localCopies[index]);
            }

            file_args->count = 0;
            file_args->state = NONE;
            break;
        }
        case READ_FD: { // read
            file_args->fd = *(int *)(p + vm->kvm_run->io.data_offset);

            int index = getIndexSharedFileFd(file_args->fd);
            if(index != -1 && file_args->localCopies[index] != -1){
                file_args->fd = file_args->localCopies[index];
            }

            // printf("%d: %d\n", file_args->id, file_args->fd);
            file_args->state = READ_CNT;
            break;
        }
        case READ_CNT: { // read
            file_args->count = *(int *)(p + vm->kvm_run->io.data_offset);
            // printf("%d: %d\n", file_args->id, file_args->count);
            file_args->state = READ_OFFSET;
            break;
        }
        case READ_OFFSET: { // read
            file_args->offset = *(int *)(p + vm->kvm_run->io.data_offset);
            // printf("%d: %d\n", file_args->id, file_args->offset);

            char *buf = malloc(file_args->count);
            lseek(file_args->fd, file_args->offset, SEEK_SET);
            ssize_t size = read(file_args->fd, buf, file_args->count);

            for(int j = 0; j < size; j++){
                file_args->buffer[j] = buf[j];
            }

            free(buf);
            file_args->count = 0;
            file_args->offset = size;
            file_args->state = READ_RET;
            break;
        }
        case WRITE_FD: { // write
            file_args->fd = *(int *)(p + vm->kvm_run->io.data_offset);

            int index = getIndexSharedFileFd(file_args->fd);
            if(index != -1 && file_args->localCopies[index] != -1){
                file_args->fd = file_args->localCopies[index];
            }
            else if(index != -1){

                setup_directory(file_args);
                char* name = shared_files_names[index];
                while(*name != '\0'){
                    file_args->buffer[file_args->count++] = *name++;
                }
                file_args->buffer[file_args->count++] = '\0';

                file_args->fd = open(file_args->buffer, O_RDWR | O_CREAT, 0644);
                if (file_args->fd == -1) {
                    perror("open");
                }

                int fd_shared = shared_files[index];
                lseek(fd_shared, 0, SEEK_SET);
                char buffer[1024];
                ssize_t size;
                while((size = read(fd_shared, buffer, 1024)) > 0){
                    // printf("size: %ld\n", size);
                    write(file_args->fd, buffer, size);
                }

                file_args->localCopies[index] = file_args->fd;
            }

            // printf("%d: %d\n", file_args->id, file_args->fd);

            file_args->count = 0;
            file_args->state = WRITE_DATA;
            break;
        }
        case WRITE_DATA: { // write
            char c = *(p + vm->kvm_run->io.data_offset);
            // printf("%d: %c\n", file_args->id, c);
            file_args->buffer[file_args->count++] = c;

            if(file_args->count == 1023 && c != '\0'){
                file_args->buffer[file_args->count] = '\0';
                write(file_args->fd, file_args->buffer, file_args->count);
                file_args->count = 0;
            }

            else if(c == '\0'){
                write(file_args->fd, file_args->buffer, file_args->count - 1);
                file_args->count = 0;
                file_args->state = NONE;
            }

            break;
        }
    }
}



void returnValueToGuest(struct vm* vm, struct vm_file_args *file_args){
    char *p = (char *)vm->kvm_run;
    
    switch(file_args->state){
        case OPEN:
            // printf("%d: IN OPEN\n", file_args->id);
            *((uint32_t *)(p + vm->kvm_run->io.data_offset)) = file_args->fd;
            file_args->state = NONE;
            break;
        case READ_RET:
            // printf("%d: IN READ\n", file_args->id);
            *(p + vm->kvm_run->io.data_offset) = file_args->buffer[file_args->count++];

            if(file_args->count == file_args->offset){
                file_args->state = NONE;
                file_args->count = 0;
            }
            break;
    }

}