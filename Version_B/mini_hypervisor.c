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
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <pthread.h>

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

void* vm_thread(void *arg);

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
};

int main(int argc, char *argv[])
{
    uint32_t MEM_SIZE;
    uint32_t PAGE_SIZE; 

	if (argc < 7) {
    	printf("The program requests 3 parameters: memory size (-m or --memory),\
                page size (-p or --page) and guest images (-g or --guest) \n");
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

    int numImages = argc - 6;
    FILE **imgs = malloc(sizeof(FILE *) * numImages);
    

    for(int i = 6 ; i < argc;  i++) {
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

    pthread_t *tids = malloc(sizeof(pthread_t) * numImages);

    for(int i = 0 ; i < numImages; i++) {
        struct vm_thread_args *args = malloc(sizeof(struct vm_thread_args));
        args->mem_size = MEM_SIZE;
        args->page_size = PAGE_SIZE;
        args->img = imgs[i];

        pthread_create(&tids[i], NULL, vm_thread, args);
    }

    for(int i = 0; i < numImages; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);
    free(imgs);

    return 0;
	
}



// telo niti za vm
void* vm_thread(void *arg){
    struct vm_thread_args *args = (struct vm_thread_args *)arg;

    struct vm vm;
	struct kvm_sregs sregs;
	struct kvm_regs regs;
	int stop = 0;
	int ret = 0;

    uint32_t mem_size = args->mem_size;
    uint32_t page_size = args->page_size;
    FILE* img = args->img;

    free(args);

    if (init_vm(&vm, mem_size)) {
		printf("Failed to init the VM\n");
		return NULL;
	}

	if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		return NULL;
	}

	setup_long_mode(&vm, &sregs, page_size, mem_size);

    if (ioctl(vm.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		return NULL;
	}

	memset(&regs, 0, sizeof(regs));
	regs.rflags = 2;
	regs.rip = 0;
	// SP raste nadole
	regs.rsp = mem_size; //da stek krece od vrha i raste nadole

	if (ioctl(vm.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
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
            return NULL;
		}

		switch (vm.kvm_run->exit_reason) {
			case KVM_EXIT_IO:
				if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0xE9) {
					char *p = (char *)vm.kvm_run;
					printf("%c", *(p + vm.kvm_run->io.data_offset));
                    fflush(stdout);
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

    return NULL;
}
