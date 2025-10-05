#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main() {
printf("PID: %d\n", getpid());
void *shellcode_area = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
if (shellcode_area == MAP_FAILED) {
perror("mmap failed");
return 1;
}
printf("Shellcode bölgesi: %p\n", shellcode_area);
while (1) {
asm volatile("nop"); // CPU'yu meşgul etmeden çalışmasını sağla
}
return 0;
}
