#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 64

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void banjir(long derajat, long menit, long detik) {
    if (derajat == 0xdeadbeef && menit == 0xdeadc0de && detik == 0xbaddc0de) {
        FILE *fp;
        char flag[128];
        fp = fopen("flag.txt", "r");
        if (fp == NULL) {
            printf("File flag.txt tidak ditemukan\n");
            exit(1);
        }

        fgets(flag, sizeof(flag), fp);
        printf("Flag: %s\n", flag);

        fclose(fp);
        
        exit(0);
    } else {
        printf("Tidak ada banjir disitu\n");
    }
}

void cekBanjir() {
    banjir(1, 2, 3);
}

void gadgets() __attribute__((naked));
void gadgets() {
    __asm__(
        "pop %rdi\n\t"
        "pop %rsi\n\t"
        "pop %rdx\n\t"
        "ret\n\t"
    );
}

void vuln() {
    char buffer[BUFFER_SIZE];

    puts("================ SISTEM INFORMASI BANJIR SEMARANG ================");
    printf("Lokasi: ");
    // gets(buffer);
    read(0, buffer, 0x200);

}

int main() {
    init();
    vuln();
    return 0;
}