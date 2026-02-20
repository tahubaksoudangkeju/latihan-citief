#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#define IV 0x42

int main(int argc, char **argv){
    if(argc < 3){ fprintf(stderr,"Usage: %s flag.txt output.bin\n", argv[0]); return 1; }
    FILE *f = fopen(argv[1],"rb"); if(!f){perror("flag"); return 1;}
    fseek(f,0,SEEK_END); long n=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *buf = (uint8_t*)malloc(n); fread(buf,1,n,f); fclose(f);
    while(n>0 && (buf[n-1]=='\n'||buf[n-1]=='\r')) n--;
    if(n<=0){ fprintf(stderr,"empty flag\n"); free(buf); return 1; }

    uint8_t *enc = (uint8_t*)malloc(n);
    enc[0] = buf[0] ^ IV;
    for(long i=1;i<n;i++) enc[i] = buf[i] ^ buf[i-1];

    FILE *o=fopen(argv[2],"wb"); if(!o){perror("out"); free(buf); free(enc); return 1;}
    fwrite(enc,1,n,o); fclose(o);
    free(buf); free(enc); return 0;
}
