#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int
foo ( char *arg )
{
	char	buf[252];
	int	p, j, len;
	//printf("address of len = %x\n",&len);

/*	char* env;
	env = arg+281;
	printf("the address of env is %p \n", (env));
	printf("the value inside of env is %c \n", *(env));
*/

	//printf("address of first env variable = %x\n",&arg);
	p = 272;
	len = (strlen(arg) > p) ? p : strlen(arg);
  	//printf("length of arg = %d\n",strlen(arg));
	
	for (j = 0; j <= len; j++){
		buf[j] = arg[j];
		//printf("j = %d\n",j);
		//printf("content = %x\n",arg[j]);
	}
	//printf("first char of j = %x\n",buf[263]);
	//printf("first char of len = %c\n",buf[267]);
	//printf("p = %d\n",p);
  	//printf("j = %d\n",j);
	
  	//printf("length of len = %d\n",len);
	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	int	t = 2;

	printf ("Target2 running.\n");

	if (argc != t)
	{
		fprintf ( stderr, "target2: argc != 2\n" );
		exit ( EXIT_FAILURE );
	}
/*
	printf("address of t = %x\n",&t);
	printf("content of first env variable = %s\n",argv[3]);
	printf("address of first env variable = %x\n",&argv[3]);
*/
	foo ( argv[1] );

	return (0);
}
