#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
foo ( char *arg )
{
	int		len;
	int		i;
	char		buf[188];
	static char *	a;
	static char *	b;
	
	len = strlen(arg);
	if (len > 201) len = 201;

	a = arg;
	b = buf;
	
	for (i = 0; i <= len; i++){
		*b++ = *a++;
		printf("the i = %d and len is %d\n",i,len);
		printf("the content is  %x \n",*a);
		printf("the address of b %p \n",(b));
	}

	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	printf ("Target4 running.\n");

	if (argc != 2)
	{
		fprintf(stderr, "target4: argc != 2\n");
		exit(EXIT_FAILURE);
	}
	
	foo ( argv[1] );
	return (0);
}
