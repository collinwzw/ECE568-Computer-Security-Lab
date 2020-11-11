#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**********************************************************
 Hints
 ------------
 This target is basically the same as target1 in Lab 1 except that the first is skipped (because it is your student number).  
 Instead the attack string is located in argv[2].  
 The other difference is that the stack layout will be different, so you will have to adjust your attack code accordingly.
 
 ***********************************************************/



int
foo ( char *arg, char *out )
{
	strcpy(out, arg);
	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	int	  t = 3;
    char  buf[112 + (argv[1][4]%8) * 8];
	
	printf("Target1 running for student #%s.\n", argv[1]);

	if (argc != t)
	{
		fprintf(stderr, "target1: argc != 3\n");
		exit(EXIT_FAILURE);
	}    

	foo ( argv[2], buf );
	return (0);
}
