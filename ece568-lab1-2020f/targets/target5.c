#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*void test()
{
	printf("target hit");
}
*/
int
foo ( char *arg )
{
	char	buf[1024];
	char	formatString[256];




	// A bit of a hack, to make things easier for the 64-bit addresses: we'll copy
	// the format string into a local buffer, and then skip the first 60 characters
	// of it when feeding it into snprintf(...)
	//printf("line before memcpy\n");
	memcpy(formatString, arg, 256);
	//*formatString = "%08x%08x%08x";

        //snprintf(buf, sizeof(buf), &formatString);
	snprintf(buf, sizeof(buf), &formatString[60]);
	//printf("%c\n",buf);
	

/*	
	int * p = (int *)0x40a4fe68;
	printf("%x",*p);
/*	//int i; 	
	//char *ptr;
	//ptr = formatString;
	//int * p = (int *)0x40a4fe68;

	
	for (i =0; i<256; i++){
		//if (i%8 == 0) printf("%08x",*(ptr++));
		//else printf(" %08x\n",*(ptr++));
		printf("i=%d,address = %p, value = %08x\n",i, ptr, *(ptr));
		ptr++;
  	}
  	*/
 
	return (0);
}

int
lab_main ( int argc, char *argv[] )
{
	printf ("Target5 running.\n");
	if (argc < 2)
	{
		fprintf(stderr, "target5: argc < 2\n");
		exit(EXIT_FAILURE);
	}
        
	foo ( argv[1] );
	return (0);
}
