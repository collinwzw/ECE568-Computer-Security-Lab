 Instructions
 ------------
 
 1. Make sure you type in your student number in the #define in sploit.c .  You should format your student number as a string without spaces like this:
 
 #define STUDENT_NUMBER "989990924"
 
 It does not matter whether your student number is 9 or 10 digits. 
 
 2. Fill in the "attackString" variable with your attack string.  Your goal will be to execute the shellcode, which is the same as in the lab and spawn a shell.
 
 3. To submit your solution, please upload your sploit.c file to Quercus AND submit your entire directory using the command
 
 submitece568f 9 *
 
  Hints
 ------------
 This target is basically the same as target1 in Lab 1 except that the first is skipped (because it is your student number).  Instead the attack string is located in argv[2].  The other difference is that the stack layout will be different, so you will have to adjust your attack code accordingly.