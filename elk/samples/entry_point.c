#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>


const char *instr = "\x48\x31\xff\xb8\x3c\x00\x00\x00\x0f\x05";

int main(){
  printf("        main @ %p\n", &main);
  printf("instructions @ %p\n", instr);

  size_t region = (size_t) instr;
  region = region & (~0xfff);
  printf("        page @ %p\n", &region);
  printf("making it executable...\n");

  int ret = mprotect(
                     (void*) region,
                     0x1000,
                     PROT_READ | PROT_EXEC);

  if(ret != 0){
    printf("failed, error: %d\n", errno);
    return 1;
  }

  void (*f)(void) = (void*) instr;
  printf("doing the jump thing\n");
  f();

}
