#include <stdio.h>
#include <stdlib.h>
struct linux_binprm {
  int unsafe;
};

void check_unsafe_exec(struct linux_binprm * bprm) {
  bprm->unsafe = 2;
}

void prepare_binprm(struct linux_binprm * bprm) {
  if (bprm->unsafe == 2) {
    printf("Downgrade Privilege.\n");
  } else {
    printf("Privilege Escalation.\n");
  }
}

void ptrace(struct linux_binprm * bprm) {
  bprm->unsafe = 0;
}

int main() {
  struct linux_binprm * bprm = (struct linux_binprm *) malloc(sizeof(struct linux_binprm));

  check_unsafe_exec(bprm);

  ptrace(bprm);
  
  prepare_binprm(bprm);

  free(bprm);
  return 0;
}
