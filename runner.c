#include <errno.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <malloc.h>

#define FILTER_ARCH AUDIT_ARCH_X86_64

int pagesize;
unsigned char * shellcode;

static void process_setup(void);
static void set_seccomp(void);
static void test_flag(void);

int main(void)
{
      process_setup();

      test_flag();

      /* Stop hackers from doing nasty stuff */
      set_seccomp();

      puts("Ready to receive shellcode...");
      read(STDIN_FILENO, shellcode, pagesize);

      puts("Executing shellcode...");
      ((void (*)(void)) shellcode)();
}

static void process_setup()
{
      setvbuf(stdout, NULL, _IONBF, 0);

      if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0)) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            exit(1);
      }

      pagesize = sysconf(_SC_PAGE_SIZE);

      shellcode = memalign(pagesize,  pagesize);
      if (shellcode == NULL) {
            perror("memalign");
            exit(1);
      }

      if (mprotect(shellcode, pagesize, PROT_READ|PROT_WRITE|PROT_EXEC)) {
            perror("mprotect");
            exit(1);
      }
}

static void set_seccomp()
{
  struct sock_filter filter[] = {
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, FILTER_ARCH, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_writev, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_open, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_openat, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 0, 1),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
    perror("prctl(PR_SET_SECCOMP)");
    exit(1);
  }
}

static void test_flag()
{
      int fd = open("flag.txt", O_RDONLY);
      if (fd < 0) {
            puts("Flag is missing or broken!");
      } else {
            puts("Flag present, closing.");
            close(fd);
      }
}
