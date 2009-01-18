#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>

#define PROC "/proc/kadvice"

int main(int argc, char **argv){
  char advice[128];

  int len = sprintf(advice, "post http://lsm/%s.1.1 sample_%s", argv[1], argv[1]);

  int fd;
  fd = open(PROC, O_RDWR);
  if(fd == -1)
    perror("open");
  ssize_t ret;
  printf("advice:%s\n", advice);
  ret = write(fd, advice, len);
  if(ret <= 0)
    perror("write");
  return 0;
}
