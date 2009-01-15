#include<stdio.h>
#include<sys/syscall.h>
#include<cabi/unistd.h>
#include<cabi/common.h>

_syscall2(int,cabi,int,cmd,unsigned long,arg)

void usage(){
  char ret[] = "usage: getaid <pid>\n";
  printf(ret);
}

int main(int argc, char **argv){
  if(argc != 2){
    usage();
    return 1;
  }
  int pid = atoi(argv[1]);
  int aid = cabi(9, pid);
  if(aid == -1){
    printf("process:%d\nnot binding\n", pid);
    return 0;
  }
  printf("process:%d\nkaoid:%d\n", pid, aid);
  return 0;
}
