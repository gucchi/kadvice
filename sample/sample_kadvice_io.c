
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BUFSZ 4096

#define TYPEINFO_SIZE 128
#define PACKET_SIZE \
  BUFSZ - TYPEINFO_SIZE - sizeof(size_t)

struct ka_packet {
  size_t typeinfo_len;
  char typeinfo_list[TYPEINFO_SIZE];
  char body[PACKET_SIZE];
};

struct ka_typeinfo {
  char typename[];
  size_t size;
};

void process_type(char *buf)
{
  


}

int main (void)
{
  FILE *fp;
  char *filename = "/proc/kkk";
  
  fp = fopen(filename, "rb");
  if (fp == NULL) {
    perror("open failed");
    exit(1);
  }
  
  char buf[BUFSZ];
  fread(buf, BUFSZ, 1, fp);
  fclose(fp);
  
  /* start parsing */
  struct ka_packet *p = (struct ka_packet *)buf;
  printf("%d %d %d\n", p->typeinfo_len, sizeof(int), sizeof(char));
  printf("%s\n", p->typeinfo_list);
  printf("%s\n", p->body);
  return 0;

}
