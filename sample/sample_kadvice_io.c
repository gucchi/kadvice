
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define BUFSZ 4096

#define TYPEINFO_SIZE 0
#define PACKET_SIZE \
  BUFSZ - TYPEINFO_SIZE - sizeof(size_t)

struct ka_packet {
  size_t typeinfo_len;
  //  char typeinfo_list[TYPEINFO_SIZE];
  char body[PACKET_SIZE];
};

struct ka_typeinfo {
  char *typename;
  size_t size;
};

struct ka_datum {
  size_t size;
  void *ptr;
};


struct ka_datum *unpack(char *segment_head)
{
  struct ka_datum *d = (struct ka_datum *)malloc(sizeof(struct ka_datum));
  memcpy(&(d->size), segment_head, sizeof(size_t));
  segment_head += sizeof(size_t);
  d->ptr = malloc(sizeof(char) * d->size);
  memcpy(d->ptr, segment_head, d->size);
  if (d->size == 0) return NULL;
  return d;
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
#if 0
  struct ka_packet *p = (struct ka_packet *)buf;
  printf("%d %d %d\n", p->typeinfo_len, sizeof(int), sizeof(char));
  printf("%s\n", p->typeinfo_list);
  printf("%s\n", p->body);
#endif
  struct ka_packet *p = (struct ka_packet *)buf;
  size_t readsize = 0;
  char *cur = p->body;
  while (readsize < PACKET_SIZE) {
    struct ka_datum *d = unpack(cur);
    if (d == NULL)
      break;
    printf("%s\n", d->ptr);
    readsize += d->size;
    cur += sizeof(size_t) + d->size;
  }
  printf("process end...\n");
  return 0;

}
