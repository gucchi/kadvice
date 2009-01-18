#ifndef __KADVICE_IO_H
#define __KADVICE_IO_H

#include <linux/module.h>
#include <linux/security.h>
#include <linux/list.h>
#include <linux/slab.h>

struct list_head ka_datum_list;

//INIT_LIST_HEAD(&ka_datum_list);
#define RINGBUFFER_SIZE 4096
#define RINGBUFFER_NUM 4


enum ka_datum_type {
  D_INT,
  D_CHAR,
  D_STRING
};

struct ka_datum {
  size_t typeinfo_len;
  char *typeinfo;
  size_t size;
  void *value;
  struct list_head list;
};
#define TYPEINFO_SIZE 128
#define PACKET_SIZE \
  RINGBUFFER_SIZE -  TYPEINFO_SIZE - sizeof(size_t)  

struct ka_packet{
  size_t typeinfo_len;
  char typeinfo_list[TYPEINFO_SIZE];
  char body[PACKET_SIZE];
};



struct ka_ringbuffer {
  char buffer[RINGBUFFER_SIZE];
  struct ka_ringbuffer *head;
};

struct ka_kadvice {
  struct proc_dir_entry *ka_proc_entry;
  struct ka_ringbuffer *read;
  struct ka_ringbuffer *write;
};

#endif /* __KADVICE_IO_H */

