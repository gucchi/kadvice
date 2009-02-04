#ifndef __KADVICE_IO_H
#define __KADVICE_IO_H

#include <linux/module.h>
#include <linux/security.h>
#include <linux/list.h>
#include <linux/slab.h>

//struct list_head ka_datum_list;

#define RINGBUFFER_SIZE 1023
#define RINGBUFFER_NUM 4

enum ka_datum_type {
  D_INT,
  D_CHAR,
  D_STRING,
  D_URI
};

struct ka_datum {
  size_t typeinfo_len;
  char *typeinfo;
  size_t size;
  void *value;
  struct list_head list;
};

#define TYPEINFO_SIZE 0
#define PACKET_SIZE \
  RINGBUFFER_SIZE -  TYPEINFO_SIZE - sizeof(size_t)  

struct ka_packet{
  size_t typeinfo_len;
  char body[PACKET_SIZE];
};

struct ka_ringbuffer {
  int dirty;
  char buffer[RINGBUFFER_SIZE];
  struct ka_ringbuffer *head;
};

#define BUFFER_CLEAN 0
#define BUFFER_DIRTY 1

struct ka_packet_operations {
  // for packing operation
  struct ka_packet *(*pack)(struct list_head *);
};

struct ka_kadvice {
  struct proc_dir_entry *ka_proc_entry;
  struct ka_ringbuffer *read;
  struct ka_ringbuffer *write;
  struct ka_packet_operations pops;
  void (*rlotate)(struct ka_kadvice *);
  void (*wlotate)(struct ka_kadvice *);

  /* ka_datum_list is for datum list; */
  struct list_head ka_datum_list;
  //gucchi
  char body[PACKET_SIZE];
  
};

extern int kadvice_int_put(int n);
extern int kadvice_char_put(char n);
extern int kadvice_string_put(char *str);
extern int kadvice_uri_put(char* uri);
extern void kadvice_send(void);
//gucchi
extern int kadvice_put(char *str);

#endif /* __KADVICE_IO_H */
