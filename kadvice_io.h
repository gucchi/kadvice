#ifndef __KADVICE_IO_H
#define __KADVICE_IO_H

#include <linux/module.h>
#include <linux/security.h>
#include <linux/list.h>


#define KADVICE_CHANNEL_PACKSIZE 4096
#define KADVICE_CHANNEL_HEADERSIZE 12
#define KADVICE_CHANNEL_DATASIZE_MAX KADVICE_CHANNEL_PACKSIZE - KADVICE_CHANNEL_HEADERSIZE

struct list_head ka_datum_list;
INIT_LIST_HEAD(&ka_datum_list);

enum ka_datum_type {
  D_INT,
  D_CHAR,
  D_STRING
};

struct ka_dutum {
  struct list_head list;
  const char* typeinfo[16];
  size_t size;
  void *value;
  
};


struct kadvice_channel_ops {
  void (*int_put)(int);
  char_put;
  long_put;
};


struct kadvice_contents_body {
  char body[KADVICE_CHANNEL_BODY_SIZE];
}


struct kadvice_channel_header {
  const char *response;
  int num_value;
  struct kadvice_contents_type *head;
  
};

struct kadvice_channel {
  
  struct kadvice_channel_header *head;
  struct kadvice_channel_ops *ops;
  int status;
  
};

#endif
