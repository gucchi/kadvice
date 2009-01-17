#ifndef __KADVICE_IO_H
#define __KADVICE_IO_H

#include <linux/module.h>
#include <linux/security.h>
#include <linux/list.h>
#include <linux/slab.h>

#define KADVICE_CHANNEL_PACKSIZE 4096
#define KADVICE_CHANNEL_HEADERSIZE 12
#define KADVICE_CHANNEL_DATASIZE_MAX KADVICE_CHANNEL_PACKSIZE - KADVICE_CHANNEL_HEADERSIZE

struct list_head ka_datum_list;

//INIT_LIST_HEAD(&ka_datum_list);

enum ka_datum_type {
  D_INT,
  D_CHAR,
  D_STRING
};

struct ka_datum {
  char *typeinfo;
  size_t size;
  void *value;
  struct list_head list;
};


#endif /* __KADVICE_IO_H */


