
/* 
 * Kadvice read interface
 * shinpei(c)ynu 2009
 *
 *
 *
 */

#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#define PROCNAME "kkk"

#include "kadvice_io.h"
#include "kadvice_debug.h"



struct ka_datum *ka_new_datum(int type)
{
  struct ka_datum *d;
  d = (struct ka_datum *)kmalloc(sizeof(struct ka_datum), GFP_KERNEL);
  if (d == NULL) {
    DBG_P("cannot allocate");
  }
  switch (type) {
  case D_INT:
    d->typeinfo_len = sizeof("int");
    d->typeinfo = (char *)kmalloc(sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "int");
    d->typeinfo[d->typeinfo_len] = "\0";
    break;
  case D_CHAR:
    d->typeinfo_len = sizeof("char");
    d->typeinfo = (char *)kmalloc(sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "char");
    d->typeinfo[d->typeinfo_len] = "\0";
    break;
  case D_STRING:
    d->typeinfo_len = sizeof("string");
    d->typeinfo = (char *)kmalloc(sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "string");
    d->typeinfo[d->typeinfo_len] = "\0";
    break;
  default:
    DBG_P("typeinfo is missing");
    break;
  }
  return d;
}

int kadvice_int_put(int n)
{
  struct ka_datum *d;
  d = ka_new_datum(D_INT);
  d->size = sizeof(int);
  d->value = kmalloc(d->size, GFP_KERNEL);
  memcpy(d->value, &n, d->size);
  /* insert datum list. */
  list_add(&d->list, &ka_datum_list);
  
  return 0;
}
EXPORT_SYMBOL(kadvice_int_put);

int kadvice_char_put(char c)
{
  struct ka_datum *d;
  d = ka_new_datum(D_CHAR);
  d->size = sizeof(char);
  d->value = kmalloc(d->size, GFP_KERNEL);
  memcpy(d->value,(void *)&c, d->size);
  
  /* insert datum list */
  list_add(&d->list, &ka_datum_list);
  return 0;
}
EXPORT_SYMBOL(kadvice_char_put);


int kadvice_string_put(char* str)
{
  struct ka_datum *d;
  d = ka_new_datum(D_STRING);
  d->size = strlen(str) + 1;
  d->value = kmalloc(d->size, GFP_KERNEL);
  memcpy(d->value, (void *)str, d->size);
  
  /* insert datum list */
  list_add(&d->list, &ka_datum_list);
  return 0;
}
EXPORT_SYMBOL(kadvice_string_put);

/* ka_pack
 * 
 * pack ka_datum_list entry and make packet.
 * packet layout, see struct ka_packet.
 */

void ka_datum_free_all ()
{
  struct list_head *ptr;
  struct ka_datum *entry;
  struct list_head *next;
  list_for_each_safe(ptr, next, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    list_del(ptr);
    DBG_P("typeinfo:%s %d", entry->typeinfo, entry->typeinfo_len);
    kfree(entry->typeinfo);
    kfree(entry->value);
    kfree(entry);
  }
  if (list_empty(&ka_datum_list))
    DBG_P("emptified datum list");

}

static void ka_pack()
{
  struct ka_packet_header *hdr = (struct ka_packet_header *)kmalloc
    (sizeof(struct ka_packet_header), GFP_KERNEL);
  struct list_head *ptr;
  struct ka_datum *entry;
  
  size_t len = 0;
  char *cur;
  list_for_each(ptr, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    len += entry->typeinfo_len;
  }
  DBG_P("len of typeinfo:%d", len);
  hdr->typeinfo_len = len;
   hdr->typeinfo_list = (char *)kmalloc
    (sizeof(char) * len + 1, GFP_KERNEL);
  
  /* make typeinfo_list into hdr->typeinfo_list */
  cur = hdr->typeinfo_list;
  
  list_for_each(ptr, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    DBG_P("hehehe");
    memcpy(cur, entry->typeinfo, sizeof(char) * entry->typeinfo_len);
    cur += entry->typeinfo_len;
    DBG_P("hi");
    cur[-1] = ',';
  }
  DBG_P("hi");
  cur[0] = '\0';
  DBG_P("%s", hdr->typeinfo_list);
  
}

static void ka_init_ringbuffer(struct ka_ringbuffer *rbuf)
{
  struct ka_ringbuffer *r;
  int i;

  rbuf = (struct ka_ringbuffer *)kzalloc(sizeof(struct ka_ringbuffer), GFP_KERNEL);
  r = rbuf;
  for (i = 1; i < RINGBUFFER_NUM; i++) {
    r->head = (struct ka_ringbuffer *)kzalloc(sizeof(struct ka_ringbuffer), GFP_KERNEL);
    r = r->head;
  }
  r->head = rbuf;
}

static void ka_write_ringbuffer(struct ka_ringbuffer *rbuf)
{


}



static int ka_read_proc (char *page, char **start, off_t off,
			 int count, int *eof, void *data) {
  ka_pack();
  return 0;

}

static int ka_proc_init(void)
{
  struct proc_dir_entry *entry;
  entry = create_proc_entry(PROCNAME, 0666, NULL);
  if (entry == NULL)
    return -ENOMEM;
  entry->read_proc = ka_read_proc;
  INIT_LIST_HEAD(&ka_datum_list);
  //ka_init_ringbuffer(rbuf);
  kadvice_int_put(3);
  kadvice_string_put("hello, world");
  return 0;
}

static void ka_proc_fini(void)
{
  remove_proc_entry(PROCNAME, NULL);
  ka_datum_free_all();
}

module_init(ka_proc_init);
module_exit(ka_proc_fini);
  

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei Nakata");
MODULE_DESCRIPTION("Kadvice io interface");
