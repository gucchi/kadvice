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
    d->typeinfo = (char *)kmalloc
      (sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "int");
    d->typeinfo[d->typeinfo_len] = '\0';
    break;
  case D_CHAR:
    d->typeinfo_len = sizeof("char");
    d->typeinfo = (char *)kmalloc
      (sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "char");
    d->typeinfo[d->typeinfo_len] = '\0';
    break;
  case D_STRING:
    d->typeinfo_len = sizeof("string");
    d->typeinfo = (char *)kmalloc
      (sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "string");
    d->typeinfo[d->typeinfo_len] = '\0';
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

static void ka_datum_free_all (void)
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

static struct ka_packet *ka_pack(void)
{
  struct ka_packet *hdr = (struct ka_packet *)kmalloc
    (sizeof(struct ka_packet), GFP_KERNEL);
  struct list_head *ptr;
  struct ka_datum *entry;
  
  size_t len = 0;
  size_t size = 0;
  char *cur;
  list_for_each(ptr, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    len += entry->typeinfo_len;
    size += entry->size;
  }
  DBG_P("len of typeinfo:%d", len);
  hdr->typeinfo_len = len;
   hdr->typeinfo_list = (char *)kmalloc
    (sizeof(char) * len + 1, GFP_KERNEL);
  
  /* make typeinfo_list into hdr->typeinfo_list */
  cur = hdr->typeinfo_list;
  
  list_for_each(ptr, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    memcpy(cur, entry->typeinfo, sizeof(char) * entry->typeinfo_len);
    cur += entry->typeinfo_len;
    cur[-1] = ',';
  }
  cur[0] = '\0';
  DBG_P("%s", hdr->typeinfo_list);
  
  /* now pack datagram */
  cur = hdr->body;
  list_for_each(ptr, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    memcpy(cur, entry->value, entry->size);
    cur += entry->size;
  }
  DBG_P("sizeof packet:%d", sizeof(struct ka_packet));
  return hdr;
}

static void ka_init_rbuf(struct ka_ringbuffer *write, struct ka_ringbuffer *read)
{
  struct ka_ringbuffer *r;
  int i;

  write = (struct ka_ringbuffer *)kzalloc
    (sizeof(struct ka_ringbuffer), GFP_KERNEL);
  r = write;
  for (i = 1; i < RINGBUFFER_NUM; i++) {
    r->head = (struct ka_ringbuffer *)kzalloc
      (sizeof(struct ka_ringbuffer), GFP_KERNEL);
    r = r->head;
  }
  r->head = write;
  DBG_P("cur_write:%p", write);
  read = write;
}


static inline void ka_rbuf_lotate(struct ka_ringbuffer *rbuf)
{
  rbuf = rbuf->head;
}


/* ka_write_rbuf_packet
 * write packet to rbuf;
 * 
 */
static void ka_write_rbuf_packet(struct ka_packet *packet)
{
  DBG_P("%p %p", current_rbuf_write, packet);
  memcpy(current_rbuf_write->buffer, packet, RINGBUFFER_SIZE);
  ka_rbuf_lotate(current_rbuf_write);
}



static int ka_read_proc (char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
  int len = 0;
  struct ka_packet *packet;
  packet = ka_pack();
  if (packet == NULL) {
    *eof = 1;
    DBG_P("cannot pack.");
    return 0;
  }
  
  ka_write_rbuf_packet(packet);
  DBG_P("bbb");
  /* this is original code for read_proc */
  
  DBG_P("hi");
  memcpy(page, current_rbuf_read->buffer, RINGBUFFER_SIZE);
  DBG_P("bye");
  len = RINGBUFFER_SIZE;

  return len;

}

static int ka_proc_init(void)
{
  struct proc_dir_entry *entry;
  entry = create_proc_entry(PROCNAME, 0666, NULL);
  if (entry == NULL)
    return -ENOMEM;
  entry->read_proc = ka_read_proc;

  INIT_LIST_HEAD(&ka_datum_list);
  ka_init_rbuf(current_rbuf_write, current_rbuf_read);


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
