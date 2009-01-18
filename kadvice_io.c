/* 
 * Kadvice read interface
 * shinpei(c)ynu 2009
 *
 */

#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>

#define PROCNAME "kkk"

#include "kadvice_io.h"
#include "kadvice_debug.h"

static struct ka_kadvice kadvice;



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

/* ka_datum_free_all
 * 
 * delete all entry from ka_datum_list
 * once its writed into buffer, this could occur.
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

/* ka_pack
 *
 * pack all datum entry form ka_datum_list and make ka_packet.
 * make sure that this function is called once at the end of
 * ka_(types)_write.
 */

static struct ka_packet *ka_pack(void)
{
  struct ka_packet *hdr = (struct ka_packet *)kmalloc
    (sizeof(struct ka_packet), GFP_KERNEL);
  struct list_head *ptr;
  struct ka_datum *entry;
  
  size_t len = 0;
  size_t size = 0;
  char *tcur = hdr->typeinfo_list;
  char *bcur = hdr->body;
  list_for_each(ptr, &ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    len += entry->typeinfo_len;
    size += entry->size;
    memcpy(tcur, entry->typeinfo, sizeof(char) * entry->typeinfo_len);
    tcur += entry->typeinfo_len;
    memcpy(bcur, entry->value, entry->size);
    bcur += entry->size;
  }
  DBG_P("len of typeinfo:%d", len);
  hdr->typeinfo_len = len;
  /*
    hdr->typeinfo_list = (char *)kmalloc
    (sizeof(char) * len + 1, GFP_KERNEL);
  */
#if 0
  if (len > TYPEINFO_SIE || size > PACKET_SIZE)
    return NULL /* error */
  
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
#endif
  DBG_P("sizeof packet:%d", sizeof(struct ka_packet));
  return hdr;
}

static void ka_init_rbuf(struct ka_kadvice *k)
{
  struct ka_ringbuffer *r;
  int i;

  k->write = (struct ka_ringbuffer *)kzalloc
    (sizeof(struct ka_ringbuffer), GFP_KERNEL);
  r = k->write;
  for (i = 1; i < RINGBUFFER_NUM; i++) {
    r->head = (struct ka_ringbuffer *)kzalloc
      (sizeof(struct ka_ringbuffer), GFP_KERNEL);
    r = r->head;
  }
  r->head = k->write;
  k->read = k->write;
  DBG_P("write:%p read:%p", k->write, k->read);
}

/* ka_rbuf_lotate
 * 
 * lotate rbuf. 
 */

static inline void ka_rbuf_lotate(struct ka_ringbuffer *rbuf)
{
  rbuf = rbuf->head;
}

/* ka_write_rbuf_packet
 * write packet to rbuf;
 * 
 */
static void ka_write_rbuf_packet(struct ka_ringbuffer *rbuf,
				 struct ka_packet *packet)
{
  memcpy(rbuf, packet, RINGBUFFER_SIZE);
  ka_rbuf_lotate(rbuf);
}

static int ka_read_proc (char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
  int len = 0;
  struct ka_packet *packet;
  struct ka_kadvice *k = (struct ka_kadvice *)data;
  struct ka_ringbuffer *readbuf = k->read;
  packet = ka_pack();
  if (packet == NULL) {
    *eof = 1;
    DBG_P("cannot pack.");
    return 0;
  }
  
  ka_write_rbuf_packet(readbuf, packet);
  DBG_P("bbb");
  /* this is original code for read_proc */
  
  memcpy(page, readbuf->buffer, RINGBUFFER_SIZE);
  DBG_P("bye");
  len = RINGBUFFER_SIZE;

  return len;

}

static struct proc_dir_entry *ka_proc_entry;

static int ka_proc_init(void)
{
  kadvice.ka_proc_entry = create_proc_entry(PROCNAME, 0666, NULL);
  if (kadvice.ka_proc_entry == NULL)
    return -ENOMEM;

  INIT_LIST_HEAD(&ka_datum_list);
  ka_init_rbuf(&kadvice);
  DBG_P("write:%p, read:%p", kadvice.write, kadvice.read);
  kadvice.ka_proc_entry->data = (void *)&kadvice;
  DBG_P("data:%p rbuf:%p", kadvice.ka_proc_entry->data, 
	kadvice.write);
  kadvice.ka_proc_entry->read_proc = ka_read_proc;

  //  kadvice_int_put(3);
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
