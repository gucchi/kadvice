/* 
 * Kadvice readinterface
 * shinpei(c)ynu 2009
 */

#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

#define PROCNAME "kkk"

#include "kadvice_io.h"
#include "kadvice_debug.h"

static struct ka_kadvice kadvice;

static DEFINE_MUTEX(kadvice_mutex);

/*
 * make new data node (which we call datum).
 */
struct ka_datum *ka_new_datum(int type)
{
  struct ka_datum *d;
  d = (struct ka_datum *)kmalloc
    (sizeof(struct ka_datum), GFP_KERNEL);
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
  case D_URI:
    d->typeinfo_len = sizeof("uri");
    d->typeinfo = (char *)kmalloc
      (sizeof(char) * d->typeinfo_len + 1, GFP_KERNEL);
    strcpy(d->typeinfo, "uri");
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
  list_add_rcu(&d->list, &(kadvice.ka_datum_list));
  
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
  
  /* insert datum list. */
  list_add_rcu(&d->list, &(kadvice.ka_datum_list));
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
  
  /* insert datum list. */
  list_add_rcu(&d->list, &(kadvice.ka_datum_list));
  return 0;
}
EXPORT_SYMBOL(kadvice_string_put);

int kadvice_uri_put(char *uri)
{
  struct ka_datum *d;
  d = ka_new_datum(D_URI);
  d->size = strlen(uri) + 1;
  d->value = kmalloc(d->size, GFP_KERNEL);
  memcpy(d->value, (void *)uri, d->size);
  
  /* insert datum list. */
  list_add_rcu(&d->list, &(kadvice.ka_datum_list));
  return 0;
}
EXPORT_SYMBOL(kadvice_uri_put);

static inline int ka_rbuf_isdirty
(struct ka_ringbuffer *rbuf)
{
  return rbuf->dirty;
}

static inline void ka_rbuf_setdirty
(struct ka_ringbuffer *rbuf)
{
  rbuf->dirty = BUFFER_DIRTY;
}

static inline void ka_rbuf_setclean
(struct ka_ringbuffer *rbuf)
{
  rbuf->dirty = BUFFER_CLEAN;
}

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
  if (list_empty(&(kadvice.ka_datum_list)))
    return ;
  list_for_each_safe(ptr, next, &(kadvice.ka_datum_list)) {
    entry = list_entry(ptr, struct ka_datum, list);
    list_del_rcu(ptr);
    kfree(entry->typeinfo);
    kfree(entry->value);
    kfree(entry);
  }
  //  if (list_empty(&(kadvice.ka_datum_list)))
  //DBG_P("emprified");
}

/* ka_pack_URI_included
 *
 * URI included packet.
 */
static struct ka_packet *ka_pack_URI_included
 (struct list_head *ka_datum_list)
{
  /*
   * URI included packet
   * ____________________________________________
   *               URI (128bytes)            
   * --------------------------------------------
   * size | bytes | size | bytes | 
   * --------------------------------------------
   */
  struct ka_packet *p;
  struct list_head *ptr;
  struct ka_datum *entry;
  
  const unsigned int uri_len = 128;
  char *uri_cur;
  char *bcur;
  size_t size = 0;

  if(list_empty(ka_datum_list)) 
    return NULL;


  //  mutex_lock(&kadvice_mutex);
  preempt_disable();


  p = (struct ka_packet *)kmalloc
    (sizeof(struct ka_packet), GFP_KERNEL);
  uri_cur = p->body;
  bcur = &(p->body[uri_len]);
  
  /* now, implement URI into packet. */
  
  list_for_each(ptr, ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    if (entry->typeinfo_len == sizeof("uri") && 
	(strcmp(entry->typeinfo, "uri")) == 0) {
      memcpy(uri_cur, entry->value, 
	     sizeof(char) * entry->size);
    } else {
      memcpy(bcur, (char*)&(entry->size), sizeof(size_t));
      bcur += sizeof(size_t);
      memcpy(bcur, entry->value, entry->size);
      bcur += entry->size;
      size += entry->size;
    }
  }
  if (size + uri_len < PACKET_SIZE) {
    memset(bcur, 0, PACKET_SIZE - (size+uri_len));
  }
  preempt_enable();
  //  mutex_unlock(&kadvice_mutex);
  return p;
}

/* ka_pack
 *
 * pack all datum entry form ka_datum_list and make ka_packet.
 * make sure that this function is called once at the end of
 * ka_(types)_write.
 */
static struct ka_packet *ka_pack_modified (struct list_head
					   *ka_datum_list)
{
  /* 
   * assuming client(who insert 
   * filtering module) would know memory layout.
   *____________________________________
   * size ! bytes    ! size !  bytes    !
   * ------------------------------------
   */
  struct ka_packet *p;
  struct list_head *ptr;
  struct ka_datum *entry;
  size_t size = 0;
  char *bcur;

  if (list_empty(ka_datum_list))
    return NULL;

  p = (struct ka_packet *)kmalloc
    (sizeof(struct ka_packet), GFP_KERNEL);
  bcur = p->body;
  list_for_each(ptr, ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    memcpy(bcur, (char*)&(entry->size), sizeof(size_t));
    bcur += sizeof(size_t);
    memcpy(bcur, entry->value, entry->size);
    bcur += entry->size;
    size += entry->size;
  }
  
  if (size < PACKET_SIZE) {
    memset(bcur, 0, PACKET_SIZE - size);
  }
  
  return p;
}

/* ka_pack_typeinfo
 * 
 * including typeinformation. in the case that 
 * user mode program wouldn't know the layout of
 * struct (means, packet);
 */
static struct ka_packet *ka_pack_typeinfo
(struct list_head *ka_datum_list)
{
  /* __________________________________________
   * typesize !type, type, type                
   * ------------------------------------------
   * bytesize ! bytes 
   * -----------------------------------------
   */
  struct ka_packet *p;
  struct list_head *ptr;
  struct ka_datum *entry;
  char *tcur;
  char *bcur;

  size_t len = 0;
  size_t size = 0;
  const unsigned int typeinfo_list_len = 128;

  if (list_empty(ka_datum_list))
    return NULL;

  p = (struct ka_packet *)kmalloc
    (sizeof(struct ka_packet), GFP_KERNEL);
  tcur = p->body;
  bcur = &(p->body[typeinfo_list_len]);  
  
  list_for_each(ptr, ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    len += entry->typeinfo_len;
    size += entry->size;
    memcpy(tcur, entry->typeinfo,
	   sizeof(char) * entry->typeinfo_len);
    tcur += entry->typeinfo_len;
    memcpy(bcur, entry->value, entry->size);
    bcur += entry->size;
  }
  DBG_P("len of typeinfo:%d", len);
  p->typeinfo_len = len;
  /*
    hdr->typeinfo_list = (char *)kmalloc
    (sizeof(char) * len + 1, GFP_KERNEL);
  */
#if 0
  if (len > TYPEINFO_SIE || size > PACKET_SIZE)
    return NULL /* error */
  
  list_for_each(ptr, ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    memcpy(cur, entry->typeinfo, 
	   sizeof(char) * entry->typeinfo_len);
    cur += entry->typeinfo_len;
    cur[-1] = ',';
  }
  cur[0] = '\0';
  DBG_P("%s", p->typeinfo_list);
  
  /* now pack datagram */
  cur = p->body;
  list_for_each(ptr, ka_datum_list) {
    entry = list_entry(ptr, struct ka_datum, list);
    memcpy(cur, entry->value, entry->size);
    cur += entry->size;
  }
#endif
  DBG_P("sizeof packet:%d", sizeof(struct ka_packet));
  return p;
}


static void ka_write_rbuf_packet(struct ka_ringbuffer *rbuf,
				 struct ka_packet *packet)
{
  
  memcpy(rbuf->buffer, packet, RINGBUFFER_SIZE);

}

/*
 * kadvice_send()
 *
 * this is exported symbol for other kernel functions.
 */

void kadvice_send(void)
{
  struct ka_packet *packet;

  //preempt_disable();
  packet = kadvice.pops.pack(&(kadvice.ka_datum_list));
  ka_write_rbuf_packet(kadvice.write, packet);

  ka_rbuf_setdirty(kadvice.write);

  kadvice.wlotate(&kadvice);
  //preempt_enable();

}
EXPORT_SYMBOL(kadvice_send);

/*
 * clear all ring buffers and free them.
 */
static void ka_fini_rbuf(struct ka_kadvice *k)
{
  struct ka_ringbuffer *prev, *cur;
  int i;
  
  prev = cur = k->write;
  for (i = 0; i < RINGBUFFER_NUM; i++) {
    cur = cur->head;
    kfree(prev);
    prev = cur;
  }
  DBG_P("buffer finishment.");
}

/*
 * initiate ring buffers for RINGNUM.
 */
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
    ka_rbuf_setclean(r);
    r = r->head;
  }
  ka_rbuf_setclean(r);
  r->head = k->write;
  k->read = k->write;
  r = k->read;
  for(i = 0; i < RINGBUFFER_NUM + 1; i++) {
    printk("%p %d ",k->read,  k->read->dirty);
    k->rlotate(k);
  }
  printk("\n");
  for(i = 0; i < RINGBUFFER_NUM + 1; i++) {
    printk("%p %d ",k->write,  k->write->dirty);
    k->wlotate(k);
  }
  printk("kadvice:%p\n", k);

}

/* 
 * when user program read PROC filesystem
 * copy ringbuffer contents into *page
 * proc filesystem allocate buffer for this 
 * operation, one page size, 4096
 * but at most, one call of read_proc is 1024 bytes.
 * 
 * in case, we want send more size, read would be called
 * for several times from read syscall.
 */
static int ka_read_proc (char *page, char **start, off_t off,
			 int count, int *eof, void *data)
{
  
  int len = 0;
  struct ka_kadvice *k = (struct ka_kadvice *)data;
  struct ka_ringbuffer *readbuf = k->read;

  /* if read buffer is empty, then return null */
  //printk("offset is %d %d %d \n", off, *eof, count);
  if (off != 0) {
    *eof = 1;
    return 0;
  }
  if (!ka_rbuf_isdirty(readbuf)) {
    *eof = 1;
    return 0;
  }
  //printk("%s", readbuf->buffer);
  memcpy(page, readbuf->buffer, RINGBUFFER_SIZE);
  printk("read from:%p\n", readbuf);
  /* clean up buffer before lotate */
  memset(readbuf->buffer, 0, RINGBUFFER_SIZE);
  ka_rbuf_setclean(readbuf);
 
  k->rlotate(k);

  len = RINGBUFFER_SIZE;
  
  ka_datum_free_all();
  *eof = 1;
  return len;
}

/*
 * lotate function for read buffer.
 */
static void lotate_read(struct ka_kadvice *k)
{
  k->read = k->read->head;
}

/* lotate function for write buffer.
 */
static void lotate_write(struct ka_kadvice *k)
{
  k->write = k->write->head;
}

/*
 * proc initiation.
 */
static int ka_proc_init(void)
{
  kadvice.rlotate = lotate_read; 
  kadvice.wlotate = lotate_write;
  kadvice.ka_proc_entry = create_proc_entry(PROCNAME, 0666, NULL);
  if (kadvice.ka_proc_entry == NULL)
    return -ENOMEM;

  INIT_LIST_HEAD(&(kadvice.ka_datum_list));
  ka_init_rbuf(&kadvice);

  kadvice.ka_proc_entry->data = (void *)&kadvice;
  kadvice.ka_proc_entry->read_proc = ka_read_proc;
  kadvice.pops.pack = ka_pack_URI_included;
  
  //  kadvice_string_put("goodbye, world");
  //  kadvice_uri_put("test.k");
  //  kadvice_string_put("hello, world");
  //  kadvice_send();
  return 0;
}

static void ka_proc_fini(void)
{
  remove_proc_entry(PROCNAME, NULL);
  ka_datum_free_all();
  ka_fini_rbuf(&kadvice);
}

module_init(ka_proc_init);
module_exit(ka_proc_fini);
  
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei Nakata");
MODULE_DESCRIPTION("Kadvice io interface");
