
/* 
 * Kadvice read interface
 * shinpei(c)ynu 2009
 *
 *
 *
 */

#include <asm/uaccess.h>
#include <linux/kernel.h>

#include "kadvice_io.h"
#include "kadvice_debug.h"


struct kadvice_channel* ka_channel_new()
{
  return (struct kadvice_channel)kmalloc(sizeof(struct kadvice_channel));
}

struct kadvice_channel_header* ka_channel_hearer_new ()
{
  return (struct kadvice_channel_header*)kmalloc(sizeof(struct kadvice_channel_header));
}

/* kadvice_int_put 
 *
 */
struct ka_datum *ka_new_datum(int type)
{
  struct ka_datum *d = (struct ka_datum *)kmalloc(sizeof(struct ka_datum));
  if (d == NULL) {
    DBG_P("cannot allocate");
  }
  switch (type) {
  case D_INT:
    strcpy(d->typeinfo, "int");
    d->typeinfo[sizeof("int")] = "\0";
    break;
  case D_CHAR:
    strcpy(d->typeinfo, "char");
    d->typeinfo[sizeof("char")] = "\0";
    break;
  case D_STRING:
    strcpy(d->typeinfo, "string");
    d->typeinfo[sizeof("string")] = "\0";
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
  d->value = kmalloc(d->size);
  memcpy(d->value, n, d->size);
  /* insert datum list. */
  
  
}
EXPORT_SYMBOL(kadvice_int_put);

int kadvice_char_put(char c)
{
  struct ka_datum *d;
  d = ka_new_datum(D_CHAR);
  d->size = sizeof(char);
  d->value = kmalloc(d->size);
  memcpy(d->value, c, d->size);
  
  /* insert datum list */

}
EXPORT_SYMBOL(kadvice_char_put);


int kadvice_string_put(char* str)
{
  struct ka_datum *d;
  d = ka_new_datum(D_STRING);
  d->size = strlen(str) + 1;
  d->value = kmalloc(d->size);
  memcpy(d->value, str, d->size);
  
  /* insert datum list */

  
}
EXPORT_SYMBOL(kadvice_string_put);

static void ka_chanenel_pack()
{

}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei Nakata");
MODULE_DESCRIPTION("Kadvice io interface");
