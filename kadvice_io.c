
/* 
 * Kadvice read interface
 * shinpei(c)ynu 2009
 *
 *
 *
 */

#include "kadvice_io.h"
#include <linux/kernel.h>
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
  return (struct ka_datum *)kmalloc(sizeof(struct ka_datum));
}

int kadvice_int_put(int n)
{
  struct kadvice_datum *d;
  d = ka_new_datum(D_INT);
  strcpy(d->typeinfo, "int");
  d->typeinfo[sizeof("int")] = "\0";
  d->
  
}
EXPORT_SYMBOL(kadvice_int_put);


int kadvice_char_put(char c)
{
  struct kadvice_datum *d;

}
EXPORT_SYMBOL(kadvice_char_put);


int kadvice_string_put(char* str)
{
  struct kadvice_datum *d = ka_new_datum();
}
EXPORT_SYMBOL(kadvice_string_put);

static void ka_chanenel_pack()
{

}



MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei Nakata");
MODULE_DESCRIPTION("Kadvice io interface");
