#include <linux/moduel.h>
#include <linux/kernel.h>
#include <linux/security.h>

#include "kadvice_io.h"




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
int kadvice_int_put(int n)
{
  struct kadvice_datum *d;
  
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
