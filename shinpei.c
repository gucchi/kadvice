#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>

//#include "kadvice_io.h"

MODULE_LICENSE("GPL");


extern int kadvice_string_put(char* str);
extern int kadvice_uri_put(char* uri);
extern int kadvice_send(void);


static int test_file_permission (struct file *file, int mask)
{

  kadvice_uri_put("test.k");
  kadvice_string_put((char*)file->f_dentry->d_name.name);
  kadvice_send();
  //  printk("%s", file->f_dentry->d_name.name);

  return 0;
}

struct security_operations my_security_ops = {
  .file_permission = test_file_permission,
};

static int test_init(void)
{
  register_security(&my_security_ops);
  return 0;
}

static void test_exit(void)
{
  unregister_security(&my_security_ops);
}

security_initcall(test_init);
module_exit(test_exit);
EXPORT_SYMBOL(my_security_ops);
