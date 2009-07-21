#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>

//MODULE_LISENCE("GPL");
//MODULE_AUTHOR("Shinpei NAKATA");


void *kdbus_get_task_cred_security(struct cred *locred)
{
  return locred->security;
}
EXPORT_SYMBOL(kdbus_get_task_cred_security);

/*
void kdbus_set_task_cred_security(struct cred *locred, 
				 void *value)
{
  printk("set cred->security to %p\n", value);
  locred->security = value;
  //  return 0;
}
EXPORT_SYMBOL(kdbus_set_task_cred_security);
*/

/*
int kdbus_init(void)
{
  
  printk("kdbus inserted");
}

void kdbus_exit(void)
{
  
}

module_init(kdbus_init);
module_exit(kdbus_exit);

*/
