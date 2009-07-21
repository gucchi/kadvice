#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include "kdbus.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei NAKATA");


struct kdbus_operations *kdbus_ops;

static void *default_get_task_cred_security(struct cred *locred)
{
  return locred->security;
}

static void default_set_task_cred_security(struct cred *locred,
					   void * value)
{
  /* should not inline this function */
  locred->security = value;
}

void *kdbus_get_task_cred_security(struct cred *locred)
{
  return kdbus_ops->kdbus_get_task_cred_security(locred);
  //  return locred->security;
}
EXPORT_SYMBOL(kdbus_get_task_cred_security);


static struct kdbus_operations default_kdbus_ops = 
{
  .kdbus_get_task_cred_security = default_get_task_cred_security,
  .kdbus_set_task_cred_security = default_set_task_cred_security,
};

int register_kdbus(struct kdbus_operations *ops)
{

  /* if ops is null, setup with default security */
  if (!ops) {
    kdbus_ops = &default_kdbus_ops;
    printk("success to register default ops\n");
    return 0;
  }
  if (kdbus_ops != &default_kdbus_ops)
    printk("error!\n");

  kdbus_ops = ops;

  return 0;
}
EXPORT_SYMBOL(register_kdbus);


int unregister_kdbus(void)
{
  kdbus_ops = &default_kdbus_ops;
  return 0;
}
EXPORT_SYMBOL(unregister_kdbus);


int kdbus_init(void)
{
  //  register_kdbus(&default_kdbus_ops);
  printk("kdbus inserted\n");
}


module_init(kdbus_init);



