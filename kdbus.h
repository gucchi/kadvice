
#ifndef __LINUX_SECURITY_KDBUS_
#define __LINUX_SECURITY_KDBUS_


#include <linux/security.h>


struct kdbus_operations {
  void *(*kdbus_get_task_cred_security)(struct cred *);
  void (*kdbus_set_task_cred_security)(struct cred *, void *value);
};

extern struct kdbus_operations *kdbus_ops;
extern int register_kdbus(struct kdbus_operations *ops);
extern int unregister_kdbus();


//extern void *kdbus_get_task_cred_security(struct cred *);
//extern void kdbus_set_task_cred_security(struct cred *, void *value);

#endif
