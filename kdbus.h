
#ifndef __LINUX_SECURITY_KDBUS_
#define __LINUX_SECURITY_KDBUS_


#include <linux/security.h>
extern void *kdbus_get_task_cred_security(struct cred *);


#endif
