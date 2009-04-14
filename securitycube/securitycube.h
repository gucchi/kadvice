#ifndef __SECURITYCUBE_H
#define __SECURITYCUBE_H

#include <linux/sched.h>

#define MODEL_MAX 8

struct sc_task_security {
  int gid;
  void *label[MODEL_MAX];
};

struct sc_inode_security {
  //  int gid;
  void *label[MODEL_MAX];
};


#endif /* __SECURITYCUBE_H */
