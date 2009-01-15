#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include "ka/ka.h"

MODULE_LICENSE("GPL");

extern struct security_operations test_security_ops;
extern struct security_operations dummy_security_ops;

static int test_inode_permission(struct inode *inode, int mask){
  printk("test inode\n");
  int ret = ka_check_inode_permission(inode,mask);
  return ret;
}

struct security_operations addsecops={
  .inode_permission = test_inode_permission,
};


static int __init test_init(void){
  //printk("secops %x testsecops %x\n",security_ops,test_security_ops);
  int addr = test_security_ops.inode_mkdir;
  //printk("sec_inode %x testsec_inode %x\n",security_ops.inode_permission, test_security_ops);
  //addsecops = security_ops;
  //addsecops.inode_permission = test_inode_permission;
  //unregister_security(&security_ops);
  //register_security(&addsecops);
  test_security_ops.inode_permission = test_inode_permission;
  printk("additional lsm\n inode_mkdir:%x\n",addr);
  return 0;
}

static void __exit test_exit(void){ 
  //unregister_security(&addsecops);
  test_security_ops.inode_permission = dummy_security_ops.inode_permission;
}
security_initcall(test_init);
module_exit(test_exit);
