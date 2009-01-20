#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <cabi/common.h>
#include "ka/kadvice_lsm.h"

MODULE_LICENSE("GPL");

static int test_inode_permission(struct inode *inode, int mask, struct nameidata *nd){
  struct cabi_account *cabi;
  int ret = 0;
  if((cabi = (struct cabi_account *)(current->cabi_info)))
    ret = ka_check_inode_permission(inode, mask, nd, cabi);
  return ret;
}
/*
static int test_file_permission(struct file *file, int mask){
  struct cabi_account *cabi;
  int ret = 0;
  if(cabi = (struct cabi_account *)(current->cabi_info))
    ret = ka_check_file_permission(file, mask, cabi);
  return ret;
}
*/

struct security_operations addhookbase_security_ops = {
  .inode_permission = test_inode_permission,
  //  .file_permission = test_file_permission,
};


static int __init addhookbase_init(void){
  if(register_security(&addhookbase_security_ops)){
    printk(KERN_INFO "failure register\n");
  }
  printk(KERN_INFO "addhookbase module init\n");
  return 0;
}


static void __exit addhookbase_exit(void){
  if(unregister_security(&addhookbase_security_ops)){
    printk(KERN_INFO "failure unregister\n");
  }
  printk(KERN_INFO "addhookbase module remove\n");
}

security_initcall(addhookbase_init);
module_exit(addhookbase_exit);
EXPORT_SYMBOL(addhookbase_security_ops);
