#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "ka/kadvice_lsm.h"
#include "ka/secops.h"
#include "ka/ka_advice.h"

MODULE_LICENSE("GPL");

int hook_inode_permission(struct inode *inode, int mask, struct nameidata *nd){
  printk("test1\n");
    return -1;
}

int hook_file_permission(struct file *file, int mask){
  const unsigned char *name = file->f_dentry->d_name.name;
  printk("file name:%s\n", name);
  return 0;
}

static int __init inshook_init(void){
  //kadvice_register_advice(1, __KA_inode_permission, &hook_inode_permission, 1);
  //kadvice_register_advice(1, __KA_file_permission, &hook_file_permission, 1);
  return 0;
}

static void __exit inshook_exit(void){
  //kadvice_unregister_advice(1, __KA_file_permission, &hook_file_permission);
  //kadvice_unregister_advice(1, __KA_inode_permission, &hook_inode_permission);
}

module_init(inshook_init);
module_exit(inshook_exit);
