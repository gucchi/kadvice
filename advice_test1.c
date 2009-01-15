#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "ka/ka.h"
#include "ka/secops.h"

MODULE_LICENSE("GPL");

extern int addhook(int, int, void *, int);
extern int clearhook(int, int);
extern int rmhook(int, int, void *);

int hook_inode_permission(struct inode *inode, int mask, struct nameidata *nd){
    return -1;
}

int hook_file_permission(struct file *file, int mask){
  const unsigned char *name = file->f_dentry->d_name.name;
  printk("file name:%s\n", name);
  return 0;
}

static int __init inshook_init(void){
  addhook(1, __KA_inode_permission, &hook_inode_permission, 1);
  addhook(1, __KA_file_permission, &hook_file_permission, 1);
  return 0;
}

static void __exit inshook_exit(void){
  rmhook(1, __KA_file_permission, &hook_file_permission);
  rmhook(1, __KA_inode_permission, &hook_inode_permission);
}

module_init(inshook_init);
module_exit(inshook_exit);
