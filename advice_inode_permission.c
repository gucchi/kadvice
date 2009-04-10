#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "ka/kadvice_lsm.h"
#include "ka/secops.h"
#include "ka/ka_advice.h"

//#include "ka/resources.h"

struct ka_sample_isec {
  int permission;
};

extern int kadvice_string_put(char *);
extern int kadvice_clear_func(unsigned long);

MODULE_LICENSE("GPL");

/*
int sample_inode_permission(struct inode *inode, int mask, struct nameidata *nd){
  struct ka_sample_isec *isec;
  isec = inode->i_security;

  if (isec != NULL) {
    if (isec->permission) {
      printk("security OK!\n");
      return 0;
    }
  }
  return 0;
}
*/
/*
int sample_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
  printk("dir num%d %p\n", dir->i_ino, dir->i_security);
  struct ka_sample_isec *isec;
  if (dir->i_security == NULL) {
    isec = (struct ka_sample_isec *)
      kmalloc(sizeof(struct ka_sample_isec), GFP_KERNEL);
    dir->i_security = (void *)isec;
    isec->permission = 1;
  }
  return 0;
}
*/
int sample_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
  struct ka_sample_isec *isec;
  //  printk("shinpei!!\n");
  isec = dir->i_security;
  if (isec != NULL) {
    printk("security %p\n", isec);
  }
  return 0;
}

int sample_inode_rename(struct inode *old_dir, struct dentry * old_dentry, struct inode *new_dir, struct dentry * new_dentry)
{
  struct ka_sample_isec *isec;
  printk("rename:%s %p\n", old_dentry->d_name.name, old_dentry->d_inode->i_security);
  isec = old_dentry->d_inode->i_security;
  if (isec != NULL) {
    printk("security %p %d\n", isec, isec->permission);
    isec->permission = 1;
    return 0;
  }
  return 1;
}

int sample_inode_alloc_security(struct inode *inode)
{
  struct ka_sample_isec *isec;
  if (inode->i_security == NULL) {
    isec = (struct ka_sample_isec *)
      kmalloc(sizeof(struct ka_sample_isec), GFP_KERNEL);
    if (!isec)
      return -ENOMEM;
    isec->permission = 1;
    inode->i_security = isec;
  }
  return 0;
}

static int __init sample_init(void){
  //set inode-label

  return 0;
}

static void __exit sample_exit(void){
  
  printk("sample unloaded\n");
}

module_init(sample_init);
module_exit(sample_exit);
