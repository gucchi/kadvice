#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "ka/kadvice_lsm.h"
#include "ka/secops.h"
#include "ka/ka_advice.h"

extern int kadvice_string_put(char *);
extern int kadvice_clear_func(unsigned long);

MODULE_LICENSE("GPL");

int sample_inode_permission(struct inode *inode, int mask, struct nameidata *nd){
  printk("sample advice\n");
  //kadvice_string_put("sample advice\n");
  return -1;	 
}

static int __init sample_init(void){
  printk("sample loaded\n");
  return 0;
}

static void __exit sample_exit(void){
  kadvice_clear_func((unsigned long)sample_inode_permission);
  printk("sample unloaded\n");
}

module_init(sample_init);
module_exit(sample_exit);
