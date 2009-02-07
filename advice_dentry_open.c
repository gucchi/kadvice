#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include "ka/kadvice_lsm.h"
#include "ka/secops.h"
#include "ka/ka_advice.h"

extern int kadvice_clear_func(unsigned long);

MODULE_LICENSE("GPL");

int log_dentry_open(struct file *file){
  printk("log:%s\n",(char*)file->f_dentry->d_name.name);
  return 0;
}

int sample_dentry_open(struct file *file){
  return -EPERM;
}

static int __init sample_init(void){
  printk("sample loaded\n");
  return 0;
}

static void __exit sample_exit(void){
  kadvice_clear_func((unsigned long)sample_dentry_open);
  kadvice_clear_func((unsigned long)log_dentry_open);
  printk("sample unloaded\n");
}

module_init(sample_init);
module_exit(sample_exit);
