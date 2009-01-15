#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include "ka_def.h"

extern unsigned int acm[32];
extern unsigned int lsm_acm[LSMACMMAX + 1];

int lsmacm_write(struct file *file, const char *buffer, unsigned long count, void *data){
  char buf[16];
  char *kaoid, *sec_ops, *action, *space;
  int n, kaoid_i, sec_ops_i, action_i;
  unsigned long len = count;
  if(len >= sizeof(buf))
    len = sizeof(buf) - 1;
  if(copy_from_user(buf, buffer, len))
    return -EFAULT;
  buf[len] = '\0';
  
  kaoid = buf;

  printk("line: %s\n", buf);

  space = strstr(kaoid, " ");
  if(space == NULL)
    return -EFAULT;
  *space = '\0';
  sec_ops = space + 1;
  space = strstr(sec_ops, " ");
  if(space == NULL)
    return -EFAULT;
  *space = '\0';
  action = space + 1;
    
  kaoid_i = simple_strtol(kaoid, NULL, 10);
  sec_ops_i = simple_strtol(sec_ops, NULL, 10);
  action_i = simple_strtol(action, NULL, 10);
  printk("acm %x \n", (1<<30) | acm[kaoid_i-1]);
  switch(action_i){
  case 0:
    printk("kaoid:%d secops[%d] off\n", kaoid_i, sec_ops_i);
    lsm_acm[sec_ops_i] &= ~acm[kaoid_i];
  case 1:
    printk("kaoid:%d secops[%d] on\n", kaoid_i, sec_ops_i);
    lsm_acm[sec_ops_i] |= acm[kaoid_i];
  }
  return (len);
}

int create_acmcontrol(){
  struct proc_dir_entry *entry;
  entry = create_proc_entry("acmcontrol", 0666, NULL);
  if(entry == NULL){
    printk(KERN_WARNING "acmcontrol: create error\n");
    return -ENOMEM;
  }
  entry->write_proc = lsmacm_write;
  return 0;
}
