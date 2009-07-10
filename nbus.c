#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include <asm-generic/bug.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei Nakata");

void *nbus_get_inode_security(struct inode *inode)
{
  WARN_ON(inode);
  return inode->i_security;
}
EXPORT_SYMBOL(nbus_get_inode_security);


void *nbus_get_task_security(struct task_struct *task)
{
  WARN_ON(task);
  return task->cred->security;
}
EXPORT_SYMBOL(nbus_get_task_security);


static int __init nbus_init (void)
{
  printk(KERN_INFO "module nbus inserted");
  return 0;
}


module_init(nbus_init);

