#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "securitycube.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei Nakata");
MODULE_DESCRIPTION("SecurityCube File Interface");

#define PROCNAME "scube"


static
struct sc_task_security *sc_alloc_new_task_security(void)
{
  struct sc_task_security *tsec = NULL;
  tsec = (struct sc_task_security *)
    kmalloc(sizeof(struct sc_task_security), GFP_KERNEL);
  return tsec;
}

static
int sc_proc_write(struct file *file, const char *buffer, 
		  unsigned long count, void *data)
{
  char buf[128];
  unsigned long len = count;
  struct task_struct *tp = NULL;
  int pid = 0;
  /* aviod buffer overrun */
  if (len >= sizeof(buf))
    len = sizeof(buf) - 1;
  /* copy from user */
  if (copy_from_user(buf, buffer, len)) {
    printk("cannot copy from user");
    goto err;
  }
  buf[len] = '\0';
  pid = simple_strtol(buf, &buf,10);
  printk("pid is :%d\n", pid);
  
  if ((tp = find_task_by_pid(pid)) == NULL) {
    printk("cannot find pid = %d\n", pid);
    goto err;
  }
  
  /* find appropriate task_struct for pid */
  struct sc_task_security *tsec;
  printk("task struct is %p\n", tp);
  if (tp->security == NULL) {
    if ((tsec = sc_alloc_new_task_security()) == NULL) {
      printk("cannot alloc new struct\n");
      return -ENOMEM;
    }
    tsec->gid = 1;
    tp->security = tsec;
  } else {
    /* its already alloced */
    tsec = (struct sc_task_security *)(tp->security);
    printk("group id for %d is %d\n", pid, tsec->gid);
  }

  return len;
 err:
  return len;
}

int sc_init(void)
{
  struct proc_dir_entry *entry;
  entry = create_proc_entry(PROCNAME, 0666, NULL);
  if (entry == NULL) {
    printk(KERN_INFO "scube_proc:unable to create\n");
    return -ENOMEM;
  }
  entry->write_proc = sc_proc_write;
  return 0;
}

void sc_exit(void)
{
  remove_proc_entry(PROCNAME, NULL);
  
}

module_init(sc_init);
module_exit(sc_exit);

