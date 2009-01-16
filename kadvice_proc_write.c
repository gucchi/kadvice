#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PROCNAME "kadvice"


extern void kadvice_put_advice_str(char *, char *, int, int, char *);


int ka_proc_write(struct file *file, const char *buffer, unsigned long count, void *data){
  char buf[128];
  char *method, *uri, *func, *acc, *weavepoint, *aoidp, *priorityp, *br;
  unsigned long len = count;
  int aoid, priority;
  if(len >= sizeof(buf))
    len = sizeof(buf) - 1;
  if(copy_from_user(buf, buffer, len))
    return -EFAULT;
  buf[len] = '\0';
  method = buf;
  uri = strstr(method, " ");
  if(!uri)
    return -EFAULT;
  *uri = '\0';
  uri++;
  func = strstr(uri, " ");
  if(!func)
    return -EFAULT;
  *func = '\0';
  func++;
  br = strstr(func, "\n");
  if(br){
    *br = '\0';
    printk("detected br\n");
  }
  printk("method:%s uri:%s func:%s\n", method, uri, func);
  
  acc = strstr(uri, "://");
  if(!acc)
    return -EFAULT;
  acc += 3;
  
  weavepoint = strstr(acc, "/");
  if(!weavepoint)
    return -EFAULT;
  *weavepoint = '\0';
  weavepoint++;
  aoidp = strstr(weavepoint, ".");
  if(!aoidp)
    return -EFAULT;
  *aoidp = '\0';
  aoidp++;
  priorityp = strstr(aoidp, ".");
  if(!priorityp)
    return -EFAULT;
  *priorityp = '\0';
  priorityp++;
  
  aoid = simple_strtol(aoidp, NULL, 10);
  priority = simple_strtol(priorityp, NULL, 10);
  printk("acc:%s weavepint:%s aoid:%d priority:%d\n", acc, weavepoint, aoid, priority);


  if(strcmp(method, "put") == 0){
    kadvice_put_advice_str(acc, weavepoint, aoid, priority, func);
  }
  return len;
}

static int ka_proc_init(void){
  struct proc_dir_entry *entry;
  entry = create_proc_entry(PROCNAME, 0666, NULL);
  if(entry == NULL){
    printk(KERN_WARNING "ka_proc: unable to create /proc entry\n");
    return -ENOMEM;
  }
  entry->write_proc = ka_proc_write;
  printk("ka_proc loaded\n");
  return 0;
}

static void ka_proc_exit(void){
  remove_proc_entry(PROCNAME, NULL);
  printk("ka_proc unloaded\n");
}

module_init(ka_proc_init);
module_exit(ka_proc_exit);
