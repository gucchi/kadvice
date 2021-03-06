#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "ka_def.h"

#define PROCNAME "kadvice"

MODULE_LICENSE("GPL");

extern int kadvice_put_advice_str(struct sc_query *);
extern int kadvice_post_advice_str(struct sc_query *);
extern int kadvice_delete_advice(struct sc_query *);


// echo "post http://localhost/1.1.1 hookpoint" > /proc/kadvice
int ka_parse_uri(char *uri, struct sc_query *query){
  char *acc, *hookpoint, *gidp, *priorityp;
  int gid, priority;
  acc = strstr(uri, "://");
  if(!acc)
    return -1;
  acc += 3;
  hookpoint = strstr(acc, "/");
  // http://localhost/(*.*.*)->hookpoint
  if(!hookpoint)
    return -1;
  *hookpoint = '\0';
  hookpoint++;
  gidp = strstr(hookpoint, ".");
  if(!gidp)
    return -1;
  *gidp = '\0';
  gidp++;
  priorityp = strstr(gidp, ".");
  if(!priorityp)
    return -1;
  *priorityp = '\0';
  priorityp++;

  gid = simple_strtol(gidp, NULL, 10);
  priority = simple_strtol(priorityp, NULL, 10);
  printk("acc:%s weavepint:%s gid:%d priority:%d\n", acc, hookpoint, gid, priority);

  query->acc = acc;
  query->hookpoint = hookpoint;
  query->gid = gid;
  query->priority = priority;

  return 0;
}

int ka_proc_write(struct file *file, const char *buffer, unsigned long count, void *data){
  char buf[128];
  char *method, *uri, *funcname, *br;
  struct sc_query *query = (struct sc_query *)kmalloc(sizeof(struct sc_query), GFP_KERNEL);
  unsigned long len = count;
  int ret = -1;
  if(len >= sizeof(buf))
    len = sizeof(buf) - 1;
  if(copy_from_user(buf, buffer, len)) {
    printk("cannot copy from user\n");
    goto err;
  }
  buf[len] = '\0';
  //  printk("%s\n", buf);
  method = buf;
  uri = strstr(method, " ");
  if(!uri)
    goto err;
  *uri = '\0';
  uri++;

  if(strcmp(method, "delete") == 0){
    br = strstr(uri, "\n");
    if(br)
      *br = '\0';
    if(ka_parse_uri(uri, query)) {
      //      printk("cannot parse\n");
      goto err;
    }
    //printk("method:%s uri:%s\n", method, uri);
    ret = kadvice_delete_advice(query);
  }else{
     funcname = strstr(uri, " ");
     if(!funcname){
       //       printk("cannot parse2\n");
      goto err;

     }
    *funcname = '\0';
    funcname++;
    br = strstr(funcname, "\n");
    if(br)
      *br = '\0';
    query->funcname = funcname;
  
    if(ka_parse_uri(uri, query)) {
      printk("cannot parse3\n");
      goto err;
    }
    printk("method:%s uri:%s funcname:%s\n", method, uri, funcname);
       
    if(strcmp(method, "post") == 0){
      ret = kadvice_post_advice_str(query);
    }else if(strcmp(method, "put") == 0){
      ret = kadvice_put_advice_str(query);
    }
  }
  kfree(query);
  if(ret != 0)
    return ret;
  return len;

 err:
  kfree(query);
  printk("ERROR!!\n");
  return -EFAULT;
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
