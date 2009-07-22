#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
//#include "ka/secops.h"

#include <linux/security.h>
#include <linux/cred.h>


#include "ka/base.h"
#include "ka_def.h"
#include "sc_lsm_strdef.h"
#include "scube.h"

long lsm_acc[LSMIDMAX + 1][AOIDMAX][FUNCMAX];

MODULE_LICENSE("GPL");

#define KA_SHOW(gid, acc, max)									\
  static int ka_show##gid(struct seq_file *m, void *p){		\
    int n = (int)p-1;											\
    int i;														\
    seq_printf(m, "[%3d]", n);									\
    for(i = 0; i < max; i++){									\
      if((void *)acc[n][gid][i] != NULL){						\
		void *ptr = (void *)lsm_acc[n][gid][i];				\
		char symname[32];										\
		char modname[32];												\
		lookup_module_symbol_attrs((unsigned long)ptr, NULL, NULL, modname, symname); \
		seq_printf(m, " %p:%s[%s] [%d]", ptr, symname, modname, i);		\
      }																	\
    }																	\
    seq_puts(m, "\n");													\
    return 0;															\
  }																		\

/* seq_file handler */
#define CREATE_SEQ_OPS(gid)							\
  static struct seq_operations lsmacc_seq_op##gid = {	\
    .start = ka_start,									\
    .next = ka_next,									\
    .stop = ka_stop,									\
    .show = ka_show##gid,								\
  };													\

#define CREATE_PROC_OPEN(gid)											\
  static int lsmacc_proc_open##gid(struct inode *inode, struct file *file) \
  {																		\
    return seq_open(file, &lsmacc_seq_op##gid);						\
  }																		\

/* procfs handler */
#define CREATE_FILE_OPS(gid)					\
  static struct file_operations lsmacc_file_ops##gid = {	\
    .open = lsmacc_proc_open##gid,							\
    .read = seq_read,										\
    .llseek = seq_lseek,									\
    .release = seq_release,									\
  };														\
  
#define CREATE_ENTRY(gid, entry, parent)		\
  do{												\
    entry = create_proc_entry(#gid, 0666, parent);	\
    if(entry)										\
      entry->proc_fops = &lsmacc_file_ops##gid;	\
  }while(0)											\
	
#define REMOVE_ENTRY(gid)				\
  do{									\
    remove_proc_entry(#gid, NULL);		\
  }while(0)								\
	

#define CREATE_SEQ(gid)			\
  CREATE_SEQ_OPS(gid)				\
  CREATE_PROC_OPEN(gid)			\
  CREATE_FILE_OPS(gid)				\


static void *ka_start(struct seq_file *m, loff_t *pos){	
  loff_t n = *pos;						
  int i;							
  if(n == 0){							
    seq_printf(m, "%-35s", "## access control cube ## gid");	
    seq_puts(m, "\n\n");					
  }								
  for(i = 0; lsm_acc[i][0]; i++){		
    n--;							
    if(n < 0)							
      return (void *)(i + 1);					
  }								
  return 0;							
}								


static void *ka_next(struct seq_file *m, void *p, loff_t *pos){	
  int n = (int)p;						
  (*pos)++;							
  if(lsm_acc[n-1][0]){				
    return (void *)(n + 1);					
  }								
  return 0;							
}								

KA_SHOW(0, lsm_acc, FUNCMAX)
KA_SHOW(1, lsm_acc, FUNCMAX)
//KA_SHOW(2)
//KA_SHOW(3)

static void ka_stop(struct seq_file *m, void *p){
  seq_puts(m, "\n");
}

CREATE_SEQ(0)
CREATE_SEQ(1)
//CREATE_SEQ(2)
//CREATE_SEQ(3)

static int lsmacc_module_init(void)
{
  struct proc_dir_entry *parent, *entry;
  parent = proc_mkdir("ka", NULL);

  CREATE_ENTRY(0, entry, parent);
  CREATE_ENTRY(1, entry, parent);
  //CREATE_ENTRY(2, entry, parent);
  //CREATE_ENTRY(3, entry, parent);

  printk("driver loaded\n");
  return 0;
}

static void lsmacc_module_exit(void)
{
  REMOVE_ENTRY(0);
  REMOVE_ENTRY(1);
  //REMOVE_ENTRY(2);
  //REMOVE_ENTRY(3);
  printk(KERN_ALERT "driver unloaded\n");
}

module_init(lsmacc_module_init);
module_exit(lsmacc_module_exit);



int scube_register_function(int gid, int lsmid, void *func, int priority){
  int i = priority;
  if(lsm_acc[lsmid][gid][priority] == 0){
    lsm_acc[lsmid][gid][priority] = (unsigned long)func;
    printk("register function lsmid:%d gid:%d [%d] %p\n", lsmid, gid, i, func);
    return 0;
  }
  /*  for(i += 1; i < 8; i++){
    if(lsm_acc[lsmid][gid][i] == 0){
      lsm_acc[lsmid][gid][i] = (unsigned long)func;
      //printk("register advice lsmid:%d gid:%d [%d] %p\n", lsmid, gid, i, func);
      return 0;
    }
    }*/

  return -1;
}

int kadvice_register_advice_over(int gid, int lsmid, void *func, int priority){
  if(lsm_acc[lsmid][gid][priority] == 0)
    return -1;
  lsm_acc[lsmid][gid][priority] = (unsigned long)func;
  printk("register advice lsmid:%d gid:%d [%d] %p\n", lsmid, gid, priority, func);
  return 0;
}

int kadvice_unregister_advice(int gid, int lsmid, void *func){
  int i;
  for(i = 0; i < 8; i++){
    if(lsm_acc[lsmid][gid][i] == (unsigned long)func){
      lsm_acc[lsmid][gid][i] = 0;
      printk("unregister advice %p", func);
      return 0;
    }
  }
  return -1;
}

int kadvice_unregister_advice_point(int gid, int lsmid, int priority){
  lsm_acc[lsmid][gid][priority] = 0;
  return 0;
}

int kadvice_clear_advice(int gid, int lsmid){
  int i;
  for(i = 0; i < 8; i++){
    lsm_acc[lsmid][gid][i] = 0;
  }
  printk("advice cleared\n");
  return 0;
}

int kadvice_clear_func(unsigned long addr){
  int i, j, k;
  for(i = 0; i < LSMIDMAX; i++){
    for(j = 0; j < AOIDMAX; j++){
      for(k = 0; k < FUNCMAX; k++){
	if(lsm_acc[i][j][k] == addr){
	  lsm_acc[i][j][k] = 0;
	}
      }
    }
  }
  return 0;
}
EXPORT_SYMBOL(kadvice_clear_func);

EXPORT_SYMBOL(scube_register_function);
EXPORT_SYMBOL(kadvice_unregister_advice);
EXPORT_SYMBOL(kadvice_clear_advice);

extern unsigned long kallsyms_lookup_name(const char *);


int sc_find_lsmid_from_str(char *name){
  int i;
  for(i = 0; i < LSMIDMAX; i++){
    if(strcmp(sc_security_str[i], name) == 0)
      return i;
  }
  return -1;
}


#define SET_QUERY(head, name, gid, priority)		\
  struct sc_query *query_##name;			\
  query_##name->funcname = (##head_##name);		\
  query_##name->gid = gid;				\
  query_##name->priority = priority;			\
  query_##name->hookpoint = #name
  
#define POST(head, name, gid, priority)	\
  SET_QUERY(head, name, gid, priority);	\
  return kadvice_post_advice_str(query_##name)




int scube_post_query(struct sc_query *query){
  int lsmid = sc_find_lsmid_from_str(query->hookpoint);
  if(lsmid < 0) {
    printk("cannot find lsm name :%s\n", query->hookpoint);
    return -1;
  }
  return scube_register_function(query->gid, lsmid, (void *)query->funcaddr, query->priority);
}
EXPORT_SYMBOL(scube_post_query);


int scube_post_query_str(struct sc_query *query){
  unsigned long addr;
  addr = kallsyms_lookup_name(query->funcname);
  if(addr == 0) {
    /* attempt to get address resolve from System.map */
    printk("cannot find funcname:%s\n", query->funcname);
    return -EFAULT;
  }
  query->funcaddr = addr;
  return scube_post_query(query);
}
EXPORT_SYMBOL(scube_post_query_str);


int kadvice_delete_advice(struct sc_query *query){
  int lsmid = sc_find_lsmid_from_str(query->hookpoint);
  if(lsmid < 0)
    return -1;
  return kadvice_unregister_advice_point(query->gid, lsmid, query->priority);
}
EXPORT_SYMBOL(kadvice_delete_advice);

/*
int kadvice_delete_advice_str(struct sc_query *query){
  unsigned long addr;
  addr = kallsyms_lookup_name(query->funcname);
  if(addr == 0)
    return -ENOMEM;
  query->funcaddr = addr;
  return kadvice_delete_advice(query);
}
EXPORT_SYMBOL(kadvice_delete_advice_str);
*/

int kadvice_put_advice(struct sc_query *query){
  int lsmid = sc_find_lsmid_from_str(query->hookpoint);
  if(lsmid < 0)
    return -1;
  return kadvice_register_advice_over(query->gid, lsmid, (void *)query->funcaddr, query->priority);
}
EXPORT_SYMBOL(kadvice_put_advice);


int kadvice_put_advice_str(struct sc_query *query){
  unsigned long addr;
  addr = kallsyms_lookup_name(query->funcname);
  if(addr == 0){
    printk("error \n");
    return -ENOMEM;
  }
  query->funcaddr = addr;
  return kadvice_put_advice(query);
}
EXPORT_SYMBOL(kadvice_put_advice_str);

int kadvice_post(char *head, char *name, int gid, int priority){
  int ret;
  struct sc_query *query = (struct sc_query *)kmalloc(sizeof(struct sc_query), GFP_KERNEL);
  int namelen = strlen(head) + strlen(name) + 1;
  char *funcname = (char *)kmalloc(namelen + 1, GFP_KERNEL);
  memset(funcname, 0, namelen + 1);
  //  printk("namelen %d head %d name %d\n",namelen, strlen(head), strlen(name));
  strncpy(funcname, head, strlen(head));
  strncat(funcname, "_", 1);
  strncat(funcname, name, strlen(name));
  funcname[namelen] = '\0';
  //  printk("func %s\n",funcname);
  query->funcname = funcname;
  query->gid = gid;
  query->priority = priority;
  query->hookpoint = name;
  ret = scube_post_query_str(query);
  //  printk("post %d\n",ret);
  kfree(query);
  kfree(funcname);
  return ret;
}
EXPORT_SYMBOL(kadvice_post);


/* alloc security */

struct scube_security *scube_alloc_security()
{
  struct scube_security *ret;
  ret = (struct scube_security *)kzalloc(sizeof(struct scube_security), GFP_KERNEL);
  if (!ret)
    return -ENOMEM;

  return ret;
}
EXPORT_SYMBOL(scube_alloc_security);



#include "func.c"
