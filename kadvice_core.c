#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "ka/secops.h"

#include <linux/security.h>
#include <linux/cred.h>

#include "ka_proc.h"
#include "ka_security_str_lsm.h"
#include "ka_def.h"

#include "ka/base.h"

unsigned long lsm_acc[LSMIDMAX + 1][AOIDMAX][FUNCMAX];

MODULE_LICENSE("GPL");
/*
static int ka_show1(struct seq_file *m, void *p){
  int n = (int)p-1;
  int i;
  seq_printf(m, "[%3d]", n);
  for(i = 0; i < 8; i++){
    if(lsm_acc[n][1][i] != NULL){
      void *ptr = (void *)lsm_acc[n][1][i];
      char symname[32];
      char modname[32];
      lookup_module_symbol_attrs((unsigned long)ptr, NULL, NULL, modname, symname);
      seq_printf(m, " %p:%s[%s]", ptr, symname, modname);
    }
  }
  seq_puts(m, "\n");
  return 0;
}
*/

#define KA_SHOW(aoid, acc, max)									\
  static int ka_show##aoid(struct seq_file *m, void *p){		\
    int n = (int)p-1;											\
    int i;														\
    seq_printf(m, "[%3d]", n);									\
    for(i = 0; i < max; i++){									\
      if((void *)acc[n][aoid][i] != NULL){						\
		void *ptr = (void *)lsm_acc[n][aoid][i];				\
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
#define CREATE_SEQ_OPS(aoid)							\
  static struct seq_operations lsmacc_seq_op##aoid = {	\
    .start = ka_start,									\
    .next = ka_next,									\
    .stop = ka_stop,									\
    .show = ka_show##aoid,								\
  };													\

#define CREATE_PROC_OPEN(aoid)											\
  static int lsmacc_proc_open##aoid(struct inode *inode, struct file *file) \
  {																		\
    return seq_open(file, &lsmacc_seq_op##aoid);						\
  }																		\

/* procfs handler */
#define CREATE_FILE_OPS(aoid)					\
  static struct file_operations lsmacc_file_ops##aoid = {	\
    .open = lsmacc_proc_open##aoid,							\
    .read = seq_read,										\
    .llseek = seq_lseek,									\
    .release = seq_release,									\
  };														\
  
#define CREATE_ENTRY(aoid, entry, parent)		\
  do{												\
    entry = create_proc_entry(#aoid, 0666, parent);	\
    if(entry)										\
      entry->proc_fops = &lsmacc_file_ops##aoid;	\
  }while(0)											\
	
#define REMOVE_ENTRY(aoid)				\
  do{									\
    remove_proc_entry(#aoid, NULL);		\
  }while(0)								\
	

#define CREATE_SEQ(aoid)			\
  CREATE_SEQ_OPS(aoid)				\
  CREATE_PROC_OPEN(aoid)			\
  CREATE_FILE_OPS(aoid)				\

static void *ka_start(struct seq_file *m, loff_t *pos){	
  loff_t n = *pos;						
  int i;							
  if(n == 0){							
    seq_printf(m, "%-35s", "## access control cube ## aoid");	
    seq_puts(m, "\n\n");					
  }								
  for(i = 0; lsm_acc[i][0] && lsm_security_str[i]; i++){		
    n--;							
    if(n < 0)							
      return (void *)(i + 1);					
  }								
  return 0;							
}								


static void *ka_next(struct seq_file *m, void *p, loff_t *pos){	
  int n = (int)p;						
  (*pos)++;							
  if(lsm_acc[n-1][0] && lsm_security_str[n-1]){				
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

//FUNC2(lsm_acc, int, file_permission, struct file *, file, int, mask);
//FUNC3(lsm_acc, int, inode_permission, struct inode *, inode, int, mask, struct nameidata *, nd);
//FUNC3(lsm_acc, int, socket_sendmsg, struct socket *, sock, struct msghdr *, msg, int, size);

/*
int ka_check_inode_permission(struct inode * inode, int mask, struct nameidata * nd)
{									
  struct cabi_account *cabi_ac;					
  int cabiid, i;								
  if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	
    return 0;					
  cabiid = cabi_ac->cabi_id;						
  int (*p)(struct inode *inode, int mask, struct nameidata *nd);
  for(i = 0; i < 8; i++){			
    if(lsm_acc[__KA_inode_permission][cabiid][i] != 0){
      int ret;
      printk("security check\n");
      p = (void *)lsm_acc[__KA_inode_permission][cabiid][i];
      if((ret = p(inode, mask, nd)) != 0)
	return ret;							
    }									
  }									
  return 0;								
}									
EXPORT_SYMBOL(ka_check_inode_permission);
*/

int kadvice_register_advice(int aoid, int lsmid, void *func, int priority){
  int i = priority;
  if(lsm_acc[lsmid][aoid][priority] == 0){
    lsm_acc[lsmid][aoid][priority] = (unsigned long)func;
     //    printk("register advice lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
    return 0;
  }
  for(i += 1; i < 8; i++){
    if(lsm_acc[lsmid][aoid][i] == 0){
      lsm_acc[lsmid][aoid][i] = (unsigned long)func;
      //printk("register advice lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
      return 0;
    }
  }
  return -1;
}

int kadvice_register_advice_over(int aoid, int lsmid, void *func, int priority){
  if(lsm_acc[lsmid][aoid][priority] == 0)
    return -1;
  lsm_acc[lsmid][aoid][priority] = (unsigned long)func;
  printk("register advice lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, priority, func);
  return 0;
}

int kadvice_unregister_advice(int aoid, int lsmid, void *func){
  int i;
  for(i = 0; i < 8; i++){
    if(lsm_acc[lsmid][aoid][i] == (unsigned long)func){
      lsm_acc[lsmid][aoid][i] = 0;
      printk("unregister advice %p", func);
      return 0;
    }
  }
  return -1;
}

int kadvice_unregister_advice_point(int aoid, int lsmid, int priority){
  lsm_acc[lsmid][aoid][priority] = 0;
  return 0;
}

int kadvice_clear_advice(int aoid, int lsmid){
  int i;
  for(i = 0; i < 8; i++){
    lsm_acc[lsmid][aoid][i] = 0;
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

EXPORT_SYMBOL(kadvice_register_advice);
EXPORT_SYMBOL(kadvice_unregister_advice);
EXPORT_SYMBOL(kadvice_clear_advice);

extern unsigned long kallsyms_lookup_name(const char *);

int ka_find_lsmid_from_str(char *name){
  int i;
  for(i = 0; i < LSMIDMAX && lsm_security_str[i]; i++){
    if(strcmp(lsm_security_str[i], name) == 0)
      return i;
  }
  return -1;
}


#define SET_QUERY(head, name, aoid, priority)		\
  struct ka_query *query_##name;			\
  query_##name->funcname = (##head_##name);		\
  query_##name->aoid = aoid;				\
  query_##name->priority = priority;			\
  query_##name->weavepoint = #name
  
#define POST(head, name, aoid, priority)	\
  SET_QUERY(head, name, aoid, priority);	\
  return kadvice_post_advice_str(query_##name)




int kadvice_post_advice(struct ka_query *query){
  int lsmid = ka_find_lsmid_from_str(query->weavepoint);
  if(lsmid < 0) {
    printk("cannot find lsm name :%s\n", query->weavepoint);
    return -1;
  }
  return kadvice_register_advice(query->aoid, lsmid, (void *)query->funcaddr, query->priority);
}
EXPORT_SYMBOL(kadvice_post_advice);


int kadvice_post_advice_str(struct ka_query *query){
  unsigned long addr;
  addr = kallsyms_lookup_name(query->funcname);
  if(addr == 0) {
    /* attempt to get address resolve from System.map */
    printk("cannot find funcname:%s\n", query->funcname);
    return -EFAULT;
  }
  query->funcaddr = addr;
  return kadvice_post_advice(query);
}
EXPORT_SYMBOL(kadvice_post_advice_str);


int kadvice_delete_advice(struct ka_query *query){
  int lsmid = ka_find_lsmid_from_str(query->weavepoint);
  if(lsmid < 0)
    return -1;
  return kadvice_unregister_advice_point(query->aoid, lsmid, query->priority);
}
EXPORT_SYMBOL(kadvice_delete_advice);

/*
int kadvice_delete_advice_str(struct ka_query *query){
  unsigned long addr;
  addr = kallsyms_lookup_name(query->funcname);
  if(addr == 0)
    return -ENOMEM;
  query->funcaddr = addr;
  return kadvice_delete_advice(query);
}
EXPORT_SYMBOL(kadvice_delete_advice_str);
*/

int kadvice_put_advice(struct ka_query *query){
  int lsmid = ka_find_lsmid_from_str(query->weavepoint);
  if(lsmid < 0)
    return -1;
  return kadvice_register_advice_over(query->aoid, lsmid, (void *)query->funcaddr, query->priority);
}
EXPORT_SYMBOL(kadvice_put_advice);


int kadvice_put_advice_str(struct ka_query *query){
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

int kadvice_post(char *head, char *name, int aoid, int priority){
  int ret;
  struct ka_query *query = (struct ka_query *)kmalloc(sizeof(struct ka_query), GFP_KERNEL);
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
  query->aoid = aoid;
  query->priority = priority;
  query->weavepoint = name;
  ret = kadvice_post_advice_str(query);
  //  printk("post %d\n",ret);
  kfree(query);
  kfree(funcname);
  return ret;
}
EXPORT_SYMBOL(kadvice_post);

/*
int kadvice_set_selinux(int aoid, int priority){
  int i = 0;
  while(lsm_security_str[i]){
    int ret = kadvice_post("selinux", lsm_security_str[i], 1, 1);
    if(!ret)
      return -1;
    i++;
  }
  return 0;
}
EXPORT_SYMBOL(kadvice_set_selinux);
*/

#include "func.c"
