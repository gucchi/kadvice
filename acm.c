#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/security.h>

#include <cabi/common.h>

#include "ka_proc.h"
#include "ka_secops_str.h"
#include "ka_def.h"
#include "ka/security_ops.h"
#include "ka/base.h"

unsigned long lsm_acm[LSMIDMAX + 1][AOIDMAX][FUNCMAX];

MODULE_LICENSE("GPL");


/*
static int ka_show1(struct seq_file *m, void *p){
  int n = (int)p-1;
  int i;
  seq_printf(m, "[%3d]", n);
  for(i = 0; i < 8; i++){
    if(lsm_acm[n][1][i] != NULL){
      void *ptr = (void *)lsm_acm[n][1][i];
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


#define KA_SHOW(aoid, acc, max)						\
  static int ka_show##aoid(struct seq_file *m, void *p){		\
    int n = (int)p-1;							\
    int i;								\
    seq_printf(m, "[%3d]", n);						\
    for(i = 0; i < max; i++){						\
      if((void *)acc[n][aoid][i] != NULL){				\
	void *ptr = (void *)lsm_acm[n][aoid][i];			\
	char symname[32];						\
	char modname[32];						\
	lookup_module_symbol_attrs((unsigned long)ptr, NULL, NULL, modname, symname); \
	seq_printf(m, " %p:%s[%s] [%d]", ptr, symname, modname, i);	\
      }									\
    }									\
    seq_puts(m, "\n");							\
    return 0;								\
  }									\


/* seq_file handler */
#define CREATE_SEQ_OPS(aoid)				\
  static struct seq_operations lsmacc_seq_op##aoid = {	\
    .start = ka_start,					\
    .next = ka_next,					\
    .stop = ka_stop,					\
    .show = ka_show##aoid,				\
  };							\

#define CREATE_PROC_OPEN(aoid)						\
  static int lsmacc_proc_open##aoid(struct inode *inode, struct file *file) \
  {									\
    return seq_open(file, &lsmacc_seq_op##aoid);			\
  }									\

/* procfs handler */
#define CREATE_FILE_OPS(aoid)					\
  static struct file_operations lsmacc_file_ops##aoid = {	\
    .open = lsmacc_proc_open##aoid,				\
    .read = seq_read,						\
    .llseek = seq_lseek,					\
    .release = seq_release,					\
  };								\

#define CREATE_ENTRY(aoid, entry, parent)		\
  do{							\
    entry = create_proc_entry(#aoid, 0666, parent);	\
    if(entry)						\
      entry->proc_fops = &lsmacc_file_ops##aoid;	\
  }while(0)						\

#define REMOVE_ENTRY(aoid)			\
  do{						\
    remove_proc_entry(#aoid, NULL);		\
  }while(0)					\


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
  for(i = 0; lsm_acm[i][0] && secops_str[i]; i++){		
    n--;							
    if(n < 0)							
      return (void *)(i + 1);					
  }								
  return 0;							
}								


static void *ka_next(struct seq_file *m, void *p, loff_t *pos){	
  int n = (int)p;						
  (*pos)++;							
  if(lsm_acm[n-1][0] && secops_str[n-1]){				
    return (void *)(n + 1);					
  }								
  return 0;							
}								




KA_SHOW(1, lsm_acm, FUNCMAX)
//KA_SHOW(2)
//KA_SHOW(3)

static void ka_stop(struct seq_file *m, void *p){
  seq_puts(m, "\n");
}

CREATE_SEQ(1)
//CREATE_SEQ(2)
//CREATE_SEQ(3)

static int lsmacc_module_init(void)
{
  struct proc_dir_entry *parent, *entry;
  parent = proc_mkdir("ka", NULL);

  CREATE_ENTRY(1, entry, parent);
  //CREATE_ENTRY(2, entry, parent);
  //CREATE_ENTRY(3, entry, parent);

  printk("driver loaded\n");
  return 0;
}

static void lsmacc_module_exit(void)
{
  REMOVE_ENTRY(1);
  //REMOVE_ENTRY(2);
  //REMOVE_ENTRY(3);
  printk(KERN_ALERT "driver unloaded\n");
}

module_init(lsmacc_module_init);
module_exit(lsmacc_module_exit);

FUNC2(lsm_acm, int, file_permission, struct file *, file, int, mask);
FUNC3(lsm_acm, int, inode_permission, struct inode *, inode, int, mask, struct nameidata *, nd);
FUNC3(lsm_acm, int, socket_sendmsg, struct socket *, sock, struct msghdr *, msg, int, size);

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
    if(lsm_acm[__KA_inode_permission][cabiid][i] != 0){
      int ret;
      printk("security check\n");
      p = (void *)lsm_acm[__KA_inode_permission][cabiid][i];
      if((ret = p(inode, mask, nd)) != 0)
	return ret;							
    }									
  }									
  return 0;								
}									
EXPORT_SYMBOL(ka_check_inode_permission);
*/

int addhook(int aoid, int lsmid, void *func, int priority){
  int i = priority;
  if(lsm_acm[lsmid][aoid][priority] == 0){
    lsm_acm[lsmid][aoid][priority] = (unsigned long)func;
    printk("addhook lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
    return 0;
  }
  for(i += 1; i < 8; i++){
    if(lsm_acm[lsmid][aoid][i] == 0){
      lsm_acm[lsmid][aoid][i] = (unsigned long)func;
      printk("addhook lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
      return 0;
    }
  }
  
  return -1;
  
  return 0;
}

int rmhook(int aoid, int lsmid, void *func){
  int i;
  for(i = 0; i < 8; i++){
    if(lsm_acm[lsmid][aoid][i] == (unsigned long)func){
      lsm_acm[lsmid][aoid][i] = 0;
      printk("remove hook %p", func);
    }
  }
  return 0;
}

int clearhook(int aoid, int lsmid){
  int i;
  for(i = 0; i < 8; i++){
    lsm_acm[lsmid][aoid][i] = 0;
  }
  printk("addhook clear\n");
  return 0;
}

unsigned long *checkhook(int aoid, int lsmid){
  int i;
  unsigned long *p = NULL;
  for(i = 0; i < 8; i++){
    if((*p = lsm_acm[lsmid][aoid][i]))
      p++;
  }
  return p;
}


EXPORT_SYMBOL(addhook);
EXPORT_SYMBOL(clearhook);
EXPORT_SYMBOL(rmhook);
EXPORT_SYMBOL(checkhook);
