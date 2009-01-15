#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "ka_proc.h"
#include "ka_secops_str.h"


MODULE_LICENSE("GPL");

#define PROCNAME "allsecop"


#define KA_SHOW(aoid)							\
  static int ka_show##aoid(struct seq_file *m, void *p){		\
    int n = (int)p-1;							\
    int i;								\
    seq_printf(m, "[%3d]", n);						\
    for(i = 0; i < 8; i++){						\
      if(lsm_acm[n][aoid][i] != NULL){					\
	void *ptr = (void *)lsm_acm[n][aoid][i];			\
	char symname[32];						\
	char modname[32];						\
	lookup_module_symbol_attrs((unsigned long)ptr, NULL, NULL, modname, symname); \
	seq_printf(m, " %p:%s[%s]", ptr, symname, modname);		\
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
    return seq_open(file, &lsmacc_seq_op##aoid);				\
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

#define CREATE_SEQ(aoid)			\
  CREATE_SEQ_OPS(aoid)				\
  CREATE_PROC_OPEN(aoid)			\
  CREATE_FILE_OPS(aoid)				\



extern int lookup_module_symbol_name(unsigned long, char *);
extern int lookup_module_symbol_attrs(unsigned long, unsigned long *, unsigned long *, char *, char *);

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

KA_SHOW(1)
KA_SHOW(2)
KA_SHOW(3)

static void ka_stop(struct seq_file *m, void *p){
  seq_puts(m, "\n");
}

CREATE_SEQ(1)
CREATE_SEQ(2)
CREATE_SEQ(3)


static int lsmacc_module_init(void)
{
  struct proc_dir_entry *parent, *entry;
  parent = proc_mkdir("ka", NULL);

  CREATE_ENTRY(1, entry, parent);
  CREATE_ENTRY(2, entry, parent);
  CREATE_ENTRY(3, entry, parent);

  printk("driver loaded\n");
  return 0;
}

static void lsmacc_module_exit(void)
{
  remove_proc_entry(PROCNAME, NULL);
  printk(KERN_ALERT "driver unloaded\n");
}

module_init(lsmacc_module_init);
module_exit(lsmacc_module_exit);

