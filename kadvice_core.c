#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "ka/secops.h"

#include <linux/security.h>
#include <cabi/common.h>

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


#define KA_SHOW(aoid, acc, max)						\
  static int ka_show##aoid(struct seq_file *m, void *p){		\
    int n = (int)p-1;							\
    int i;								\
    seq_printf(m, "[%3d]", n);						\
    for(i = 0; i < max; i++){						\
      if((void *)acc[n][aoid][i] != NULL){				\
	void *ptr = (void *)lsm_acc[n][aoid][i];			\
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
    printk("register advice lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
    return 0;
  }
  for(i += 1; i < 8; i++){
    if(lsm_acc[lsmid][aoid][i] == 0){
      lsm_acc[lsmid][aoid][i] = (unsigned long)func;
      printk("register advice lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
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
	  printk("clear func\n");
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
  if(lsmid < 0)
    return -1;
  return kadvice_register_advice(query->aoid, lsmid, (void *)query->funcaddr, query->priority);
}
EXPORT_SYMBOL(kadvice_post_advice);


int kadvice_post_advice_str(struct ka_query *query){
  unsigned long addr;
  addr = kallsyms_lookup_name(query->funcname);
  if(addr == 0)
    return -ENOMEM;
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
  printk("namelen %d head %d name %d\n",namelen, strlen(head), strlen(name));
  strncpy(funcname, head, strlen(head));
  strncat(funcname, "_", 1);
  strncat(funcname, name, strlen(name));
  funcname[namelen] = '\0';
  query->funcname = funcname;
  query->aoid = aoid;
  query->priority = priority;
  query->weavepoint = name;
  ret = kadvice_post_advice_str(query);
  printk("post %d\n",ret);
  kfree(query);
  kfree(funcname);
  return ret;
}
EXPORT_SYMBOL(kadvice_post);
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


FUNC2INT(lsm_acc, ptrace, struct task_struct *, parent, struct task_struct *, child);
FUNC4INT(lsm_acc, capget, struct task_struct *, target, kernel_cap_t *, effective, kernel_cap_t *, inheritable, kernel_cap_t *, permitted);
FUNC4INT(lsm_acc, capset_check, struct task_struct *, target, kernel_cap_t *, effective, kernel_cap_t *, inheritable, kernel_cap_t *, permitted);
FUNC4VOID(lsm_acc, capset_set, struct task_struct *, target, kernel_cap_t *, effective, kernel_cap_t *, inheritable, kernel_cap_t *, permitted);
FUNC2INT(lsm_acc, capable, struct task_struct *, tsk, int, cap);
FUNC1INT(lsm_acc, acct, struct file *, file);
FUNC2INT(lsm_acc, sysctl, struct ctl_table *, table, int, op);
FUNC4INT(lsm_acc, quotactl, int, cmds, int, type, int, id, struct super_block *, sb);
FUNC1INT(lsm_acc, quota_on, struct dentry *, dentry);
FUNC1INT(lsm_acc, syslog, int, type);
FUNC2INT(lsm_acc, settime, struct timespec *, ts, struct timezone *, tz);
FUNC2INT(lsm_acc, vm_enough_memory, struct mm_struct *, mm, long, pages);
FUNC1INT(lsm_acc, bprm_alloc_security, struct linux_binprm *, bprm);
FUNC1VOID(lsm_acc, bprm_free_security, struct linux_binprm *, bprm);
FUNC2VOID(lsm_acc, bprm_apply_creds, struct linux_binprm *, bprm, int, unsafe);
FUNC1VOID(lsm_acc, bprm_post_apply_creds, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, bprm_set_security, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, bprm_check_security, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, bprm_secureexec, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, sb_alloc_security, struct super_block *, sb);
FUNC1VOID(lsm_acc, sb_free_security, struct super_block *, sb);
FUNC3INT(lsm_acc, sb_copy_data, struct file_system_type *, type, void *, orig, void *, copy);
FUNC2INT(lsm_acc, sb_kern_mount, struct super_block *, sb, void *, data);
FUNC1INT(lsm_acc, sb_statfs, struct dentry *, dentry);
FUNC5INT(lsm_acc, sb_mount, char *, dev_name, struct nameidata *, nd, char *, type, unsigned long, flags, void *, data);
FUNC2INT(lsm_acc, sb_check_sb, struct vfsmount *, mnt, struct nameidata *, nd);
FUNC2INT(lsm_acc, sb_umount, struct vfsmount *, mnt, int, flags);
FUNC1VOID(lsm_acc, sb_umount_close, struct vfsmount *, mnt);
FUNC1VOID(lsm_acc, sb_umount_busy, struct vfsmount *, mnt);
FUNC3VOID(lsm_acc, sb_post_remount, struct vfsmount *, mnt, unsigned long, flags, void *, data);
FUNC0VOID(lsm_acc, sb_post_mountroot, void);

FUNC2VOID(lsm_acc, sb_post_addmount, struct vfsmount *, mnt, struct nameidata *, mountpoint_nd);
FUNC2INT(lsm_acc, sb_pivotroot, struct nameidata *, old_nd, struct nameidata *, new_nd);
FUNC2VOID(lsm_acc, sb_post_pivotroot, struct nameidata *, old_nd, struct nameidata *, new_nd);
FUNC1INT(lsm_acc, inode_alloc_security, struct inode *, inode);
FUNC1VOID(lsm_acc, inode_free_security, struct inode *, inode);
FUNC5INT(lsm_acc, inode_init_security, struct inode *, inode, struct inode *, dir, char **, name, void **, value, size_t *, len);
FUNC3INT(lsm_acc, inode_create, struct inode *, dir, struct dentry *, dentry, int, mode);
FUNC3INT(lsm_acc, inode_link, struct dentry *, old_dentry, struct inode *, dir, struct dentry *, new_dentry);
FUNC2INT(lsm_acc, inode_unlink, struct inode *, dir, struct dentry *, dentry);
FUNC3INT(lsm_acc, inode_symlink, struct inode *, dir, struct dentry *, dentry, const char *, old_name);
FUNC3INT(lsm_acc, inode_mkdir, struct inode *, dir, struct dentry *, dentry, int, mode);
FUNC2INT(lsm_acc, inode_rmdir, struct inode *, dir, struct dentry *, dentry);
FUNC4INT(lsm_acc, inode_mknod, struct inode *, dir, struct dentry *, dentry, int, mode, dev_t, dev);
FUNC4INT(lsm_acc, inode_rename, struct inode *, old_dir, struct dentry *, old_dentry, struct inode *, new_dir, struct dentry *, new_dentry);
FUNC1INT(lsm_acc, inode_readlink, struct dentry *, dentry);
FUNC2INT(lsm_acc, inode_follow_link, struct dentry *, dentry, struct nameidata *, nd);

FUNC3INT(lsm_acc, inode_permission, struct inode *, inode, int, mask, struct nameidata *, nd);

FUNC2INT(lsm_acc, inode_setattr, struct dentry *, dentry, struct iattr *, attr);
FUNC2INT(lsm_acc, inode_getattr, struct vfsmount *, mnt, struct dentry *, dentry);
FUNC1VOID(lsm_acc, inode_delete, struct inode *, inode);
FUNC5INT(lsm_acc, inode_setxattr, struct dentry *, dentry, char *, name, void *, value, size_t, size, int, flags);
FUNC5VOID(lsm_acc, inode_post_setxattr, struct dentry *, dentry, char *, name, void *, value, size_t, size, int, flags);
FUNC2INT(lsm_acc, inode_getxattr, struct dentry *, dentry, char *, name);
FUNC1INT(lsm_acc, inode_listxattr, struct dentry *, dentry);
FUNC2INT(lsm_acc, inode_removexattr, struct dentry *, dentry, char *, name);
FUNC1INT(lsm_acc, inode_need_killpriv, struct dentry *, dentry);
FUNC1INT(lsm_acc, inode_killpriv, struct dentry *, dentry);
FUNC5INT(lsm_acc, inode_getsecurity, const struct inode *, inode, const char *, name, void *, buffer, size_t, size, int, err);
FUNC5INT(lsm_acc, inode_setsecurity, struct inode *, inode, const char *, name, const void *, value, size_t, size, int, flags);
FUNC3INT(lsm_acc, inode_listsecurity, struct inode *, inode, char *, buffer, size_t, buffer_size);
FUNC2INT(lsm_acc, file_permission, struct file *, file, int, mask);
FUNC1INT(lsm_acc, file_alloc_security, struct file *, file);
FUNC1VOID(lsm_acc, file_free_security, struct file *, file);
FUNC3INT(lsm_acc, file_ioctl, struct file *, file, unsigned int, cmd, unsigned long, arg);
FUNC6INT(lsm_acc, file_mmap, struct file *, file, unsigned long, reqprot, unsigned long, prot, unsigned long, flags, unsigned long, addr, unsigned long, addr_only);
FUNC3INT(lsm_acc, file_mprotect, struct vm_area_struct *, vma, unsigned long, reqprot, unsigned long, prot);
FUNC2INT(lsm_acc, file_lock, struct file *, file, unsigned int, cmd);
FUNC3INT(lsm_acc, file_fcntl, struct file *, file, unsigned int, cmd, unsigned long, arg);
FUNC1INT(lsm_acc, file_set_fowner, struct file *, file);
FUNC3INT(lsm_acc, file_send_sigiotask, struct task_struct *, tsk, struct fown_struct *, fown, int, sig);
FUNC1INT(lsm_acc, file_receive, struct file *, file);
FUNC1INT(lsm_acc, dentry_open, struct file *, file);


FUNC1INT(lsm_acc, task_create, unsigned long, clone_flags);
FUNC1INT(lsm_acc, task_alloc_security, struct task_struct *, p);
FUNC1VOID(lsm_acc, task_free_security, struct task_struct *, p);
FUNC4INT(lsm_acc, task_setuid, uid_t, id0, uid_t, id1, uid_t, id2, int, flags);
FUNC4INT(lsm_acc, task_post_setuid, int, task_post_setuid, uid_t, old_euid, uid_t, old_suid, int, flags);
FUNC4INT(lsm_acc, task_setgid, gid_t, id0, gid_t, id1, gid_t, id2, int, flags);
FUNC2INT(lsm_acc, task_setpgid, struct task_struct *, p, pid_t, pgid);
FUNC1INT(lsm_acc, task_getpgid, struct task_struct *, p);
FUNC1INT(lsm_acc, task_getsid, struct task_struct *, p);
FUNC2VOID(lsm_acc, task_getsecid, struct task_struct *, p, u32 *, secid);
FUNC1INT(lsm_acc, task_setgroups, struct group_info *, group_info);
FUNC2INT(lsm_acc, task_setnice, struct task_struct *, p, int, nice);
FUNC2INT(lsm_acc, task_setioprio, struct task_struct *, p, int, ioprio);
FUNC1INT(lsm_acc, task_getioprio, struct task_struct *, p);
FUNC2INT(lsm_acc, task_setrlimit, unsigned int, resource, struct rlimit *, new_rlim);
FUNC3INT(lsm_acc, task_setscheduler, struct task_struct *, p, int, policy, struct sched_param *, lp);
FUNC1INT(lsm_acc, task_getscheduler, struct task_struct *, p);
FUNC1INT(lsm_acc, task_movememory, struct task_struct *, p);
FUNC4INT(lsm_acc, task_kill, struct task_struct *, p, struct siginfo *, info, int, sig, u32, secid);
FUNC1INT(lsm_acc, task_wait, struct task_struct *, p);
FUNC5INT(lsm_acc, task_prctl, int, option, unsigned long, arg2, unsigned long, arg3, unsigned long, arg4, unsigned long, arg5);
FUNC1VOID(lsm_acc, task_reparent_to_init, struct task_struct *, p);
FUNC2VOID(lsm_acc, task_to_inode, struct task_struct *, p, struct inode *, inode);

FUNC2INT(lsm_acc, ipc_permission, struct kern_ipc_perm *, ipcp, short, flag);
FUNC1INT(lsm_acc, msg_msg_alloc_security, struct msg_msg *, msg);
FUNC1VOID(lsm_acc, msg_msg_free_security, struct msg_msg *, msg);
FUNC1INT(lsm_acc, msg_queue_alloc_security, struct msg_queue *, msq);
FUNC1VOID(lsm_acc, msg_queue_free_security, struct msg_queue *, msq);
FUNC2INT(lsm_acc, msg_queue_associate, struct msg_queue *, msq, int, msqflg);
FUNC2INT(lsm_acc, msg_queue_msgctl, struct msg_queue *, msq, int, cmd);
FUNC3INT(lsm_acc, msg_queue_msgsnd, struct msg_queue *, msq, struct msg_msg *, msg, int, msqflg);
FUNC5INT(lsm_acc, msg_queue_msgrcv, struct msg_queue *, msq, struct msg_msg *, msg, struct task_struct *, target, long, type, int, mode);
FUNC1INT(lsm_acc, shm_alloc_security, struct shmid_kernel *, shp);
FUNC1VOID(lsm_acc, shm_free_security, struct shmid_kernel *, shp);
FUNC2INT(lsm_acc, shm_associate, struct shmid_kernel *, shp, int, shmflg);
FUNC2INT(lsm_acc, shm_shmctl, struct shmid_kernel *, shp, int, cmd);
FUNC3INT(lsm_acc, shm_shmat, struct shmid_kernel *, shp, char __user *, shmaddr, int, shmflg);
FUNC1INT(lsm_acc, sem_alloc_security, struct sem_array *, sma);
FUNC1VOID(lsm_acc, sem_free_security, struct sem_array *, sma);
FUNC2INT(lsm_acc, sem_associate, struct sem_array *, sma, int, semflg);
FUNC2INT(lsm_acc, sem_semctl, struct sem_array *, sma, int, cmd);
FUNC4INT(lsm_acc, sem_semop, struct sem_array *, sma, struct sembuf *, sops, unsigned, nsops, int, alter);

FUNC2INT(lsm_acc, netlink_send, struct sock *, sk, struct sk_buff *, skb);
FUNC2INT(lsm_acc, netlink_recv, struct sk_buff *, skb, int, cap);
FUNC2INT(lsm_acc, register_security, const char *, name, struct security_operations *, ops);
FUNC2VOID(lsm_acc, d_instantiate, struct dentry *, dentry, struct inode *, inode);
FUNC3INT(lsm_acc, getprocattr, struct task_struct *, p, char *, name, char **, value);
FUNC4INT(lsm_acc, setprocattr, struct task_struct *, p, char *, name, void *, value, size_t, size);
FUNC3INT(lsm_acc, secid_to_secctx, u32, secid, char **, secdata, u32 *, seclen);
FUNC2VOID(lsm_acc, release_secctx, char *, secdata, u32, seclen);
FUNC3INT(lsm_acc, unix_stream_connect, struct socket *, sock, struct socket *, other, struct sock *, newsk);
FUNC2INT(lsm_acc, unix_may_send, struct socket *, sock, struct socket *, other);
FUNC4INT(lsm_acc, socket_create, int, family, int, type, int, protocol, int, kern);
FUNC5INT(lsm_acc, socket_post_create, struct socket *, sock, int, family, int, type, int, protocol, int, kern);
FUNC3INT(lsm_acc, socket_bind, struct socket *, sock, struct sockaddr *, address, int, addrlen);
FUNC3INT(lsm_acc, socket_connect, struct socket *, sock, struct sockaddr *, address, int, addrlen);
FUNC2INT(lsm_acc, socket_listen, struct socket *, sock, int, backlog);
FUNC2INT(lsm_acc, socket_accept, struct socket *, sock, struct socket *, newsock);
FUNC2VOID(lsm_acc, socket_post_accept, struct socket *, sock, struct socket *, newsock);
FUNC3INT(lsm_acc, socket_sendmsg, struct socket *, sock, struct msghdr *, msg, int, size);
FUNC4INT(lsm_acc, socket_recvmsg, struct socket *, sock, struct msghdr *, msg, int, size, int, flags);
FUNC1INT(lsm_acc, socket_getsockname, struct socket *, sock);
FUNC1INT(lsm_acc, socket_getpeername, struct socket *, sock);
FUNC3INT(lsm_acc, socket_getsockopt, struct socket *, sock, int, level, int, optname);
FUNC3INT(lsm_acc, socket_setsockopt, struct socket *, sock, int, level, int, optname);
FUNC2INT(lsm_acc, socket_shutdown, struct socket *, sock, int, how);
FUNC2INT(lsm_acc, socket_sock_rcv_skb, struct sock *, sk, struct sk_buff *, skb);
FUNC4INT(lsm_acc, socket_getpeersec_stream, struct socket *, sock, char __user *, optval, int __user *, optlen, unsigned, len);
FUNC3INT(lsm_acc, socket_getpeersec_dgram, struct socket *, sock, struct sk_buff *, skb, u32 *, secid);
FUNC3INT(lsm_acc, sk_alloc_security, struct sock *, sk, int, family, gfp_t, priority);
FUNC1VOID(lsm_acc, sk_free_security, struct sock *, sk);
FUNC2VOID(lsm_acc, sk_clone_security, const struct sock *, sk, struct sock *, newsk);
FUNC2VOID(lsm_acc, sk_getsecid, struct sock *, sk, u32 *, secid);
FUNC2VOID(lsm_acc, sock_graft, struct sock*, sk, struct socket *, parent);
FUNC3INT(lsm_acc, inet_conn_request, struct sock *, sk, struct sk_buff *, skb, struct request_sock *, req);
FUNC2VOID(lsm_acc, inet_csk_clone, struct sock *, newsk, const struct request_sock *, req);
FUNC2VOID(lsm_acc, inet_conn_established, struct sock *, sk, struct sk_buff *, skb);
FUNC2VOID(lsm_acc, req_classify_flow, const struct request_sock *, req, struct flowi *, fl);
FUNC2INT(lsm_acc, xfrm_policy_alloc_security, struct xfrm_policy *, xp, struct xfrm_user_sec_ctx *, sec_ctx);
FUNC2INT(lsm_acc, xfrm_policy_clone_security, struct xfrm_policy *, old, struct xfrm_policy *, new);
FUNC1VOID(lsm_acc, xfrm_policy_free_security, struct xfrm_policy *, xp);
FUNC1INT(lsm_acc, xfrm_policy_delete_security, struct xfrm_policy *, xp);
FUNC3INT(lsm_acc, xfrm_state_alloc_security, struct xfrm_state *, x, struct xfrm_user_sec_ctx *, sec_ctx, u32, secid);
FUNC1VOID(lsm_acc, xfrm_state_free_security, struct xfrm_state *, x);
FUNC1INT(lsm_acc, xfrm_state_delete_security, struct xfrm_state *, x);
FUNC3INT(lsm_acc, xfrm_policy_lookup, struct xfrm_policy *, xp, u32, fl_secid, u8, dir);
FUNC3INT(lsm_acc, xfrm_state_pol_flow_match, struct xfrm_state *, x, struct xfrm_policy *, xp, struct flowi *, fl);
FUNC3INT(lsm_acc, xfrm_decode_session, struct sk_buff *, skb, u32 *, secid, int, ckall);
