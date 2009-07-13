#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/ptrace.h>
#include <linux/xattr.h>
#include <linux/hugetlb.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <linux/securebits.h>
#include "ka/kadvice_lsm.h"
#include "securitycube/securitycube.h"

#define CONFIG_SECURITY_PATH 1
#define CONFIG_SECURITY_NETWORK_XFRM 1
#define CONFIG_SECURITY_NETWORK 1
#define CONFIG_KEYS 1
#define CONFIG_AUDIT 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shinpei NAKATA");

static int sc_ptrace_may_access(struct task_struct * child,unsigned int mode)
{
  int ret = 0;

  rcu_read_lock();
  if (!cap_issubset(__task_cred(child)->cap_permitted,
		    current_cred()->cap_permitted) &&
      !capable(CAP_SYS_PTRACE))
    ret = -EPERM;
  rcu_read_unlock();
  if (ret == 0)
    return sc_check_ptrace_may_access( child, mode);
  return ret;
}

extern int security_real_capable(struct task_struct *tsk, int cap);

static int sc_ptrace_traceme(struct task_struct * parent)
{
  int ret = 0;

  rcu_read_lock();
  if (!cap_issubset(current_cred()->cap_permitted,
		    __task_cred(parent)->cap_permitted) &&
      !has_capability(parent, CAP_SYS_PTRACE))
    ret = -EPERM;
  rcu_read_unlock();
  if (ret == 0)
    return sc_check_ptrace_traceme( parent);
  return ret;
}

static int sc_capget(struct task_struct * target,kernel_cap_t * effective,kernel_cap_t * inheritable,kernel_cap_t * permitted)
{
  const struct cred *cred;
  
  /* Derived from kernel/capability.c:sys_capget. */
  rcu_read_lock();
  cred = __task_cred(target);
  *effective   = cred->cap_effective;
  *inheritable = cred->cap_inheritable;
  *permitted   = cred->cap_permitted;
  rcu_read_unlock();
  return sc_check_capget( target, effective, inheritable, permitted);
}

extern int cap_inh_is_capped(void);

static int sc_capset(struct cred * new,const struct cred * old,const kernel_cap_t * effective,const kernel_cap_t * inheritable,const kernel_cap_t * permitted)
{
	if (cap_inh_is_capped() &&
	    !cap_issubset(*inheritable,
			  cap_combine(old->cap_inheritable,
				      old->cap_permitted)))
		/* incapable of using this inheritable set */
		return -EPERM;

	if (!cap_issubset(*inheritable,
			  cap_combine(old->cap_inheritable,
				      old->cap_bset)))
		/* no new pI capabilities outside bounding set */
		return -EPERM;

	/* verify restrictions on target's new Permitted set */
	if (!cap_issubset(*permitted, old->cap_permitted))
		return -EPERM;

	/* verify the _new_Effective_ is a subset of the _new_Permitted_ */
	if (!cap_issubset(*effective, *permitted))
		return -EPERM;

	new->cap_effective   = *effective;
	new->cap_inheritable = *inheritable;
	new->cap_permitted   = *permitted;
	return sc_check_capset( new, old, effective, inheritable, permitted);
}

static int sc_capable(struct task_struct * tsk,const struct cred * cred,int cap,int audit)
{
  return cap_raised(cred->cap_effective, cap) ? sc_check_capable( tsk, cred, cap, audit) : -EPERM;

}

static int sc_acct(struct file * file)
{	return sc_check_acct( file);
}
static int sc_sysctl(struct ctl_table * table,int op)
{	return sc_check_sysctl( table, op);
}
static int sc_quotactl(int cmds,int type,int id,struct super_block * sb)
{	return sc_check_quotactl( cmds, type, id, sb);
}
static int sc_quota_on(struct dentry * dentry)
{
  return sc_check_quota_on( dentry);
}
static int sc_syslog(int type)
{
  if ((type != 3 && type != 10) && !capable(CAP_SYS_ADMIN))
    return -EPERM;
  return sc_check_syslog( type);
}
static int sc_settime(struct timespec * ts,struct timezone * tz)
{	
  if (!capable(CAP_SYS_TIME))
    return -EPERM;
  return sc_check_settime( ts, tz);
}

static int sc_vm_enough_memory(struct mm_struct * mm,long pages)
{
  return sc_check_vm_enough_memory( mm, pages);
}

static int sc_bprm_set_creds(struct linux_binprm * bprm)
{
  return sc_check_bprm_set_creds( bprm);
}

static int sc_bprm_check_security(struct linux_binprm * bprm)
{
  return sc_check_bprm_check_security( bprm);
}

static int sc_bprm_secureexec(struct linux_binprm * bprm)
{
  const struct cred *cred = current_cred();

  if (cred->uid != 0) {
    if (bprm->cap_effective)
      return 1;
    if (!cap_isclear(cred->cap_permitted))
      return 1;
  }

  return (cred->euid != cred->uid ||
	  cred->egid != cred->gid);

  //  return sc_check_bprm_secureexec( bprm);
}
static void sc_bprm_committing_creds(struct linux_binprm * bprm)
{	return sc_check_bprm_committing_creds( bprm);
}
static void sc_bprm_committed_creds(struct linux_binprm * bprm)
{	return sc_check_bprm_committed_creds( bprm);
}
static int sc_sb_alloc_security(struct super_block * sb)
{	return sc_check_sb_alloc_security( sb);
}
static void sc_sb_free_security(struct super_block * sb)
{	return sc_check_sb_free_security( sb);
}
static int sc_sb_copy_data(char * orig,char * copy)
{	return sc_check_sb_copy_data( orig, copy);
}
static int sc_sb_kern_mount(struct super_block * sb,int flags,void * data)
{	return sc_check_sb_kern_mount( sb, flags, data);
}
static int sc_sb_show_options(struct seq_file * m,struct super_block * sb)
{	return sc_check_sb_show_options( m, sb);
}
static int sc_sb_statfs(struct dentry * dentry)
{	return sc_check_sb_statfs( dentry);
}
static int sc_sb_mount(char * dev_name,struct path * path,char * type,unsigned long flags,void * data)
{	return sc_check_sb_mount( dev_name, path, type, flags, data);
}
static int sc_sb_check_sb(struct vfsmount * mnt,struct path * path)
{	return sc_check_sb_check_sb( mnt, path);
}
static int sc_sb_umount(struct vfsmount * mnt,int flags)
{	return sc_check_sb_umount( mnt, flags);
}
static void sc_sb_umount_close(struct vfsmount * mnt)
{	return sc_check_sb_umount_close( mnt);
}
static void sc_sb_umount_busy(struct vfsmount * mnt)
{	return sc_check_sb_umount_busy( mnt);
}
static void sc_sb_post_remount(struct vfsmount * mnt,unsigned long flags,void * data)
{	return sc_check_sb_post_remount( mnt, flags, data);
}
static void sc_sb_post_addmount(struct vfsmount * mnt,struct path * mountpoint)
{	return sc_check_sb_post_addmount( mnt, mountpoint);
}
static int sc_sb_pivotroot(struct path * old_path,struct path * new_path)
{	return sc_check_sb_pivotroot( old_path, new_path);
}
static void sc_sb_post_pivotroot(struct path * old_path,struct path * new_path)
{	return sc_check_sb_post_pivotroot( old_path, new_path);
}

static int sc_sb_set_mnt_opts(struct super_block * sb,struct security_mnt_opts * opts)
{	
  if (unlikely(opts->num_mnt_opts))
    return -EOPNOTSUPP;
  return sc_check_sb_set_mnt_opts( sb, opts);
}

static void sc_sb_clone_mnt_opts(const struct super_block * oldsb,struct super_block * newsb)
{	return sc_check_sb_clone_mnt_opts( oldsb, newsb);
}
static int sc_sb_parse_opts_str(char * options,struct security_mnt_opts * opts)
{	return sc_check_sb_parse_opts_str( options, opts);
}
#ifdef CONFIG_SECURITY_PATH

static int sc_path_unlink(struct path * dir,struct dentry * dentry)
{	return sc_check_path_unlink( dir, dentry);
}
static int sc_path_mkdir(struct path * dir,struct dentry * dentry,int mode)
{	return sc_check_path_mkdir( dir, dentry, mode);
}
static int sc_path_rmdir(struct path * dir,struct dentry * dentry)
{	return sc_check_path_rmdir( dir, dentry);
}
static int sc_path_mknod(struct path * dir,struct dentry * dentry,int mode,unsigned int dev)
{	return sc_check_path_mknod( dir, dentry, mode, dev);
}
static int sc_path_truncate(struct path * path,loff_t length,unsigned int time_attrs)
{	return sc_check_path_truncate( path, length, time_attrs);
}
static int sc_path_symlink(struct path * dir,struct dentry * dentry,const char * old_name)
{	return sc_check_path_symlink( dir, dentry, old_name);
}
static int sc_path_link(struct dentry * old_dentry,struct path * new_dir,struct dentry * new_dentry)
{	return sc_check_path_link( old_dentry, new_dir, new_dentry);
}
static int sc_path_rename(struct path * old_dir,struct dentry * old_dentry,struct path * new_dir,struct dentry * new_dentry)
{	return sc_check_path_rename( old_dir, old_dentry, new_dir, new_dentry);
}

#endif
static int sc_inode_alloc_security(struct inode * inode)
{	return sc_check_inode_alloc_security( inode);
}
static void sc_inode_free_security(struct inode * inode)
{	return sc_check_inode_free_security( inode);
}
static int sc_inode_init_security(struct inode * inode,struct inode * dir,char ** name,void ** value,size_t * len)
{
  return -EOPNOTSUPP;
  //return sc_check_inode_init_security( inode, dir, name, value, len);
}
static int sc_inode_create(struct inode * dir,struct dentry * dentry,int mode)
{	return sc_check_inode_create( dir, dentry, mode);
}
static int sc_inode_link(struct dentry * old_dentry,struct inode * dir,struct dentry * new_dentry)
{	return sc_check_inode_link( old_dentry, dir, new_dentry);
}
static int sc_inode_unlink(struct inode * dir,struct dentry * dentry)
{	return sc_check_inode_unlink( dir, dentry);
}
static int sc_inode_symlink(struct inode * dir,struct dentry * dentry,const char * old_name)
{	return sc_check_inode_symlink( dir, dentry, old_name);
}
static int sc_inode_mkdir(struct inode * dir,struct dentry * dentry,int mode)
{	return sc_check_inode_mkdir( dir, dentry, mode);
}
static int sc_inode_rmdir(struct inode * dir,struct dentry * dentry)
{	return sc_check_inode_rmdir( dir, dentry);
}
static int sc_inode_mknod(struct inode * dir,struct dentry * dentry,int mode,dev_t dev)
{	return sc_check_inode_mknod( dir, dentry, mode, dev);
}
static int sc_inode_rename(struct inode * old_dir,struct dentry * old_dentry,struct inode * new_dir,struct dentry * new_dentry)
{	return sc_check_inode_rename( old_dir, old_dentry, new_dir, new_dentry);
}
static int sc_inode_readlink(struct dentry * dentry)
{	return sc_check_inode_readlink( dentry);
}
static int sc_inode_follow_link(struct dentry * dentry,struct nameidata * nd)
{	return sc_check_inode_follow_link( dentry, nd);
}
static int sc_inode_permission(struct inode * inode,int mask)
{	return sc_check_inode_permission( inode, mask);
}
static int sc_inode_setattr(struct dentry * dentry,struct iattr * attr)
{
  return sc_check_inode_setattr( dentry, attr);
}
static int sc_inode_getattr(struct vfsmount * mnt,struct dentry * dentry)
{

  return sc_check_inode_getattr( mnt, dentry);
}
static void sc_inode_delete(struct inode * inode)
{	return sc_check_inode_delete( inode);
}
static int sc_inode_setxattr(struct dentry * dentry,const char * name,const void * value,size_t size,int flags)
{
  if (!strcmp(name, XATTR_NAME_CAPS)) {
    if (!capable(CAP_SETFCAP))
      return -EPERM;
    return sc_check_inode_setxattr( dentry, name, value, size, flags);
  }
  
  if (!strncmp(name, XATTR_SECURITY_PREFIX,
	       sizeof(XATTR_SECURITY_PREFIX) - 1)  &&
      !capable(CAP_SYS_ADMIN))
    return -EPERM;
  return sc_check_inode_setxattr( dentry, name, value, size, flags);
}

static void sc_inode_post_setxattr(struct dentry * dentry,const char * name,const void * value,size_t size,int flags)
{	return sc_check_inode_post_setxattr( dentry, name, value, size, flags);
}
static int sc_inode_getxattr(struct dentry * dentry,const char * name)
{	return sc_check_inode_getxattr( dentry, name);
}
static int sc_inode_listxattr(struct dentry * dentry)
{	return sc_check_inode_listxattr( dentry);
}
static int sc_inode_removexattr(struct dentry * dentry,const char * name)
{
  if (!strcmp(name, XATTR_NAME_CAPS)) {
    if (!capable(CAP_SETFCAP))
      return -EPERM;
  return sc_check_inode_removexattr( dentry, name);

  }
  
  if (!strncmp(name, XATTR_SECURITY_PREFIX,
	       sizeof(XATTR_SECURITY_PREFIX) - 1)  &&
      !capable(CAP_SYS_ADMIN))
    return -EPERM;
  return sc_check_inode_removexattr( dentry, name);



}
static int sc_inode_need_killpriv(struct dentry * dentry)
{
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode->i_op->getxattr)
	  return sc_check_inode_need_killpriv( dentry);

	error = inode->i_op->getxattr(dentry, XATTR_NAME_CAPS, NULL, 0);
	if (error <= 0)
	  return sc_check_inode_need_killpriv( dentry);
	return 1;


}
static int sc_inode_killpriv(struct dentry * dentry)
{
	struct inode *inode = dentry->d_inode;

	if (!inode->i_op->removexattr)
	  return sc_check_inode_killpriv( dentry);
	return inode->i_op->removexattr(dentry, XATTR_NAME_CAPS);

}
static int sc_inode_getsecurity(const struct inode * inode,const char * name,void ** buffer,bool alloc)
{
  return -EOPNOTSUPP;
  //	return sc_check_inode_getsecurity( inode, name, buffer, alloc);
}
static int sc_inode_setsecurity(struct inode * inode,const char * name,const void * value,size_t size,int flags)
{
  return -EOPNOTSUPP;
  //	return sc_check_inode_setsecurity( inode, name, value, size, flags);
}
static int sc_inode_listsecurity(struct inode * inode,char * buffer,size_t buffer_size)
{	return sc_check_inode_listsecurity( inode, buffer, buffer_size);
}
static void sc_inode_getsecid(const struct inode * inode,u32 * secid)
{

  *secid = 0;
  return sc_check_inode_getsecid( inode, secid);


}


static int sc_file_permission(struct file * file,int mask)
{	return sc_check_file_permission( file, mask);
}
static int sc_file_alloc_security(struct file * file)
{	return sc_check_file_alloc_security( file);
}
static void sc_file_free_security(struct file * file)
{	return sc_check_file_free_security( file);
}
static int sc_file_ioctl(struct file * file,unsigned int cmd,unsigned long arg)
{	return sc_check_file_ioctl( file, cmd, arg);
}

unsigned long mmap_min_addr = 65539;
static int sc_file_mmap(struct file * file,unsigned long reqprot,unsigned long prot,unsigned long flags,unsigned long addr,unsigned long addr_only)
{
  if ((addr < mmap_min_addr) && !capable(CAP_SYS_RAWIO))
    return -EACCES;
  return sc_check_file_mmap( file, reqprot, prot, flags, addr, addr_only);
}

static int sc_file_mprotect(struct vm_area_struct * vma,unsigned long reqprot,unsigned long prot)
{	return sc_check_file_mprotect( vma, reqprot, prot);
}
static int sc_file_lock(struct file * file,unsigned int cmd)
{	return sc_check_file_lock( file, cmd);
}
static int sc_file_fcntl(struct file * file,unsigned int cmd,unsigned long arg)
{	return sc_check_file_fcntl( file, cmd, arg);
}
static int sc_file_set_fowner(struct file * file)
{	return sc_check_file_set_fowner( file);
}
static int sc_file_send_sigiotask(struct task_struct * tsk,struct fown_struct * fown,int sig)
{	return sc_check_file_send_sigiotask( tsk, fown, sig);
}
static int sc_file_receive(struct file * file)
{	return sc_check_file_receive( file);
}
static int sc_dentry_open(struct file * file,const struct cred * cred)
{	return sc_check_dentry_open( file, cred);
}
static int sc_task_create(unsigned long clone_flags)
{	return sc_check_task_create( clone_flags);
}
static void sc_cred_free(struct cred * cred)
{	return sc_check_cred_free( cred);
}
static int sc_cred_prepare(struct cred * new,const struct cred * old,gfp_t gfp)
{	return sc_check_cred_prepare( new, old, gfp);
}
static void sc_cred_commit(struct cred * new,const struct cred * old)
{	return sc_check_cred_commit( new, old);
}
static int sc_kernel_act_as(struct cred * new,u32 secid)
{	return sc_check_kernel_act_as( new, secid);
}
static int sc_kernel_create_files_as(struct cred * new,struct inode * inode)
{	return sc_check_kernel_create_files_as( new, inode);
}

static int sc_task_setuid(uid_t id0,uid_t id1,uid_t id2,int flags)
{	return sc_check_task_setuid( id0, id1, id2, flags);
}

extern void cap_emulate_setxuid(struct cred *new, struct cred *old);

static int sc_task_fix_setuid(struct cred * new,const struct cred * old,int flags)
{	
	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
		/* juggle the capabilities to follow [RES]UID changes unless
		 * otherwise suppressed */
		if (!issecure(SECURE_NO_SETUID_FIXUP))
			cap_emulate_setxuid(new, old);
		break;

	case LSM_SETID_FS:
		/* juggle the capabilties to follow FSUID changes, unless
		 * otherwise suppressed
		 *
		 * FIXME - is fsuser used for all CAP_FS_MASK capabilities?
		 *          if not, we might be a bit too harsh here.
		 */
		if (!issecure(SECURE_NO_SETUID_FIXUP)) {
			if (old->fsuid == 0 && new->fsuid != 0)
				new->cap_effective =
					cap_drop_fs_set(new->cap_effective);

			if (old->fsuid != 0 && new->fsuid == 0)
				new->cap_effective =
					cap_raise_fs_set(new->cap_effective,
							 new->cap_permitted);
		}
		break;

	default:
		return -EINVAL;
	}

	return sc_check_task_fix_setuid( new, old, flags);


}
static int sc_task_setgid(gid_t id0,gid_t id1,gid_t id2,int flags)
{	return sc_check_task_setgid( id0, id1, id2, flags);
}
static int sc_task_setpgid(struct task_struct * p,pid_t pgid)
{	return sc_check_task_setpgid( p, pgid);
}


static int sc_task_getpgid(struct task_struct * p)
{	return sc_check_task_getpgid( p);
}
static int sc_task_getsid(struct task_struct * p)
{	return sc_check_task_getsid( p);
}
static void sc_task_getsecid(struct task_struct * p,u32 * secid)
{
  *secid = 0;
  return sc_check_task_getsecid( p, secid);
}
static int sc_task_setgroups(struct group_info * group_info)
{	return sc_check_task_setgroups( group_info);
}

extern int cap_safe_nice (struct task_struct *p);

static int sc_task_setnice(struct task_struct * p,int nice)
{
  int ret;
  if ((ret = cap_safe_nice(p)) == 0) 
	return sc_check_task_setnice( p, nice);
  return ret;
}

static int sc_task_setioprio(struct task_struct * p,int ioprio)
{
  int ret;
  if ((ret = cap_safe_nice(p)) == 0) 
	return sc_check_task_setioprio( p, ioprio);
  return ret;
}
static int sc_task_getioprio(struct task_struct * p)
{	return sc_check_task_getioprio( p);
}
static int sc_task_setrlimit(unsigned int resource,struct rlimit * new_rlim)
{	return sc_check_task_setrlimit( resource, new_rlim);
}


static int sc_task_setscheduler(struct task_struct * p,int policy,struct sched_param * lp)
{
  int ret;
  if((ret = cap_safe_nice(p)) == 0)
    return sc_check_task_setscheduler( p, policy, lp);
  return ret;
}

static int sc_task_getscheduler(struct task_struct * p)
{
	return sc_check_task_getscheduler( p);
}
static int sc_task_movememory(struct task_struct * p)
{	return sc_check_task_movememory( p);
}
static int sc_task_kill(struct task_struct * p,struct siginfo * info,int sig,u32 secid)
{	return sc_check_task_kill( p, info, sig, secid);
}
static int sc_task_wait(struct task_struct * p)
{	return sc_check_task_wait( p);
}
static int sc_task_prctl(int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5)
{
  return sc_check_task_prctl( option, arg2, arg3, arg4, arg5);
}
static void sc_task_to_inode(struct task_struct * p,struct inode * inode)
{	return sc_check_task_to_inode( p, inode);
}
static int sc_ipc_permission(struct kern_ipc_perm * ipcp,short flag)
{	return sc_check_ipc_permission( ipcp, flag);
}
static void sc_ipc_getsecid(struct kern_ipc_perm * ipcp,u32 * secid)
{
  *secid = 0;
  return sc_check_ipc_getsecid( ipcp, secid);
}
static int sc_msg_msg_alloc_security(struct msg_msg * msg)
{	return sc_check_msg_msg_alloc_security( msg);
}
static void sc_msg_msg_free_security(struct msg_msg * msg)
{	return sc_check_msg_msg_free_security( msg);
}
static int sc_msg_queue_alloc_security(struct msg_queue * msq)
{	return sc_check_msg_queue_alloc_security( msq);
}
static void sc_msg_queue_free_security(struct msg_queue * msq)
{	return sc_check_msg_queue_free_security( msq);
}
static int sc_msg_queue_associate(struct msg_queue * msq,int msqflg)
{	return sc_check_msg_queue_associate( msq, msqflg);
}
static int sc_msg_queue_msgctl(struct msg_queue * msq,int cmd)
{	return sc_check_msg_queue_msgctl( msq, cmd);
}
static int sc_msg_queue_msgsnd(struct msg_queue * msq,struct msg_msg * msg,int msqflg)
{	return sc_check_msg_queue_msgsnd( msq, msg, msqflg);
}
static int sc_msg_queue_msgrcv(struct msg_queue * msq,struct msg_msg * msg,struct task_struct * target,long type,int mode)
{	return sc_check_msg_queue_msgrcv( msq, msg, target, type, mode);
}
static int sc_shm_alloc_security(struct shmid_kernel * shp)
{	return sc_check_shm_alloc_security( shp);
}
static void sc_shm_free_security(struct shmid_kernel * shp)
{	return sc_check_shm_free_security( shp);
}
static int sc_shm_associate(struct shmid_kernel * shp,int shmflg)
{	return sc_check_shm_associate( shp, shmflg);
}
static int sc_shm_shmctl(struct shmid_kernel * shp,int cmd)
{	return sc_check_shm_shmctl( shp, cmd);
}
static int sc_shm_shmat(struct shmid_kernel * shp,char * shmaddr,int shmflg)
{	return sc_check_shm_shmat( shp, shmaddr, shmflg);
}
static int sc_sem_alloc_security(struct sem_array * sma)
{	return sc_check_sem_alloc_security( sma);
}
static void sc_sem_free_security(struct sem_array * sma)
{	return sc_check_sem_free_security( sma);
}
static int sc_sem_associate(struct sem_array * sma,int semflg)
{	return sc_check_sem_associate( sma, semflg);
}
static int sc_sem_semctl(struct sem_array * sma,int cmd)
{	return sc_check_sem_semctl( sma, cmd);
}
static int sc_sem_semop(struct sem_array * sma,struct sembuf * sops,unsigned int nsops,int alter)
{	return sc_check_sem_semop( sma, sops, nsops, alter);
}
static int sc_netlink_send(struct sock * sk,struct sk_buff * skb)
{	return sc_check_netlink_send( sk, skb);
}
static int sc_netlink_recv(struct sk_buff * skb,int cap)
{	return sc_check_netlink_recv( skb, cap);
}
static void sc_d_instantiate(struct dentry * dentry,struct inode * inode)
{	return sc_check_d_instantiate( dentry, inode);
}
static int sc_getprocattr(struct task_struct * p,char * name,char ** value)
{
  return -EINVAL;
  //	return sc_check_getprocattr( p, name, value);
}

static int sc_setprocattr(struct task_struct * p,char * name,void * value,size_t size)
{
  return -EINVAL;
  //	return sc_check_setprocattr( p, name, value, size);
}
static int sc_secid_to_secctx(u32 secid,char ** secdata,u32 * seclen)
{
  return -EOPNOTSUPP;
  //	return sc_check_secid_to_secctx( secid, secdata, seclen);
}
static int sc_secctx_to_secid(const char * secdata,u32 seclen,u32 * secid)
{
  return -EOPNOTSUPP;
  //	return sc_check_secctx_to_secid( secdata, seclen, secid);
}
static void sc_release_secctx(char * secdata,u32 seclen)
{	return sc_check_release_secctx( secdata, seclen);
}

#ifdef CONFIG_SECURITY_NETWORK
static int sc_unix_stream_connect(struct socket * sock,struct socket * other,struct sock * newsk)
{	return sc_check_unix_stream_connect( sock, other, newsk);
}
static int sc_unix_may_send(struct socket * sock,struct socket * other)
{	return sc_check_unix_may_send( sock, other);
}
static int sc_socket_create(int family,int type,int protocol,int kern)
{	return sc_check_socket_create( family, type, protocol, kern);
}
static int sc_socket_post_create(struct socket * sock,int family,int type,int protocol,int kern)
{	return sc_check_socket_post_create( sock, family, type, protocol, kern);
}
static int sc_socket_bind(struct socket * sock,struct sockaddr * address,int addrlen)
{	return sc_check_socket_bind( sock, address, addrlen);
}
static int sc_socket_connect(struct socket * sock,struct sockaddr * address,int addrlen)
{	return sc_check_socket_connect( sock, address, addrlen);
}
static int sc_socket_listen(struct socket * sock,int backlog)
{	return sc_check_socket_listen( sock, backlog);
}
static int sc_socket_accept(struct socket * sock,struct socket * newsock)
{	return sc_check_socket_accept( sock, newsock);
}
static int sc_socket_sendmsg(struct socket * sock,struct msghdr * msg,int size)
{	return sc_check_socket_sendmsg( sock, msg, size);
}
static int sc_socket_recvmsg(struct socket * sock,struct msghdr * msg,int size,int flags)
{	return sc_check_socket_recvmsg( sock, msg, size, flags);
}
static int sc_socket_getsockname(struct socket * sock)
{	return sc_check_socket_getsockname( sock);
}
static int sc_socket_getpeername(struct socket * sock)
{	return sc_check_socket_getpeername( sock);
}
static int sc_socket_getsockopt(struct socket * sock,int level,int optname)
{	return sc_check_socket_getsockopt( sock, level, optname);
}
static int sc_socket_setsockopt(struct socket * sock,int level,int optname)
{	return sc_check_socket_setsockopt( sock, level, optname);
}
static int sc_socket_shutdown(struct socket * sock,int how)
{	return sc_check_socket_shutdown( sock, how);
}
static int sc_socket_sock_rcv_skb(struct sock * sk,struct sk_buff * skb)
{	return sc_check_socket_sock_rcv_skb( sk, skb);
}
static int sc_socket_getpeersec_stream(struct socket * sock,char * optval,int * optlen,unsigned int len)
{
  return -ENOPROTOOPT;
  //return sc_check_socket_getpeersec_stream( sock, optval, optlen, len);
}
static int sc_socket_getpeersec_dgram(struct socket * sock,struct sk_buff * skb,u32 * secid)
{
  return -ENOPROTOOPT;
  //	return sc_check_socket_getpeersec_dgram( sock, skb, secid);
}
static int sc_sk_alloc_security(struct sock * sk,int family,gfp_t priority)
{	return sc_check_sk_alloc_security( sk, family, priority);
}
static void sc_sk_free_security(struct sock * sk)
{	return sc_check_sk_free_security( sk);
}
static void sc_sk_clone_security(const struct sock * sk,struct sock * newsk)
{	return sc_check_sk_clone_security( sk, newsk);
}
static void sc_sk_getsecid(struct sock * sk,u32 * secid)
{	return sc_check_sk_getsecid( sk, secid);
}
static void sc_sock_graft(struct sock * sk,struct socket * parent)
{	return sc_check_sock_graft( sk, parent);
}
static int sc_inet_conn_request(struct sock * sk,struct sk_buff * skb,struct request_sock * req)
{	return sc_check_inet_conn_request( sk, skb, req);
}
static void sc_inet_csk_clone(struct sock * newsk,const struct request_sock * req)
{	return sc_check_inet_csk_clone( newsk, req);
}
static void sc_inet_conn_established(struct sock * sk,struct sk_buff * skb)
{	return sc_check_inet_conn_established( sk, skb);
}
static void sc_req_classify_flow(const struct request_sock * req,struct flowi * fl)
{	return sc_check_req_classify_flow( req, fl);
}


#endif /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

static int sc_xfrm_policy_alloc_security(struct xfrm_sec_ctx ** ctxp,struct xfrm_user_sec_ctx * sec_ctx)
{	return sc_check_xfrm_policy_alloc_security( ctxp, sec_ctx);
}
static int sc_xfrm_policy_clone_security(struct xfrm_sec_ctx * old_ctx,struct xfrm_sec_ctx ** new_ctx)
{	return sc_check_xfrm_policy_clone_security( old_ctx, new_ctx);
}
static void sc_xfrm_policy_free_security(struct xfrm_sec_ctx * ctx)
{	return sc_check_xfrm_policy_free_security( ctx);
}
static int sc_xfrm_policy_delete_security(struct xfrm_sec_ctx * ctx)
{	return sc_check_xfrm_policy_delete_security( ctx);
}
static int sc_xfrm_state_alloc_security(struct xfrm_state * x,struct xfrm_user_sec_ctx * sec_ctx,u32 secid)
{	return sc_check_xfrm_state_alloc_security( x, sec_ctx, secid);
}
static void sc_xfrm_state_free_security(struct xfrm_state * x)
{	return sc_check_xfrm_state_free_security( x);
}
static int sc_xfrm_state_delete_security(struct xfrm_state * x)
{	return sc_check_xfrm_state_delete_security( x);
}
static int sc_xfrm_policy_lookup(struct xfrm_sec_ctx * ctx,u32 fl_secid,u8 dir)
{	return sc_check_xfrm_policy_lookup( ctx, fl_secid, dir);
}
static int sc_xfrm_state_pol_flow_match(struct xfrm_state * x,struct xfrm_policy * xp,struct flowi * fl)
{	
  return 1;
  return sc_check_xfrm_state_pol_flow_match( x, xp, fl);
}
static int sc_xfrm_decode_session(struct sk_buff * skb,u32 * secid,int ckall)
{	return sc_check_xfrm_decode_session( skb, secid, ckall);
}


#endif /* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS
static int sc_key_alloc(struct key * key,const struct cred * cred,unsigned long flags)
{	return sc_check_key_alloc( key, cred, flags);
}
static void sc_key_free(struct key * key)
{	return sc_check_key_free( key);
}
static int sc_key_permission(key_ref_t key_ref,const struct cred * cred,key_perm_t perm)
{	return sc_check_key_permission( key_ref, cred, perm);
}
static int sc_key_getsecurity(struct key * key,char ** _buffer)
{
  *_buffer = NULL;
  return sc_check_key_getsecurity( key, _buffer);
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
static int sc_audit_rule_init(u32 field,u32 op,char * rulestr,void ** lsmrule)
{	return sc_check_audit_rule_init( field, op, rulestr, lsmrule);
}
static int sc_audit_rule_known(struct audit_krule * krule)
{	return sc_check_audit_rule_known( krule);
}
static int sc_audit_rule_match(u32 secid,u32 field,u32 op,void * lsmrule,struct audit_context * actx)
{	return sc_check_audit_rule_match( secid, field, op, lsmrule, actx);
}
static void sc_audit_rule_free(void * lsmrule)
{	return sc_check_audit_rule_free( lsmrule);
}

#endif /* CONFIG_AUDIT */



struct security_operations sc_ops = {
  .name = "scube",

  .ptrace_may_access = sc_ptrace_may_access,
  .ptrace_traceme = sc_ptrace_traceme,
  .capget = sc_capget,
  .capset = sc_capset,
  .capable = sc_capable,
  .acct = sc_acct,
  .sysctl = sc_sysctl,
  .quotactl = sc_quotactl,
  .quota_on = sc_quota_on,
  .syslog = sc_syslog,
  .settime = sc_settime,

  //.vm_enough_memory = sc_vm_enough_memory,

  //.bprm_set_creds = sc_bprm_set_creds,  /* cannot sudo */
  .bprm_check_security = sc_bprm_check_security,
  .bprm_secureexec = sc_bprm_secureexec,
  .bprm_committing_creds = sc_bprm_committing_creds,
  .bprm_committed_creds = sc_bprm_committed_creds,

  .sb_alloc_security = sc_sb_alloc_security,
  .sb_free_security = sc_sb_free_security,
  .sb_copy_data = sc_sb_copy_data,
  .sb_kern_mount = sc_sb_kern_mount,
  .sb_show_options = sc_sb_show_options,
  .sb_statfs = sc_sb_statfs,
  .sb_mount = sc_sb_mount,
  .sb_check_sb = sc_sb_check_sb,
  .sb_umount = sc_sb_umount,
  .sb_umount_close = sc_sb_umount_close,
  .sb_umount_busy = sc_sb_umount_busy,
  .sb_post_remount = sc_sb_post_remount,
  .sb_post_addmount = sc_sb_post_addmount,
  .sb_pivotroot = sc_sb_pivotroot,
  .sb_post_pivotroot = sc_sb_post_pivotroot,
  .sb_set_mnt_opts = sc_sb_set_mnt_opts,
  .sb_clone_mnt_opts = sc_sb_clone_mnt_opts,
  .sb_parse_opts_str = sc_sb_parse_opts_str,

#ifdef CONFIG_SECURITY_PATH
  .path_unlink = sc_path_unlink,
  .path_mkdir = sc_path_mkdir,
  .path_rmdir = sc_path_rmdir,
  .path_mknod = sc_path_mknod,
  .path_truncate = sc_path_truncate,
  .path_symlink = sc_path_symlink,
  .path_link = sc_path_link,
  .path_rename = sc_path_rename,
#endif

  .inode_alloc_security = sc_inode_alloc_security,
  .inode_free_security = sc_inode_free_security,
  .inode_init_security = sc_inode_init_security,
  .inode_create = sc_inode_create,
  .inode_link = sc_inode_link,
  .inode_unlink = sc_inode_unlink,
  .inode_symlink = sc_inode_symlink,
  .inode_mkdir = sc_inode_mkdir,
  .inode_rmdir = sc_inode_rmdir,
  .inode_mknod = sc_inode_mknod,
  .inode_rename = sc_inode_rename,
  .inode_readlink = sc_inode_readlink,
  .inode_follow_link = sc_inode_follow_link,
  .inode_permission = sc_inode_permission,
  .inode_setattr = sc_inode_setattr,
  .inode_getattr = sc_inode_getattr,
  .inode_delete = sc_inode_delete,
  .inode_setxattr = sc_inode_setxattr,
  .inode_post_setxattr = sc_inode_post_setxattr,
  .inode_getxattr = sc_inode_getxattr,
  .inode_listxattr = sc_inode_listxattr,

  .inode_removexattr = sc_inode_removexattr,
  .inode_need_killpriv = sc_inode_need_killpriv,
  .inode_killpriv = sc_inode_killpriv,


  .inode_getsecurity = sc_inode_getsecurity,
  .inode_setsecurity = sc_inode_setsecurity,
  .inode_listsecurity = sc_inode_listsecurity,
  .inode_getsecid = sc_inode_getsecid,
  
  .file_permission = sc_file_permission,
  
  .file_alloc_security = sc_file_alloc_security,
  .file_free_security = sc_file_free_security,
  .file_ioctl = sc_file_ioctl,
  .file_mmap = sc_file_mmap,
  .file_mprotect = sc_file_mprotect,
  .file_lock = sc_file_lock,
  .file_fcntl = sc_file_fcntl,
  .file_set_fowner = sc_file_set_fowner,
  .file_send_sigiotask = sc_file_send_sigiotask,
  .file_receive = sc_file_receive,
  
  .dentry_open = sc_dentry_open,
  .task_create = sc_task_create,
  .cred_free = sc_cred_free,
  .cred_prepare = sc_cred_prepare,
  .cred_commit = sc_cred_commit,
  .kernel_act_as = sc_kernel_act_as,
  .kernel_create_files_as = sc_kernel_create_files_as,
  
  .task_setuid = sc_task_setuid,
  
  .task_fix_setuid = sc_task_fix_setuid,
  
  .task_setgid = sc_task_setgid,
  .task_setpgid = sc_task_setpgid,
  .task_getpgid = sc_task_getpgid,
  .task_getsid = sc_task_getsid,
  .task_getsecid = sc_task_getsecid,
  .task_setgroups = sc_task_setgroups,
  .task_setnice = sc_task_setnice,
  .task_setioprio = sc_task_setioprio,
  .task_getioprio = sc_task_getioprio,
  .task_setrlimit = sc_task_setrlimit,
  .task_setscheduler = sc_task_setscheduler,
  .task_getscheduler = sc_task_getscheduler,
  .task_movememory = sc_task_movememory,
  .task_kill = sc_task_kill,
  .task_wait = sc_task_wait,
  //.task_prctl = sc_task_prctl,
  .task_to_inode = sc_task_to_inode,
  
  .ipc_permission = sc_ipc_permission,
  .ipc_getsecid = sc_ipc_getsecid,

  .msg_msg_alloc_security = sc_msg_msg_alloc_security,
  .msg_msg_free_security = sc_msg_msg_free_security,
  .msg_queue_alloc_security = sc_msg_queue_alloc_security,
  .msg_queue_free_security = sc_msg_queue_free_security,
  .msg_queue_associate = sc_msg_queue_associate,
  .msg_queue_msgctl = sc_msg_queue_msgctl,
  .msg_queue_msgsnd = sc_msg_queue_msgsnd,
  .msg_queue_msgrcv = sc_msg_queue_msgrcv,

  .shm_alloc_security = sc_shm_alloc_security,
  .shm_free_security = sc_shm_free_security,
  .shm_associate = sc_shm_associate,
  .shm_shmctl = sc_shm_shmctl,
  .shm_shmat = sc_shm_shmat,
  .sem_alloc_security = sc_sem_alloc_security,
  .sem_free_security = sc_sem_free_security,
  .sem_associate = sc_sem_associate,
  .sem_semctl = sc_sem_semctl,
  .sem_semop = sc_sem_semop,
  
  .netlink_send = sc_netlink_send,
  .netlink_recv = sc_netlink_recv,
  
  .d_instantiate = sc_d_instantiate,
  .getprocattr = sc_getprocattr,
  .setprocattr = sc_setprocattr,
  .secid_to_secctx = sc_secid_to_secctx,
  .secctx_to_secid = sc_secctx_to_secid,
  .release_secctx = sc_release_secctx,
  
#ifdef CONFIG_SECURITY_NETWORK
  .unix_stream_connect = sc_unix_stream_connect,
  .unix_may_send = sc_unix_may_send,
  .socket_create = sc_socket_create,
  .socket_post_create = sc_socket_post_create,
  .socket_bind = sc_socket_bind,
  .socket_connect = sc_socket_connect,
  .socket_listen = sc_socket_listen,
  .socket_accept = sc_socket_accept,
  .socket_sendmsg = sc_socket_sendmsg,
  .socket_recvmsg = sc_socket_recvmsg,
  .socket_getsockname = sc_socket_getsockname,
  .socket_getpeername = sc_socket_getpeername,
  .socket_getsockopt = sc_socket_getsockopt,
  .socket_setsockopt = sc_socket_setsockopt,
  .socket_shutdown = sc_socket_shutdown,
  .socket_sock_rcv_skb = sc_socket_sock_rcv_skb,
  .socket_getpeersec_stream = sc_socket_getpeersec_stream,
  .socket_getpeersec_dgram = sc_socket_getpeersec_dgram,
  .sk_alloc_security = sc_sk_alloc_security,
  .sk_free_security = sc_sk_free_security,
  .sk_clone_security = sc_sk_clone_security,
  .sk_getsecid = sc_sk_getsecid,
  .sock_graft = sc_sock_graft,
  .inet_conn_request = sc_inet_conn_request,
  .inet_csk_clone = sc_inet_csk_clone,
  .inet_conn_established = sc_inet_conn_established,
  .req_classify_flow = sc_req_classify_flow,
#endif
  
#ifdef CONFIG_SECURITY_NETWORK_XFRM
  .xfrm_policy_alloc_security = sc_xfrm_policy_alloc_security,
  .xfrm_policy_clone_security = sc_xfrm_policy_clone_security,
  .xfrm_policy_free_security = sc_xfrm_policy_free_security,
  .xfrm_policy_delete_security = sc_xfrm_policy_delete_security,
  .xfrm_state_alloc_security = sc_xfrm_state_alloc_security,
  .xfrm_state_free_security = sc_xfrm_state_free_security,
  .xfrm_state_delete_security = sc_xfrm_state_delete_security,
  .xfrm_policy_lookup = sc_xfrm_policy_lookup,
  .xfrm_state_pol_flow_match = sc_xfrm_state_pol_flow_match,
  .xfrm_decode_session = sc_xfrm_decode_session,
#endif
  
#ifdef CONFIG_KEYS
  .key_alloc = sc_key_alloc,
  .key_free = sc_key_free,
  .key_permission = sc_key_permission,
  .key_getsecurity = sc_key_getsecurity,
#endif

#ifdef CONFIG_AUDIT
  .audit_rule_init = sc_audit_rule_init,
  .audit_rule_known = sc_audit_rule_known,
  .audit_rule_match = sc_audit_rule_match,
  .audit_rule_free = sc_audit_rule_free,
#endif
};


extern int register_security (struct security_operations*);
extern int unregister_security (struct security_operations*);

static int __init kadvicelsm_init(void){
  if(register_security(&sc_ops)){
    printk(KERN_INFO "failure register\n");
  }
  printk(KERN_INFO "addhookbase module init\n");
  return 0;
}

static void __exit kadvicelsm_exit(void){

  if(unregister_security(&sc_ops)){
     printk(KERN_INFO "failure unregister\n");
  }
  printk(KERN_INFO "addhookbase module remove\n");
}

//security_initcall(kadvicelsm_init);
module_init(kadvicelsm_init);
module_exit(kadvicelsm_exit);
