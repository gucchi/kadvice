#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>


int lsm_ptrace_may_access(struct task_struct *child, unsigned int mode)
{
return sc_check_ptrace_may_access(child, mode);
}

int lsm_ptrace_traceme(struct task_struct *parent)
{
return sc_check_ptrace_traceme(parent);
}

int lsm_capget(struct task_struct *target,
kernel_cap_t *effective,
kernel_cap_t *inheritable,
kernel_cap_t *permitted)
{
return sc_check_capget(target, effective, inheritable, permitted);
}

int lsm_capset(struct cred *new, const struct cred *old,
const kernel_cap_t *effective,
const kernel_cap_t *inheritable,
const kernel_cap_t *permitted)
{
return sc_check_capset(new, old,
effective, inheritable, permitted);
}

int lsm_capable(int cap)
{
return sc_check_capable(current, current_cred(), cap,
SECURITY_CAP_AUDIT);
}

int lsm_real_capable(struct task_struct *tsk, int cap)
{
const struct cred *cred;
int ret;

cred = get_task_cred(tsk);
ret = sc_check_capable(tsk, cred, cap, SECURITY_CAP_AUDIT);
put_cred(cred);
return ret;
}

int lsm_real_capable_noaudit(struct task_struct *tsk, int cap)
{
const struct cred *cred;
int ret;

cred = get_task_cred(tsk);
ret = sc_check_capable(tsk, cred, cap, SECURITY_CAP_NOAUDIT);
put_cred(cred);
return ret;
}

int lsm_acct(struct file *file)
{
return sc_check_acct(file);
}

int lsm_sysctl(struct ctl_table *table, int op)
{
return sc_check_sysctl(table, op);
}

int lsm_quotactl(int cmds, int type, int id, struct super_block *sb)
{
return sc_check_quotactl(cmds, type, id, sb);
}

int lsm_quota_on(struct dentry *dentry)
{
return sc_check_quota_on(dentry);
}

int lsm_syslog(int type)
{
return sc_check_syslog(type);
}

int lsm_settime(struct timespec *ts, struct timezone *tz)
{
return sc_check_settime(ts, tz);
}

int lsm_vm_enough_memory(long pages)
{
WARN_ON(current->mm == NULL);
return sc_check_vm_enough_memory(current->mm, pages);
}

int lsm_vm_enough_memory_mm(struct mm_struct *mm, long pages)
{
WARN_ON(mm == NULL);
return sc_check_vm_enough_memory(mm, pages);
}

int lsm_vm_enough_memory_kern(long pages)
{
/* If current->mm is a kernel thread then we will pass NULL,
for this specific case that is fine */
return sc_check_vm_enough_memory(current->mm, pages);
}

int lsm_bprm_set_creds(struct linux_binprm *bprm)
{
return sc_check_bprm_set_creds(bprm);
}

int lsm_bprm_check(struct linux_binprm *bprm)
{
return sc_check_bprm_check_security(bprm);
}

void lsm_bprm_committing_creds(struct linux_binprm *bprm)
{
sc_check_bprm_committing_creds(bprm);
}

void lsm_bprm_committed_creds(struct linux_binprm *bprm)
{
sc_check_bprm_committed_creds(bprm);
}

int lsm_bprm_secureexec(struct linux_binprm *bprm)
{
return sc_check_bprm_secureexec(bprm);
}

int lsm_sb_alloc(struct super_block *sb)
{
return sc_check_sb_alloc_security(sb);
}

void lsm_sb_free(struct super_block *sb)
{
sc_check_sb_free_security(sb);
}

int lsm_sb_copy_data(char *orig, char *copy)
{
return sc_check_sb_copy_data(orig, copy);
}
EXPORT_SYMBOL(lsm_sb_copy_data);

int lsm_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
return sc_check_sb_kern_mount(sb, flags, data);
}

int lsm_sb_show_options(struct seq_file *m, struct super_block *sb)
{
return sc_check_sb_show_options(m, sb);
}

int lsm_sb_statfs(struct dentry *dentry)
{
return sc_check_sb_statfs(dentry);
}

int lsm_sb_mount(char *dev_name, struct path *path,
char *type, unsigned long flags, void *data)
{
return sc_check_sb_mount(dev_name, path, type, flags, data);
}

int lsm_sb_check_sb(struct vfsmount *mnt, struct path *path)
{
return sc_check_sb_check_sb(mnt, path);
}

int lsm_sb_umount(struct vfsmount *mnt, int flags)
{
return sc_check_sb_umount(mnt, flags);
}

void lsm_sb_umount_close(struct vfsmount *mnt)
{
sc_check_sb_umount_close(mnt);
}

void lsm_sb_umount_busy(struct vfsmount *mnt)
{
sc_check_sb_umount_busy(mnt);
}

void lsm_sb_post_remount(struct vfsmount *mnt, unsigned long flags, void *data)
{
sc_check_sb_post_remount(mnt, flags, data);
}

void lsm_sb_post_addmount(struct vfsmount *mnt, struct path *mountpoint)
{
sc_check_sb_post_addmount(mnt, mountpoint);
}

int lsm_sb_pivotroot(struct path *old_path, struct path *new_path)
{
return sc_check_sb_pivotroot(old_path, new_path);
}

void lsm_sb_post_pivotroot(struct path *old_path, struct path *new_path)
{
sc_check_sb_post_pivotroot(old_path, new_path);
}

int lsm_sb_set_mnt_opts(struct super_block *sb,
struct lsm_mnt_opts *opts)
{
return sc_check_sb_set_mnt_opts(sb, opts);
}
EXPORT_SYMBOL(lsm_sb_set_mnt_opts);

void lsm_sb_clone_mnt_opts(const struct super_block *oldsb,
struct super_block *newsb)
{
sc_check_sb_clone_mnt_opts(oldsb, newsb);
}
EXPORT_SYMBOL(lsm_sb_clone_mnt_opts);

int lsm_sb_parse_opts_str(char *options, struct lsm_mnt_opts *opts)
{
return sc_check_sb_parse_opts_str(options, opts);
}
EXPORT_SYMBOL(lsm_sb_parse_opts_str);

int lsm_inode_alloc(struct inode *inode)
{
inode->i_security = NULL;
return sc_check_inode_alloc_security(inode);
}

void lsm_inode_free(struct inode *inode)
{
sc_check_inode_free_security(inode);
}

int lsm_inode_init_security(struct inode *inode, struct inode *dir,
char **name, void **value, size_t *len)
{
if (unlikely(IS_PRIVATE(inode)))
return -EOPNOTSUPP;
return sc_check_inode_init_security(inode, dir, name, value, len);
}
EXPORT_SYMBOL(lsm_inode_init_security);

#ifdef CONFIG_SECURITY_PATH
int lsm_path_mknod(struct path *path, struct dentry *dentry, int mode,
unsigned int dev)
{
if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
return 0;
return sc_check_path_mknod(path, dentry, mode, dev);
}
EXPORT_SYMBOL(lsm_path_mknod);

int lsm_path_mkdir(struct path *path, struct dentry *dentry, int mode)
{
if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
return 0;
return sc_check_path_mkdir(path, dentry, mode);
}

int lsm_path_rmdir(struct path *path, struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
return 0;
return sc_check_path_rmdir(path, dentry);
}

int lsm_path_unlink(struct path *path, struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
return 0;
return sc_check_path_unlink(path, dentry);
}

int lsm_path_symlink(struct path *path, struct dentry *dentry,
const char *old_name)
{
if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
return 0;
return sc_check_path_symlink(path, dentry, old_name);
}

int lsm_path_link(struct dentry *old_dentry, struct path *new_dir,
struct dentry *new_dentry)
{
if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
return 0;
return sc_check_path_link(old_dentry, new_dir, new_dentry);
}

int lsm_path_rename(struct path *old_dir, struct dentry *old_dentry,
struct path *new_dir, struct dentry *new_dentry)
{
if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
(new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
return 0;
return sc_check_path_rename(old_dir, old_dentry, new_dir,
new_dentry);
}

int lsm_path_truncate(struct path *path, loff_t length,
unsigned int time_attrs)
{
if (unlikely(IS_PRIVATE(path->dentry->d_inode)))
return 0;
return sc_check_path_truncate(path, length, time_attrs);
}
#endif

int lsm_inode_create(struct inode *dir, struct dentry *dentry, int mode)
{
if (unlikely(IS_PRIVATE(dir)))
return 0;
return sc_check_inode_create(dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(lsm_inode_create);

int lsm_inode_link(struct dentry *old_dentry, struct inode *dir,
struct dentry *new_dentry)
{
if (unlikely(IS_PRIVATE(old_dentry->d_inode)))
return 0;
return sc_check_inode_link(old_dentry, dir, new_dentry);
}

int lsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_unlink(dir, dentry);
}

int lsm_inode_symlink(struct inode *dir, struct dentry *dentry,
const char *old_name)
{
if (unlikely(IS_PRIVATE(dir)))
return 0;
return sc_check_inode_symlink(dir, dentry, old_name);
}

int lsm_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
if (unlikely(IS_PRIVATE(dir)))
return 0;
return sc_check_inode_mkdir(dir, dentry, mode);
}
EXPORT_SYMBOL_GPL(lsm_inode_mkdir);

int lsm_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_rmdir(dir, dentry);
}

int lsm_inode_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
if (unlikely(IS_PRIVATE(dir)))
return 0;
return sc_check_inode_mknod(dir, dentry, mode, dev);
}

int lsm_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
struct inode *new_dir, struct dentry *new_dentry)
{
if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||
(new_dentry->d_inode && IS_PRIVATE(new_dentry->d_inode))))
return 0;
return sc_check_inode_rename(old_dir, old_dentry,
new_dir, new_dentry);
}

int lsm_inode_readlink(struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_readlink(dentry);
}

int lsm_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_follow_link(dentry, nd);
}

int lsm_inode_permission(struct inode *inode, int mask)
{
if (unlikely(IS_PRIVATE(inode)))
return 0;
return sc_check_inode_permission(inode, mask);
}

int lsm_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_setattr(dentry, attr);
}
EXPORT_SYMBOL_GPL(lsm_inode_setattr);

int lsm_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_getattr(mnt, dentry);
}

void lsm_inode_delete(struct inode *inode)
{
if (unlikely(IS_PRIVATE(inode)))
return;
sc_check_inode_delete(inode);
}

int lsm_inode_setxattr(struct dentry *dentry, const char *name,
const void *value, size_t size, int flags)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_setxattr(dentry, name, value, size, flags);
}

void lsm_inode_post_setxattr(struct dentry *dentry, const char *name,
const void *value, size_t size, int flags)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return;
sc_check_inode_post_setxattr(dentry, name, value, size, flags);
}

int lsm_inode_getxattr(struct dentry *dentry, const char *name)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_getxattr(dentry, name);
}

int lsm_inode_listxattr(struct dentry *dentry)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_listxattr(dentry);
}

int lsm_inode_removexattr(struct dentry *dentry, const char *name)
{
if (unlikely(IS_PRIVATE(dentry->d_inode)))
return 0;
return sc_check_inode_removexattr(dentry, name);
}

int lsm_inode_need_killpriv(struct dentry *dentry)
{
return sc_check_inode_need_killpriv(dentry);
}

int lsm_inode_killpriv(struct dentry *dentry)
{
return sc_check_inode_killpriv(dentry);
}

int lsm_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
if (unlikely(IS_PRIVATE(inode)))
return 0;
return sc_check_inode_getsecurity(inode, name, buffer, alloc);
}

int lsm_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
if (unlikely(IS_PRIVATE(inode)))
return 0;
return sc_check_inode_setsecurity(inode, name, value, size, flags);
}

int lsm_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
if (unlikely(IS_PRIVATE(inode)))
return 0;
return sc_check_inode_listsecurity(inode, buffer, buffer_size);
}

void lsm_inode_getsecid(const struct inode *inode, u32 *secid)
{
sc_check_inode_getsecid(inode, secid);
}

int lsm_file_permission(struct file *file, int mask)
{
return sc_check_file_permission(file, mask);
}

int lsm_file_alloc(struct file *file)
{
return sc_check_file_alloc_security(file);
}

void lsm_file_free(struct file *file)
{
sc_check_file_free_security(file);
}

int lsm_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
return sc_check_file_ioctl(file, cmd, arg);
}

int lsm_file_mmap(struct file *file, unsigned long reqprot,
unsigned long prot, unsigned long flags,
unsigned long addr, unsigned long addr_only)
{
return sc_check_file_mmap(file, reqprot, prot, flags, addr, addr_only);
}

int lsm_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
unsigned long prot)
{
return sc_check_file_mprotect(vma, reqprot, prot);
}

int lsm_file_lock(struct file *file, unsigned int cmd)
{
return sc_check_file_lock(file, cmd);
}

int lsm_file_fcntl(struct file *file, unsigned int cmd, unsigned long arg)
{
return sc_check_file_fcntl(file, cmd, arg);
}

int lsm_file_set_fowner(struct file *file)
{
return sc_check_file_set_fowner(file);
}

int lsm_file_send_sigiotask(struct task_struct *tsk,
struct fown_struct *fown, int sig)
{
return sc_check_file_send_sigiotask(tsk, fown, sig);
}

int lsm_file_receive(struct file *file)
{
return sc_check_file_receive(file);
}

int lsm_dentry_open(struct file *file, const struct cred *cred)
{
return sc_check_dentry_open(file, cred);
}

int lsm_task_create(unsigned long clone_flags)
{
return sc_check_task_create(clone_flags);
}

void lsm_cred_free(struct cred *cred)
{
sc_check_cred_free(cred);
}

int lsm_prepare_creds(struct cred *new, const struct cred *old, gfp_t gfp)
{
return sc_check_cred_prepare(new, old, gfp);
}

void lsm_commit_creds(struct cred *new, const struct cred *old)
{
sc_check_cred_commit(new, old);
}

int lsm_kernel_act_as(struct cred *new, u32 secid)
{
return sc_check_kernel_act_as(new, secid);
}

int lsm_kernel_create_files_as(struct cred *new, struct inode *inode)
{
return sc_check_kernel_create_files_as(new, inode);
}

int lsm_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
return sc_check_task_setuid(id0, id1, id2, flags);
}

int lsm_task_fix_setuid(struct cred *new, const struct cred *old,
int flags)
{
return sc_check_task_fix_setuid(new, old, flags);
}

int lsm_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
return sc_check_task_setgid(id0, id1, id2, flags);
}

int lsm_task_setpgid(struct task_struct *p, pid_t pgid)
{
return sc_check_task_setpgid(p, pgid);
}

int lsm_task_getpgid(struct task_struct *p)
{
return sc_check_task_getpgid(p);
}

int lsm_task_getsid(struct task_struct *p)
{
return sc_check_task_getsid(p);
}

void lsm_task_getsecid(struct task_struct *p, u32 *secid)
{
sc_check_task_getsecid(p, secid);
}
EXPORT_SYMBOL(lsm_task_getsecid);

int lsm_task_setgroups(struct group_info *group_info)
{
return sc_check_task_setgroups(group_info);
}

int lsm_task_setnice(struct task_struct *p, int nice)
{
return sc_check_task_setnice(p, nice);
}

int lsm_task_setioprio(struct task_struct *p, int ioprio)
{
return sc_check_task_setioprio(p, ioprio);
}

int lsm_task_getioprio(struct task_struct *p)
{
return sc_check_task_getioprio(p);
}

int lsm_task_setrlimit(unsigned int resource, struct rlimit *new_rlim)
{
return sc_check_task_setrlimit(resource, new_rlim);
}

int lsm_task_setscheduler(struct task_struct *p,
int policy, struct sched_param *lp)
{
return sc_check_task_setscheduler(p, policy, lp);
}

int lsm_task_getscheduler(struct task_struct *p)
{
return sc_check_task_getscheduler(p);
}

int lsm_task_movememory(struct task_struct *p)
{
return sc_check_task_movememory(p);
}

int lsm_task_kill(struct task_struct *p, struct siginfo *info,
int sig, u32 secid)
{
return sc_check_task_kill(p, info, sig, secid);
}

int lsm_task_wait(struct task_struct *p)
{
return sc_check_task_wait(p);
}

int lsm_task_prctl(int option, unsigned long arg2, unsigned long arg3,
unsigned long arg4, unsigned long arg5)
{
return sc_check_task_prctl(option, arg2, arg3, arg4, arg5);
}

void lsm_task_to_inode(struct task_struct *p, struct inode *inode)
{
sc_check_task_to_inode(p, inode);
}

int lsm_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
return sc_check_ipc_permission(ipcp, flag);
}

void lsm_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
sc_check_ipc_getsecid(ipcp, secid);
}

int lsm_msg_msg_alloc(struct msg_msg *msg)
{
return sc_check_msg_msg_alloc_security(msg);
}

void lsm_msg_msg_free(struct msg_msg *msg)
{
sc_check_msg_msg_free_security(msg);
}

int lsm_msg_queue_alloc(struct msg_queue *msq)
{
return sc_check_msg_queue_alloc_security(msq);
}

void lsm_msg_queue_free(struct msg_queue *msq)
{
sc_check_msg_queue_free_security(msq);
}

int lsm_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
return sc_check_msg_queue_associate(msq, msqflg);
}

int lsm_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
return sc_check_msg_queue_msgctl(msq, cmd);
}

int lsm_msg_queue_msgsnd(struct msg_queue *msq,
struct msg_msg *msg, int msqflg)
{
return sc_check_msg_queue_msgsnd(msq, msg, msqflg);
}

int lsm_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
struct task_struct *target, long type, int mode)
{
return sc_check_msg_queue_msgrcv(msq, msg, target, type, mode);
}

int lsm_shm_alloc(struct shmid_kernel *shp)
{
return sc_check_shm_alloc_security(shp);
}

void lsm_shm_free(struct shmid_kernel *shp)
{
sc_check_shm_free_security(shp);
}

int lsm_shm_associate(struct shmid_kernel *shp, int shmflg)
{
return sc_check_shm_associate(shp, shmflg);
}

int lsm_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
return sc_check_shm_shmctl(shp, cmd);
}

int lsm_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr, int shmflg)
{
return sc_check_shm_shmat(shp, shmaddr, shmflg);
}

int lsm_sem_alloc(struct sem_array *sma)
{
return sc_check_sem_alloc_security(sma);
}

void lsm_sem_free(struct sem_array *sma)
{
sc_check_sem_free_security(sma);
}

int lsm_sem_associate(struct sem_array *sma, int semflg)
{
return sc_check_sem_associate(sma, semflg);
}

int lsm_sem_semctl(struct sem_array *sma, int cmd)
{
return sc_check_sem_semctl(sma, cmd);
}

int lsm_sem_semop(struct sem_array *sma, struct sembuf *sops,
unsigned int nsops, int alter)
{
return sc_check_sem_semop(sma, sops, nsops, alter);
}

void lsm_d_instantiate(struct dentry *dentry, struct inode *inode)
{
if (unlikely(inode && IS_PRIVATE(inode)))
return;
sc_check_d_instantiate(dentry, inode);
}
EXPORT_SYMBOL(lsm_d_instantiate);

int lsm_getprocattr(struct task_struct *p, char *name, char **value)
{
return sc_check_getprocattr(p, name, value);
}

int lsm_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
return sc_check_setprocattr(p, name, value, size);
}

int lsm_netlink_send(struct sock *sk, struct sk_buff *skb)
{
return sc_check_netlink_send(sk, skb);
}

int lsm_netlink_recv(struct sk_buff *skb, int cap)
{
return sc_check_netlink_recv(skb, cap);
}
EXPORT_SYMBOL(lsm_netlink_recv);

int lsm_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
return sc_check_secid_to_secctx(secid, secdata, seclen);
}
EXPORT_SYMBOL(lsm_secid_to_secctx);

int lsm_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
return sc_check_secctx_to_secid(secdata, seclen, secid);
}
EXPORT_SYMBOL(lsm_secctx_to_secid);

void lsm_release_secctx(char *secdata, u32 seclen)
{
sc_check_release_secctx(secdata, seclen);
}
EXPORT_SYMBOL(lsm_release_secctx);

#ifdef CONFIG_SECURITY_NETWORK

int lsm_unix_stream_connect(struct socket *sock, struct socket *other,
struct sock *newsk)
{
return sc_check_unix_stream_connect(sock, other, newsk);
}
EXPORT_SYMBOL(lsm_unix_stream_connect);

int lsm_unix_may_send(struct socket *sock,  struct socket *other)
{
return sc_check_unix_may_send(sock, other);
}
EXPORT_SYMBOL(lsm_unix_may_send);

int lsm_socket_create(int family, int type, int protocol, int kern)
{
return sc_check_socket_create(family, type, protocol, kern);
}

int lsm_socket_post_create(struct socket *sock, int family,
int type, int protocol, int kern)
{
return sc_check_socket_post_create(sock, family, type,
protocol, kern);
}

int lsm_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
return sc_check_socket_bind(sock, address, addrlen);
}

int lsm_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
return sc_check_socket_connect(sock, address, addrlen);
}

int lsm_socket_listen(struct socket *sock, int backlog)
{
return sc_check_socket_listen(sock, backlog);
}

int lsm_socket_accept(struct socket *sock, struct socket *newsock)
{
return sc_check_socket_accept(sock, newsock);
}

int lsm_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
return sc_check_socket_sendmsg(sock, msg, size);
}

int lsm_socket_recvmsg(struct socket *sock, struct msghdr *msg,
int size, int flags)
{
return sc_check_socket_recvmsg(sock, msg, size, flags);
}

int lsm_socket_getsockname(struct socket *sock)
{
return sc_check_socket_getsockname(sock);
}

int lsm_socket_getpeername(struct socket *sock)
{
return sc_check_socket_getpeername(sock);
}

int lsm_socket_getsockopt(struct socket *sock, int level, int optname)
{
return sc_check_socket_getsockopt(sock, level, optname);
}

int lsm_socket_setsockopt(struct socket *sock, int level, int optname)
{
return sc_check_socket_setsockopt(sock, level, optname);
}

int lsm_socket_shutdown(struct socket *sock, int how)
{
return sc_check_socket_shutdown(sock, how);
}

int lsm_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
return sc_check_socket_sock_rcv_skb(sk, skb);
}
EXPORT_SYMBOL(lsm_sock_rcv_skb);

int lsm_socket_getpeersec_stream(struct socket *sock, char __user *optval,
int __user *optlen, unsigned int len)
{
return sc_check_socket_getpeersec_stream(sock, optval, optlen, len);
}

int lsm_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
return sc_check_socket_getpeersec_dgram(sock, skb, secid);
}
EXPORT_SYMBOL(lsm_socket_getpeersec_dgram);

int lsm_sk_alloc(struct sock *sk, int family, gfp_t priority)
{
return sc_check_sk_alloc_security(sk, family, priority);
}

void lsm_sk_free(struct sock *sk)
{
sc_check_sk_free_security(sk);
}

void lsm_sk_clone(const struct sock *sk, struct sock *newsk)
{
sc_check_sk_clone_security(sk, newsk);
}

void lsm_sk_classify_flow(struct sock *sk, struct flowi *fl)
{
sc_check_sk_getsecid(sk, &fl->secid);
}
EXPORT_SYMBOL(lsm_sk_classify_flow);

void lsm_req_classify_flow(const struct request_sock *req, struct flowi *fl)
{
sc_check_req_classify_flow(req, fl);
}
EXPORT_SYMBOL(lsm_req_classify_flow);

void lsm_sock_graft(struct sock *sk, struct socket *parent)
{
sc_check_sock_graft(sk, parent);
}
EXPORT_SYMBOL(lsm_sock_graft);

int lsm_inet_conn_request(struct sock *sk,
struct sk_buff *skb, struct request_sock *req)
{
return sc_check_inet_conn_request(sk, skb, req);
}
EXPORT_SYMBOL(lsm_inet_conn_request);

void lsm_inet_csk_clone(struct sock *newsk,
const struct request_sock *req)
{
sc_check_inet_csk_clone(newsk, req);
}

void lsm_inet_conn_established(struct sock *sk,
struct sk_buff *skb)
{
sc_check_inet_conn_established(sk, skb);
}

#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM

int lsm_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx)
{
return sc_check_xfrm_policy_alloc_security(ctxp, sec_ctx);
}
EXPORT_SYMBOL(lsm_xfrm_policy_alloc);

int lsm_xfrm_policy_clone(struct xfrm_sec_ctx *old_ctx,
struct xfrm_sec_ctx **new_ctxp)
{
return sc_check_xfrm_policy_clone_security(old_ctx, new_ctxp);
}

void lsm_xfrm_policy_free(struct xfrm_sec_ctx *ctx)
{
sc_check_xfrm_policy_free_security(ctx);
}
EXPORT_SYMBOL(lsm_xfrm_policy_free);

int lsm_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)
{
return sc_check_xfrm_policy_delete_security(ctx);
}

int lsm_xfrm_state_alloc(struct xfrm_state *x, struct xfrm_user_sec_ctx *sec_ctx)
{
return sc_check_xfrm_state_alloc_security(x, sec_ctx, 0);
}
EXPORT_SYMBOL(lsm_xfrm_state_alloc);

int lsm_xfrm_state_alloc_acquire(struct xfrm_state *x,
struct xfrm_sec_ctx *polsec, u32 secid)
{
if (!polsec)
return 0;
/*
* We want the context to be taken from secid which is usually
* from the sock.
*/
return sc_check_xfrm_state_alloc_security(x, NULL, secid);
}

int lsm_xfrm_state_delete(struct xfrm_state *x)
{
return sc_check_xfrm_state_delete_security(x);
}
EXPORT_SYMBOL(lsm_xfrm_state_delete);

void lsm_xfrm_state_free(struct xfrm_state *x)
{
sc_check_xfrm_state_free_security(x);
}

int lsm_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir)
{
return sc_check_xfrm_policy_lookup(ctx, fl_secid, dir);
}

int lsm_xfrm_state_pol_flow_match(struct xfrm_state *x,
struct xfrm_policy *xp, struct flowi *fl)
{
return sc_check_xfrm_state_pol_flow_match(x, xp, fl);
}

int lsm_xfrm_decode_session(struct sk_buff *skb, u32 *secid)
{
return sc_check_xfrm_decode_session(skb, secid, 1);
}

void lsm_skb_classify_flow(struct sk_buff *skb, struct flowi *fl)
{
int rc = sc_check_xfrm_decode_session(skb, &fl->secid, 0);

BUG_ON(rc);
}
EXPORT_SYMBOL(lsm_skb_classify_flow);

#endif	/* CONFIG_SECURITY_NETWORK_XFRM */

#ifdef CONFIG_KEYS

int lsm_key_alloc(struct key *key, const struct cred *cred,
unsigned long flags)
{
return sc_check_key_alloc(key, cred, flags);
}

void lsm_key_free(struct key *key)
{
sc_check_key_free(key);
}

int lsm_key_permission(key_ref_t key_ref,
const struct cred *cred, key_perm_t perm)
{
return sc_check_key_permission(key_ref, cred, perm);
}

int lsm_key_getsecurity(struct key *key, char **_buffer)
{
return sc_check_key_getsecurity(key, _buffer);
}

#endif	/* CONFIG_KEYS */

#ifdef CONFIG_AUDIT

int lsm_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
return sc_check_audit_rule_init(field, op, rulestr, lsmrule);
}

int lsm_audit_rule_known(struct audit_krule *krule)
{
return sc_check_audit_rule_known(krule);
}

void lsm_audit_rule_free(void *lsmrule)
{
sc_check_audit_rule_free(lsmrule);
}

int lsm_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
struct audit_context *actx)
{
return sc_check_audit_rule_match(secid, field, op, lsmrule, actx);
}

#endif /* CONFIG_AUDIT */
struct security_operations lsm_security_ops = {
.ptrace_may_access = lsm_ptrace_may_access,
.ptrace_traceme = lsm_ptrace_traceme,
.capget = lsm_capget,
.capset = lsm_capset,
.capable = lsm_capable,
.real_capable = lsm_real_capable,
.real_capable_noaudit = lsm_real_capable_noaudit,
.acct = lsm_acct,
.sysctl = lsm_sysctl,
.quotactl = lsm_quotactl,
.quota_on = lsm_quota_on,
.syslog = lsm_syslog,
.settime = lsm_settime,
.vm_enough_memory = lsm_vm_enough_memory,
.vm_enough_memory_mm = lsm_vm_enough_memory_mm,
.vm_enough_memory_kern = lsm_vm_enough_memory_kern,
.bprm_set_creds = lsm_bprm_set_creds,
.bprm_check = lsm_bprm_check,
.bprm_committing_creds = lsm_bprm_committing_creds,
.bprm_committed_creds = lsm_bprm_committed_creds,
.bprm_secureexec = lsm_bprm_secureexec,
.sb_alloc = lsm_sb_alloc,
.sb_free = lsm_sb_free,
.sb_copy_data = lsm_sb_copy_data,
.sb_kern_mount = lsm_sb_kern_mount,
.sb_show_options = lsm_sb_show_options,
.sb_statfs = lsm_sb_statfs,
.sb_mount = lsm_sb_mount,
.sb_check_sb = lsm_sb_check_sb,
.sb_umount = lsm_sb_umount,
.sb_umount_close = lsm_sb_umount_close,
.sb_umount_busy = lsm_sb_umount_busy,
.sb_post_remount = lsm_sb_post_remount,
.sb_post_addmount = lsm_sb_post_addmount,
.sb_pivotroot = lsm_sb_pivotroot,
.sb_post_pivotroot = lsm_sb_post_pivotroot,
.sb_set_mnt_opts = lsm_sb_set_mnt_opts,
.sb_clone_mnt_opts = lsm_sb_clone_mnt_opts,
.sb_parse_opts_str = lsm_sb_parse_opts_str,
.inode_alloc = lsm_inode_alloc,
.inode_free = lsm_inode_free,
.inode_init_security = lsm_inode_init_security,
.path_mknod = lsm_path_mknod,
.path_mkdir = lsm_path_mkdir,
.path_rmdir = lsm_path_rmdir,
.path_unlink = lsm_path_unlink,
.path_symlink = lsm_path_symlink,
.path_link = lsm_path_link,
.path_rename = lsm_path_rename,
.path_truncate = lsm_path_truncate,
.inode_create = lsm_inode_create,
.inode_link = lsm_inode_link,
.inode_unlink = lsm_inode_unlink,
.inode_symlink = lsm_inode_symlink,
.inode_mkdir = lsm_inode_mkdir,
.inode_rmdir = lsm_inode_rmdir,
.inode_mknod = lsm_inode_mknod,
.inode_rename = lsm_inode_rename,
.inode_readlink = lsm_inode_readlink,
.inode_follow_link = lsm_inode_follow_link,
.inode_permission = lsm_inode_permission,
.inode_setattr = lsm_inode_setattr,
.inode_getattr = lsm_inode_getattr,
.inode_delete = lsm_inode_delete,
.inode_setxattr = lsm_inode_setxattr,
.inode_post_setxattr = lsm_inode_post_setxattr,
.inode_getxattr = lsm_inode_getxattr,
.inode_listxattr = lsm_inode_listxattr,
.inode_removexattr = lsm_inode_removexattr,
.inode_need_killpriv = lsm_inode_need_killpriv,
.inode_killpriv = lsm_inode_killpriv,
.inode_getsecurity = lsm_inode_getsecurity,
.inode_setsecurity = lsm_inode_setsecurity,
.inode_listsecurity = lsm_inode_listsecurity,
.inode_getsecid = lsm_inode_getsecid,
.file_permission = lsm_file_permission,
.file_alloc = lsm_file_alloc,
.file_free = lsm_file_free,
.file_ioctl = lsm_file_ioctl,
.file_mmap = lsm_file_mmap,
.file_mprotect = lsm_file_mprotect,
.file_lock = lsm_file_lock,
.file_fcntl = lsm_file_fcntl,
.file_set_fowner = lsm_file_set_fowner,
.file_send_sigiotask = lsm_file_send_sigiotask,
.file_receive = lsm_file_receive,
.dentry_open = lsm_dentry_open,
.task_create = lsm_task_create,
.cred_free = lsm_cred_free,
.prepare_creds = lsm_prepare_creds,
.commit_creds = lsm_commit_creds,
.kernel_act_as = lsm_kernel_act_as,
.kernel_create_files_as = lsm_kernel_create_files_as,
.task_setuid = lsm_task_setuid,
.task_fix_setuid = lsm_task_fix_setuid,
.task_setgid = lsm_task_setgid,
.task_setpgid = lsm_task_setpgid,
.task_getpgid = lsm_task_getpgid,
.task_getsid = lsm_task_getsid,
.task_getsecid = lsm_task_getsecid,
.task_setgroups = lsm_task_setgroups,
.task_setnice = lsm_task_setnice,
.task_setioprio = lsm_task_setioprio,
.task_getioprio = lsm_task_getioprio,
.task_setrlimit = lsm_task_setrlimit,
.task_setscheduler = lsm_task_setscheduler,
.task_getscheduler = lsm_task_getscheduler,
.task_movememory = lsm_task_movememory,
.task_kill = lsm_task_kill,
.task_wait = lsm_task_wait,
.task_prctl = lsm_task_prctl,
.task_to_inode = lsm_task_to_inode,
.ipc_permission = lsm_ipc_permission,
.ipc_getsecid = lsm_ipc_getsecid,
.msg_msg_alloc = lsm_msg_msg_alloc,
.msg_msg_free = lsm_msg_msg_free,
.msg_queue_alloc = lsm_msg_queue_alloc,
.msg_queue_free = lsm_msg_queue_free,
.msg_queue_associate = lsm_msg_queue_associate,
.msg_queue_msgctl = lsm_msg_queue_msgctl,
.msg_queue_msgsnd = lsm_msg_queue_msgsnd,
.msg_queue_msgrcv = lsm_msg_queue_msgrcv,
.shm_alloc = lsm_shm_alloc,
.shm_free = lsm_shm_free,
.shm_associate = lsm_shm_associate,
.shm_shmctl = lsm_shm_shmctl,
.shm_shmat = lsm_shm_shmat,
.sem_alloc = lsm_sem_alloc,
.sem_free = lsm_sem_free,
.sem_associate = lsm_sem_associate,
.sem_semctl = lsm_sem_semctl,
.sem_semop = lsm_sem_semop,
.d_instantiate = lsm_d_instantiate,
.getprocattr = lsm_getprocattr,
.setprocattr = lsm_setprocattr,
.netlink_send = lsm_netlink_send,
.netlink_recv = lsm_netlink_recv,
.secid_to_secctx = lsm_secid_to_secctx,
.secctx_to_secid = lsm_secctx_to_secid,
.release_secctx = lsm_release_secctx,
.unix_stream_connect = lsm_unix_stream_connect,
.unix_may_send = lsm_unix_may_send,
.socket_create = lsm_socket_create,
.socket_post_create = lsm_socket_post_create,
.socket_bind = lsm_socket_bind,
.socket_connect = lsm_socket_connect,
.socket_listen = lsm_socket_listen,
.socket_accept = lsm_socket_accept,
.socket_sendmsg = lsm_socket_sendmsg,
.socket_recvmsg = lsm_socket_recvmsg,
.socket_getsockname = lsm_socket_getsockname,
.socket_getpeername = lsm_socket_getpeername,
.socket_getsockopt = lsm_socket_getsockopt,
.socket_setsockopt = lsm_socket_setsockopt,
.socket_shutdown = lsm_socket_shutdown,
.sock_rcv_skb = lsm_sock_rcv_skb,
.socket_getpeersec_stream = lsm_socket_getpeersec_stream,
.socket_getpeersec_dgram = lsm_socket_getpeersec_dgram,
.sk_alloc = lsm_sk_alloc,
.sk_free = lsm_sk_free,
.sk_clone = lsm_sk_clone,
.sk_classify_flow = lsm_sk_classify_flow,
.req_classify_flow = lsm_req_classify_flow,
.sock_graft = lsm_sock_graft,
.inet_conn_request = lsm_inet_conn_request,
.inet_csk_clone = lsm_inet_csk_clone,
.inet_conn_established = lsm_inet_conn_established,
.xfrm_policy_alloc = lsm_xfrm_policy_alloc,
.xfrm_policy_clone = lsm_xfrm_policy_clone,
.xfrm_policy_free = lsm_xfrm_policy_free,
.xfrm_policy_delete = lsm_xfrm_policy_delete,
.xfrm_state_alloc = lsm_xfrm_state_alloc,
.xfrm_state_alloc_acquire = lsm_xfrm_state_alloc_acquire,
.xfrm_state_delete = lsm_xfrm_state_delete,
.xfrm_state_free = lsm_xfrm_state_free,
.xfrm_policy_lookup = lsm_xfrm_policy_lookup,
.xfrm_state_pol_flow_match = lsm_xfrm_state_pol_flow_match,
.xfrm_decode_session = lsm_xfrm_decode_session,
.skb_classify_flow = lsm_skb_classify_flow,
.key_alloc = lsm_key_alloc,
.key_free = lsm_key_free,
.key_permission = lsm_key_permission,
.key_getsecurity = lsm_key_getsecurity,
.audit_rule_init = lsm_audit_rule_init,
.audit_rule_known = lsm_audit_rule_known,
.audit_rule_free = lsm_audit_rule_free,
.audit_rule_match = lsm_audit_rule_match,
};

static int securitycube_init(void)
{
  if(register_security(&lsm_security_ops)) {
	printk(KERN_INFO "failure register\n");
  }
  printk(KERN_INFO "security cube properly registered\n");
  return 0;
}

static void security_exit(void)
{

}

module_init(securitycube_init);
module_exit(security_exit);
EXPORT_SYMBOL(lsm_security_ops);
