#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>

#include "ka/secops.h"

#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/xattr.h>
#include <linux/hugetlb.h>
#include <linux/ptrace.h>
#include <linux/file.h>


#include "ka_security_str_lsm.h"


MODULE_LICENSE("GPL");


int dummy_test_ptrace (struct task_struct *parent, struct task_struct *child)
{
	return 0;
}

int dummy_test_capget (struct task_struct *target, kernel_cap_t * effective,
			 kernel_cap_t * inheritable, kernel_cap_t * permitted)
{
	*effective = *inheritable = *permitted = 0;
	if (target->euid == 0) {
		*permitted |= (~0 & ~CAP_FS_MASK);
		*effective |= (~0 & ~CAP_TO_MASK(CAP_SETPCAP) & ~CAP_FS_MASK);
	}
	if (target->fsuid == 0) {
		*permitted |= CAP_FS_MASK;
		*effective |= CAP_FS_MASK;
	}
	return 0;
}

int dummy_test_capset_check (struct task_struct *target,
			       kernel_cap_t * effective,
			       kernel_cap_t * inheritable,
			       kernel_cap_t * permitted)
{
	return -EPERM;
}

void dummy_test_capset_set (struct task_struct *target,
			      kernel_cap_t * effective,
			      kernel_cap_t * inheritable,
			      kernel_cap_t * permitted)
{
	return;
}

int dummy_test_acct (struct file *file)
{
	return 0;
}

int dummy_test_capable (struct task_struct *tsk, int cap)
{
	if (cap_raised (tsk->cap_effective, cap))
		return 0;
	return -EPERM;
}

int dummy_test_sysctl (ctl_table * table, int op)
{
	return 0;
}

int dummy_test_quotactl (int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

int dummy_test_quota_on (struct dentry *dentry)
{
	return 0;
}

int dummy_test_syslog (int type)
{
	if ((type != 3 && type != 10) && current->euid)
		return -EPERM;
	return 0;
}

int dummy_test_settime(struct timespec *ts, struct timezone *tz)
{
	if (!capable(CAP_SYS_TIME))
		return -EPERM;
	return 0;
}

int dummy_test_vm_enough_memory(struct mm_struct *mm, long pages)
{
	int cap_sys_admin = 0;

	if (dummy_test_capable(current, CAP_SYS_ADMIN) == 0)
		cap_sys_admin = 1;
	return __vm_enough_memory(mm, pages, cap_sys_admin);
}

int dummy_test_bprm_alloc_security (struct linux_binprm *bprm)
{
	return 0;
}

void dummy_test_bprm_free_security (struct linux_binprm *bprm)
{
	return;
}

void dummy_test_bprm_apply_creds (struct linux_binprm *bprm, int unsafe)
{
	if (bprm->e_uid != current->uid || bprm->e_gid != current->gid) {
		set_dumpable(current->mm, suid_dumpable);

		if ((unsafe & ~LSM_UNSAFE_PTRACE_CAP) && !capable(CAP_SETUID)) {
			bprm->e_uid = current->uid;
			bprm->e_gid = current->gid;
		}
	}

	current->suid = current->euid = current->fsuid = bprm->e_uid;
	current->sgid = current->egid = current->fsgid = bprm->e_gid;

	dummy_test_capget(current, &current->cap_effective, &current->cap_inheritable, &current->cap_permitted);
}

void dummy_test_bprm_post_apply_creds (struct linux_binprm *bprm)
{
	return;
}

int dummy_test_bprm_set_security (struct linux_binprm *bprm)
{
	return 0;
}

int dummy_test_bprm_check_security (struct linux_binprm *bprm)
{
	return 0;
}

int dummy_test_bprm_secureexec (struct linux_binprm *bprm)
{
	/* The new userland will simply use the value provided
	   in the AT_SECURE field to decide whether secure mode
	   is required.  Hence, this logic is required to preserve
	   the legacy decision algorithm used by the old userland. */
	return (current->euid != current->uid ||
		current->egid != current->gid);
}

int dummy_test_sb_alloc_security (struct super_block *sb)
{
	return 0;
}

void dummy_test_sb_free_security (struct super_block *sb)
{
	return;
}

int dummy_test_sb_copy_data (struct file_system_type *type,
			       void *orig, void *copy)
{
	return 0;
}

int dummy_test_sb_kern_mount (struct super_block *sb, void *data)
{
	return 0;
}

int dummy_test_sb_statfs (struct dentry *dentry)
{
	return 0;
}

int dummy_test_sb_mount (char *dev_name, struct nameidata *nd, char *type,
			   unsigned long flags, void *data)
{
	return 0;
}

int dummy_test_sb_check_sb (struct vfsmount *mnt, struct nameidata *nd)
{
	return 0;
}

int dummy_test_sb_umount (struct vfsmount *mnt, int flags)
{
	return 0;
}

void dummy_test_sb_umount_close (struct vfsmount *mnt)
{
	return;
}

void dummy_test_sb_umount_busy (struct vfsmount *mnt)
{
	return;
}

void dummy_test_sb_post_remount (struct vfsmount *mnt, unsigned long flags,
				   void *data)
{
	return;
}


void dummy_test_sb_post_mountroot (void)
{
	return;
}

void dummy_test_sb_post_addmount (struct vfsmount *mnt, struct nameidata *nd)
{
	return;
}

int dummy_test_sb_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd)
{
	return 0;
}

void dummy_test_sb_post_pivotroot (struct nameidata *old_nd, struct nameidata *new_nd)
{
	return;
}

int dummy_test_inode_alloc_security (struct inode *inode)
{
	return 0;
}

void dummy_test_inode_free_security (struct inode *inode)
{
	return;
}

int dummy_test_inode_init_security (struct inode *inode, struct inode *dir,
				      char **name, void **value, size_t *len)
{
	return -EOPNOTSUPP;
}

int dummy_test_inode_create (struct inode *inode, struct dentry *dentry,
			       int mask)
{
	return 0;
}

int dummy_test_inode_link (struct dentry *old_dentry, struct inode *inode,
			     struct dentry *new_dentry)
{
	return 0;
}

int dummy_test_inode_unlink (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

int dummy_test_inode_symlink (struct inode *inode, struct dentry *dentry,
				const char *name)
{
	return 0;
}

int dummy_test_inode_mkdir (struct inode *inode, struct dentry *dentry,
			      int mask)
{
	return 0;
}

int dummy_test_inode_rmdir (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

int dummy_test_inode_mknod (struct inode *inode, struct dentry *dentry,
			      int mode, dev_t dev)
{
	return 0;
}

int dummy_test_inode_rename (struct inode *old_inode,
			       struct dentry *old_dentry,
			       struct inode *new_inode,
			       struct dentry *new_dentry)
{
	return 0;
}

int dummy_test_inode_readlink (struct dentry *dentry)
{
	return 0;
}

int dummy_test_inode_follow_link (struct dentry *dentry,
				    struct nameidata *nameidata)
{
	return 0;
}

int dummy_test_inode_permission (struct inode *inode, int mask, struct nameidata *nd)
{
	return 0;
}

int dummy_test_inode_setattr (struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

int dummy_test_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

void dummy_test_inode_delete (struct inode *ino)
{
	return;
}

int dummy_test_inode_setxattr (struct dentry *dentry, char *name, void *value,
				size_t size, int flags)
{
	if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof(XATTR_SECURITY_PREFIX) - 1) &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

void dummy_test_inode_post_setxattr (struct dentry *dentry, char *name, void *value,
				       size_t size, int flags)
{
}

int dummy_test_inode_getxattr (struct dentry *dentry, char *name)
{
	return 0;
}

int dummy_test_inode_listxattr (struct dentry *dentry)
{
	return 0;
}

int dummy_test_inode_removexattr (struct dentry *dentry, char *name)
{
	if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof(XATTR_SECURITY_PREFIX) - 1) &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int dummy_test_inode_need_killpriv(struct dentry *dentry)
{
	return 0;
}

int dummy_test_inode_killpriv(struct dentry *dentry)
{
	return 0;
}

int dummy_test_inode_getsecurity(const struct inode *inode, const char *name, void *buffer, size_t size, int err)
{
	return -EOPNOTSUPP;
}

int dummy_test_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

int dummy_test_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)
{
	return 0;
}

int dummy_test_file_permission (struct file *file, int mask)
{
	return 0;
}

int dummy_test_file_alloc_security (struct file *file)
{
	return 0;
}

void dummy_test_file_free_security (struct file *file)
{
	return;
}

int dummy_test_file_ioctl (struct file *file, unsigned int command,
			     unsigned long arg)
{
	return 0;
}

int dummy_test_file_mmap (struct file *file, unsigned long reqprot,
			    unsigned long prot,
			    unsigned long flags,
			    unsigned long addr,
			    unsigned long addr_only)
{
	if ((addr < mmap_min_addr) && !capable(CAP_SYS_RAWIO))
		return -EACCES;
	return 0;
}

int dummy_test_file_mprotect (struct vm_area_struct *vma,
				unsigned long reqprot,
				unsigned long prot)
{
	return 0;
}

int dummy_test_file_lock (struct file *file, unsigned int cmd)
{
	return 0;
}

int dummy_test_file_fcntl (struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	return 0;
}

int dummy_test_file_set_fowner (struct file *file)
{
	return 0;
}

int dummy_test_file_send_sigiotask (struct task_struct *tsk,
				      struct fown_struct *fown, int sig)
{
	return 0;
}

int dummy_test_file_receive (struct file *file)
{
	return 0;
}

int dummy_test_dentry_open (struct file *file)
{
	return 0;
}

int dummy_test_task_create (unsigned long clone_flags)
{
	return 0;
}

int dummy_test_task_alloc_security (struct task_struct *p)
{
	return 0;
}

void dummy_test_task_free_security (struct task_struct *p)
{
	return;
}

int dummy_test_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

int dummy_test_task_post_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	dummy_test_capget(current, &current->cap_effective, &current->cap_inheritable, &current->cap_permitted);
	return 0;
}

int dummy_test_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
	return 0;
}

int dummy_test_task_setpgid (struct task_struct *p, pid_t pgid)
{
	return 0;
}

int dummy_test_task_getpgid (struct task_struct *p)
{
	return 0;
}

int dummy_test_task_getsid (struct task_struct *p)
{
	return 0;
}

void dummy_test_task_getsecid (struct task_struct *p, u32 *secid)
{ }

int dummy_test_task_setgroups (struct group_info *group_info)
{
	return 0;
}

int dummy_test_task_setnice (struct task_struct *p, int nice)
{
	return 0;
}

int dummy_test_task_setioprio (struct task_struct *p, int ioprio)
{
	return 0;
}

int dummy_test_task_getioprio (struct task_struct *p)
{
	return 0;
}

int dummy_test_task_setrlimit (unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

int dummy_test_task_setscheduler (struct task_struct *p, int policy,
				    struct sched_param *lp)
{
	return 0;
}

int dummy_test_task_getscheduler (struct task_struct *p)
{
	return 0;
}

int dummy_test_task_movememory (struct task_struct *p)
{
	return 0;
}

int dummy_test_task_wait (struct task_struct *p)
{
	return 0;
}

int dummy_test_task_kill (struct task_struct *p, struct siginfo *info,
			    int sig, u32 secid)
{
	return 0;
}

int dummy_test_task_prctl (int option, unsigned long arg2, unsigned long arg3,
			     unsigned long arg4, unsigned long arg5)
{
	return 0;
}

void dummy_test_task_reparent_to_init (struct task_struct *p)
{
	p->euid = p->fsuid = 0;
	return;
}

void dummy_test_task_to_inode(struct task_struct *p, struct inode *inode)
{ }

int dummy_test_ipc_permission (struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

int dummy_test_msg_msg_alloc_security (struct msg_msg *msg)
{
	return 0;
}

void dummy_test_msg_msg_free_security (struct msg_msg *msg)
{
	return;
}

int dummy_test_msg_queue_alloc_security (struct msg_queue *msq)
{
	return 0;
}

void dummy_test_msg_queue_free_security (struct msg_queue *msq)
{
	return;
}

int dummy_test_msg_queue_associate (struct msg_queue *msq, 
				      int msqflg)
{
	return 0;
}

int dummy_test_msg_queue_msgctl (struct msg_queue *msq, int cmd)
{
	return 0;
}

int dummy_test_msg_queue_msgsnd (struct msg_queue *msq, struct msg_msg *msg,
				   int msgflg)
{
	return 0;
}

int dummy_test_msg_queue_msgrcv (struct msg_queue *msq, struct msg_msg *msg,
				   struct task_struct *target, long type,
				   int mode)
{
	return 0;
}

int dummy_test_shm_alloc_security (struct shmid_kernel *shp)
{
	return 0;
}

void dummy_test_shm_free_security (struct shmid_kernel *shp)
{
	return;
}

int dummy_test_shm_associate (struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

int dummy_test_shm_shmctl (struct shmid_kernel *shp, int cmd)
{
	return 0;
}

int dummy_test_shm_shmat (struct shmid_kernel *shp, char __user *shmaddr,
			    int shmflg)
{
	return 0;
}

int dummy_test_sem_alloc_security (struct sem_array *sma)
{
	return 0;
}

void dummy_test_sem_free_security (struct sem_array *sma)
{
	return;
}

int dummy_test_sem_associate (struct sem_array *sma, int semflg)
{
	return 0;
}

int dummy_test_sem_semctl (struct sem_array *sma, int cmd)
{
	return 0;
}

int dummy_test_sem_semop (struct sem_array *sma, 
			    struct sembuf *sops, unsigned nsops, int alter)
{
	return 0;
}

int dummy_test_netlink_send (struct sock *sk, struct sk_buff *skb)
{
	NETLINK_CB(skb).eff_cap = current->cap_effective;
	return 0;
}

int dummy_test_netlink_recv (struct sk_buff *skb, int cap)
{
	if (!cap_raised (NETLINK_CB (skb).eff_cap, cap))
		return -EPERM;
	return 0;
}

#ifdef CONFIG_SECURITY_NETWORK
int dummy_test_unix_stream_connect (struct socket *sock,
				      struct socket *other,
				      struct sock *newsk)
{
	return 0;
}

int dummy_test_unix_may_send (struct socket *sock,
				struct socket *other)
{
	return 0;
}

int dummy_test_socket_create (int family, int type,
				int protocol, int kern)
{
	return 0;
}

int dummy_test_socket_post_create (struct socket *sock, int family, int type,
				     int protocol, int kern)
{
	return 0;
}

int dummy_test_socket_bind (struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	return 0;
}

int dummy_test_socket_connect (struct socket *sock, struct sockaddr *address,
				 int addrlen)
{
	return 0;
}

int dummy_test_socket_listen (struct socket *sock, int backlog)
{
	return 0;
}

int dummy_test_socket_accept (struct socket *sock, struct socket *newsock)
{
	return 0;
}

void dummy_test_socket_post_accept (struct socket *sock, 
				      struct socket *newsock)
{
	return;
}

int dummy_test_socket_sendmsg (struct socket *sock, struct msghdr *msg,
				 int size)
{
	return 0;
}

int dummy_test_socket_recvmsg (struct socket *sock, struct msghdr *msg,
				 int size, int flags)
{
	return 0;
}

int dummy_test_socket_getsockname (struct socket *sock)
{
	return 0;
}

int dummy_test_socket_getpeername (struct socket *sock)
{
	return 0;
}

int dummy_test_socket_setsockopt (struct socket *sock, int level, int optname)
{
	return 0;
}

int dummy_test_socket_getsockopt (struct socket *sock, int level, int optname)
{
	return 0;
}

int dummy_test_socket_shutdown (struct socket *sock, int how)
{
	return 0;
}

int dummy_test_socket_sock_rcv_skb (struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

int dummy_test_socket_getpeersec_stream(struct socket *sock, char __user *optval,
					  int __user *optlen, unsigned len)
{
	return -ENOPROTOOPT;
}

int dummy_test_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)
{
	return -ENOPROTOOPT;
}

inline int dummy_test_sk_alloc_security (struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

inline void dummy_test_sk_free_security (struct sock *sk)
{
}

inline void dummy_test_sk_clone_security (const struct sock *sk, struct sock *newsk)
{
}

inline void dummy_test_sk_getsecid(struct sock *sk, u32 *secid)
{
}

inline void dummy_test_sock_graft(struct sock* sk, struct socket *parent)
{
}

inline int dummy_test_inet_conn_request(struct sock *sk,
			struct sk_buff *skb, struct request_sock *req)
{
	return 0;
}

inline void dummy_test_inet_csk_clone(struct sock *newsk,
			const struct request_sock *req)
{
}

inline void dummy_test_inet_conn_established(struct sock *sk,
			struct sk_buff *skb)
{
}

inline void dummy_test_req_classify_flow(const struct request_sock *req,
			struct flowi *fl)
{
}
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
int dummy_test_xfrm_policy_alloc_security(struct xfrm_policy *xp,
		struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

inline int dummy_test_xfrm_policy_clone_security(struct xfrm_policy *old, struct xfrm_policy *new)
{
	return 0;
}

void dummy_test_xfrm_policy_free_security(struct xfrm_policy *xp)
{
}

int dummy_test_xfrm_policy_delete_security(struct xfrm_policy *xp)
{
	return 0;
}

int dummy_test_xfrm_state_alloc_security(struct xfrm_state *x,
	struct xfrm_user_sec_ctx *sec_ctx, u32 secid)
{
	return 0;
}

void dummy_test_xfrm_state_free_security(struct xfrm_state *x)
{
}

int dummy_test_xfrm_state_delete_security(struct xfrm_state *x)
{
	return 0;
}

int dummy_test_xfrm_policy_lookup(struct xfrm_policy *xp, u32 sk_sid, u8 dir)
{
	return 0;
}

int dummy_test_xfrm_state_pol_flow_match(struct xfrm_state *x,
				struct xfrm_policy *xp, struct flowi *fl)
{
	return 1;
}

int dummy_test_xfrm_decode_session(struct sk_buff *skb, u32 *fl, int ckall)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */
int dummy_test_register_security (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}

void dummy_test_d_instantiate (struct dentry *dentry, struct inode *inode)
{
	return;
}

int dummy_test_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

int dummy_test_setprocattr(struct task_struct *p, char *name, void *value, size_t size)
{
	return -EINVAL;
}

int dummy_test_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

void dummy_test_release_secctx(char *secdata, u32 seclen)
{
}

#ifdef CONFIG_KEYS
inline int dummy_test_key_alloc(struct key *key, struct task_struct *ctx,
				  unsigned long flags)
{
	return 0;
}

inline void dummy_test_key_free(struct key *key)
{
}

inline int dummy_test_key_permission(key_ref_t key_ref,
				       struct task_struct *context,
				       key_perm_t perm)
{
	return 0;
}
#endif //CONFIG_KEYS

extern int kadvice_post(char *, char *, int, int);
extern int kadvice_clear_advice(int, int);

#define SIZE 151

static int __init dummy_test_init(void){
  int i;
    
  for(i = 0; i < SIZE ; i++){
    kadvice_post("dummy_test", lsm_security_str[i], 0, 1);
  }
  
  //kadvice_post("dummy_test", "inode_permission", 0, 1);
  printk("dummy_test init\n");
  return 0;
}
static void __exit dummy_test_exit(void){
  int i = 0;
  for(i = 0; i < SIZE ; i++){
    kadvice_clear_advice(0, i);
  }
  printk("dummy_test removed\n");
}

security_initcall(dummy_test_init);
module_exit(dummy_test_exit);
