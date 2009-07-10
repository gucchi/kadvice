
#include <linux/security.h>

static int cap_acct(struct file *file)
{
	return 0;
}

static int cap_sysctl(ctl_table *table, int op)
{
	return 0;
}

static int cap_quotactl(int cmds, int type, int id, struct super_block *sb)
{
	return 0;
}

static int cap_quota_on(struct dentry *dentry)
{
	return 0;
}

static int cap_bprm_check_security (struct linux_binprm *bprm)
{
	return 0;
}

static void cap_bprm_committing_creds(struct linux_binprm *bprm)
{
}

static void cap_bprm_committed_creds(struct linux_binprm *bprm)
{
}

static int cap_sb_alloc_security(struct super_block *sb)
{
	return 0;
}

static void cap_sb_free_security(struct super_block *sb)
{
}

static int cap_sb_copy_data(char *orig, char *copy)
{
	return 0;
}

static int cap_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
	return 0;
}

static int cap_sb_show_options(struct seq_file *m, struct super_block *sb)
{
	return 0;
}

static int cap_sb_statfs(struct dentry *dentry)
{
	return 0;
}

static int cap_sb_mount(char *dev_name, struct path *path, char *type,
			unsigned long flags, void *data)
{
	return 0;
}

static int cap_sb_check_sb(struct vfsmount *mnt, struct path *path)
{
	return 0;
}

static int cap_sb_umount(struct vfsmount *mnt, int flags)
{
	return 0;
}

static void cap_sb_umount_close(struct vfsmount *mnt)
{
}

static void cap_sb_umount_busy(struct vfsmount *mnt)
{
}

static void cap_sb_post_remount(struct vfsmount *mnt, unsigned long flags,
				void *data)
{
}

static void cap_sb_post_addmount(struct vfsmount *mnt, struct path *path)
{
}

static int cap_sb_pivotroot(struct path *old_path, struct path *new_path)
{
	return 0;
}

static void cap_sb_post_pivotroot(struct path *old_path, struct path *new_path)
{
}

static int cap_sb_set_mnt_opts(struct super_block *sb,
			       struct security_mnt_opts *opts)
{
	if (unlikely(opts->num_mnt_opts))
		return -EOPNOTSUPP;
	return 0;
}

static void cap_sb_clone_mnt_opts(const struct super_block *oldsb,
				  struct super_block *newsb)
{
}

static int cap_sb_parse_opts_str(char *options, struct security_mnt_opts *opts)
{
	return 0;
}

static int cap_inode_alloc_security(struct inode *inode)
{
	return 0;
}

static void cap_inode_free_security(struct inode *inode)
{
}

static int cap_inode_init_security(struct inode *inode, struct inode *dir,
				   char **name, void **value, size_t *len)
{
	return -EOPNOTSUPP;
}

static int cap_inode_create(struct inode *inode, struct dentry *dentry,
			    int mask)
{
	return 0;
}

static int cap_inode_link(struct dentry *old_dentry, struct inode *inode,
			  struct dentry *new_dentry)
{
	return 0;
}

static int cap_inode_unlink(struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int cap_inode_symlink(struct inode *inode, struct dentry *dentry,
			     const char *name)
{
	return 0;
}

static int cap_inode_mkdir(struct inode *inode, struct dentry *dentry,
			   int mask)
{
	return 0;
}

static int cap_inode_rmdir(struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int cap_inode_mknod(struct inode *inode, struct dentry *dentry,
			   int mode, dev_t dev)
{
	return 0;
}

static int cap_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			    struct inode *new_inode, struct dentry *new_dentry)
{
	return 0;
}

static int cap_inode_readlink(struct dentry *dentry)
{
	return 0;
}

static int cap_inode_follow_link(struct dentry *dentry,
				 struct nameidata *nameidata)
{
	return 0;
}

static int cap_inode_permission(struct inode *inode, int mask)
{
	return 0;
}

static int cap_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int cap_inode_getattr(struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void cap_inode_delete(struct inode *ino)
{
}

static void cap_inode_post_setxattr(struct dentry *dentry, const char *name,
				    const void *value, size_t size, int flags)
{
}

static int cap_inode_getxattr(struct dentry *dentry, const char *name)
{
	return 0;
}

static int cap_inode_listxattr(struct dentry *dentry)
{
	return 0;
}

static int cap_inode_getsecurity(const struct inode *inode, const char *name,
				 void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static int cap_inode_setsecurity(struct inode *inode, const char *name,
				 const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static int cap_inode_listsecurity(struct inode *inode, char *buffer,
				  size_t buffer_size)
{
	return 0;
}

static void cap_inode_getsecid(const struct inode *inode, u32 *secid)
{
	*secid = 0;
}

#ifdef CONFIG_SECURITY_PATH
static int cap_path_mknod(struct path *dir, struct dentry *dentry, int mode,
			  unsigned int dev)
{
	return 0;
}

static int cap_path_mkdir(struct path *dir, struct dentry *dentry, int mode)
{
	return 0;
}

static int cap_path_rmdir(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int cap_path_unlink(struct path *dir, struct dentry *dentry)
{
	return 0;
}

static int cap_path_symlink(struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
	return 0;
}

static int cap_path_link(struct dentry *old_dentry, struct path *new_dir,
			 struct dentry *new_dentry)
{
	return 0;
}

static int cap_path_rename(struct path *old_path, struct dentry *old_dentry,
			   struct path *new_path, struct dentry *new_dentry)
{
	return 0;
}

static int cap_path_truncate(struct path *path, loff_t length,
			     unsigned int time_attrs)
{
	return 0;
}
#endif

static int cap_file_permission(struct file *file, int mask)
{
	return 0;
}

static int cap_file_alloc_security(struct file *file)
{
	return 0;
}

static void cap_file_free_security(struct file *file)
{
}

static int cap_file_ioctl(struct file *file, unsigned int command,
			  unsigned long arg)
{
	return 0;
}

static int cap_file_mmap(struct file *file, unsigned long reqprot,
			 unsigned long prot, unsigned long flags,
			 unsigned long addr, unsigned long addr_only)
{
	if ((addr < mmap_min_addr) && !capable(CAP_SYS_RAWIO))
		return -EACCES;
	return 0;
}

static int cap_file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
			     unsigned long prot)
{
	return 0;
}

static int cap_file_lock(struct file *file, unsigned int cmd)
{
	return 0;
}

static int cap_file_fcntl(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	return 0;
}

static int cap_file_set_fowner(struct file *file)
{
	return 0;
}

static int cap_file_send_sigiotask(struct task_struct *tsk,
				   struct fown_struct *fown, int sig)
{
	return 0;
}

static int cap_file_receive(struct file *file)
{
	return 0;
}

static int cap_dentry_open(struct file *file, const struct cred *cred)
{
	return 0;
}

static int cap_task_create(unsigned long clone_flags)
{
	return 0;
}

static void cap_cred_free(struct cred *cred)
{
}

static int cap_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
	return 0;
}

static void cap_cred_commit(struct cred *new, const struct cred *old)
{
}

static int cap_kernel_act_as(struct cred *new, u32 secid)
{
	return 0;
}

static int cap_kernel_create_files_as(struct cred *new, struct inode *inode)
{
	return 0;
}

static int cap_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int cap_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags)
{
	return 0;
}

static int cap_task_setpgid(struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int cap_task_getpgid(struct task_struct *p)
{
	return 0;
}

static int cap_task_getsid(struct task_struct *p)
{
	return 0;
}

static void cap_task_getsecid(struct task_struct *p, u32 *secid)
{
	*secid = 0;
}

static int cap_task_setgroups(struct group_info *group_info)
{
	return 0;
}

static int cap_task_getioprio(struct task_struct *p)
{
	return 0;
}

static int cap_task_setrlimit(unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int cap_task_getscheduler(struct task_struct *p)
{
	return 0;
}

static int cap_task_movememory(struct task_struct *p)
{
	return 0;
}

static int cap_task_wait(struct task_struct *p)
{
	return 0;
}

static int cap_task_kill(struct task_struct *p, struct siginfo *info,
			 int sig, u32 secid)
{
	return 0;
}

static void cap_task_to_inode(struct task_struct *p, struct inode *inode)
{
}

static int cap_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	return 0;
}

static void cap_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)
{
	*secid = 0;
}

static int cap_msg_msg_alloc_security(struct msg_msg *msg)
{
	return 0;
}

static void cap_msg_msg_free_security(struct msg_msg *msg)
{
}

static int cap_msg_queue_alloc_security(struct msg_queue *msq)
{
	return 0;
}

static void cap_msg_queue_free_security(struct msg_queue *msq)
{
}

static int cap_msg_queue_associate(struct msg_queue *msq, int msqflg)
{
	return 0;
}

static int cap_msg_queue_msgctl(struct msg_queue *msq, int cmd)
{
	return 0;
}

static int cap_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg,
				int msgflg)
{
	return 0;
}

static int cap_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				struct task_struct *target, long type, int mode)
{
	return 0;
}

static int cap_shm_alloc_security(struct shmid_kernel *shp)
{
	return 0;
}

static void cap_shm_free_security(struct shmid_kernel *shp)
{
}

static int cap_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	return 0;
}

static int cap_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	return 0;
}

static int cap_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,
			 int shmflg)
{
	return 0;
}

static int cap_sem_alloc_security(struct sem_array *sma)
{
	return 0;
}

static void cap_sem_free_security(struct sem_array *sma)
{
}

static int cap_sem_associate(struct sem_array *sma, int semflg)
{
	return 0;
}

static int cap_sem_semctl(struct sem_array *sma, int cmd)
{
	return 0;
}

static int cap_sem_semop(struct sem_array *sma, struct sembuf *sops,
			 unsigned nsops, int alter)
{
	return 0;
}

#ifdef CONFIG_SECURITY_NETWORK
static int cap_unix_stream_connect(struct socket *sock, struct socket *other,
				   struct sock *newsk)
{
	return 0;
}

static int cap_unix_may_send(struct socket *sock, struct socket *other)
{
	return 0;
}

static int cap_socket_create(int family, int type, int protocol, int kern)
{
	return 0;
}

static int cap_socket_post_create(struct socket *sock, int family, int type,
				  int protocol, int kern)
{
	return 0;
}

static int cap_socket_bind(struct socket *sock, struct sockaddr *address,
			   int addrlen)
{
	return 0;
}

static int cap_socket_connect(struct socket *sock, struct sockaddr *address,
			      int addrlen)
{
	return 0;
}

static int cap_socket_listen(struct socket *sock, int backlog)
{
	return 0;
}

static int cap_socket_accept(struct socket *sock, struct socket *newsock)
{
	return 0;
}

static int cap_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return 0;
}

static int cap_socket_recvmsg(struct socket *sock, struct msghdr *msg,
			      int size, int flags)
{
	return 0;
}

static int cap_socket_getsockname(struct socket *sock)
{
	return 0;
}

static int cap_socket_getpeername(struct socket *sock)
{
	return 0;
}

static int cap_socket_setsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int cap_socket_getsockopt(struct socket *sock, int level, int optname)
{
	return 0;
}

static int cap_socket_shutdown(struct socket *sock, int how)
{
	return 0;
}

static int cap_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static int cap_socket_getpeersec_stream(struct socket *sock,
					char __user *optval,
					int __user *optlen, unsigned len)
{
	return -ENOPROTOOPT;
}

static int cap_socket_getpeersec_dgram(struct socket *sock,
				       struct sk_buff *skb, u32 *secid)
{
	return -ENOPROTOOPT;
}

static int cap_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	return 0;
}

static void cap_sk_free_security(struct sock *sk)
{
}

static void cap_sk_clone_security(const struct sock *sk, struct sock *newsk)
{
}

static void cap_sk_getsecid(struct sock *sk, u32 *secid)
{
}

static void cap_sock_graft(struct sock *sk, struct socket *parent)
{
}

static int cap_inet_conn_request(struct sock *sk, struct sk_buff *skb,
				 struct request_sock *req)
{
	return 0;
}

static void cap_inet_csk_clone(struct sock *newsk,
			       const struct request_sock *req)
{
}

static void cap_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
}

static void cap_req_classify_flow(const struct request_sock *req,
				  struct flowi *fl)
{
}
#endif	/* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static int cap_xfrm_policy_alloc_security(struct xfrm_sec_ctx **ctxp,
					  struct xfrm_user_sec_ctx *sec_ctx)
{
	return 0;
}

static int cap_xfrm_policy_clone_security(struct xfrm_sec_ctx *old_ctx,
					  struct xfrm_sec_ctx **new_ctxp)
{
	return 0;
}

static void cap_xfrm_policy_free_security(struct xfrm_sec_ctx *ctx)
{
}

static int cap_xfrm_policy_delete_security(struct xfrm_sec_ctx *ctx)
{
	return 0;
}

static int cap_xfrm_state_alloc_security(struct xfrm_state *x,
					 struct xfrm_user_sec_ctx *sec_ctx,
					 u32 secid)
{
	return 0;
}

static void cap_xfrm_state_free_security(struct xfrm_state *x)
{
}

static int cap_xfrm_state_delete_security(struct xfrm_state *x)
{
	return 0;
}

static int cap_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 sk_sid, u8 dir)
{
	return 0;
}

static int cap_xfrm_state_pol_flow_match(struct xfrm_state *x,
					 struct xfrm_policy *xp,
					 struct flowi *fl)
{
	return 1;
}

static int cap_xfrm_decode_session(struct sk_buff *skb, u32 *fl, int ckall)
{
	return 0;
}

#endif /* CONFIG_SECURITY_NETWORK_XFRM */
static void cap_d_instantiate(struct dentry *dentry, struct inode *inode)
{
}

static int cap_getprocattr(struct task_struct *p, char *name, char **value)
{
	return -EINVAL;
}

static int cap_setprocattr(struct task_struct *p, char *name, void *value,
			   size_t size)
{
	return -EINVAL;
}

static int cap_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return -EOPNOTSUPP;
}

static int cap_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid)
{
	return -EOPNOTSUPP;
}

static void cap_release_secctx(char *secdata, u32 seclen)
{
}

#ifdef CONFIG_KEYS
static int cap_key_alloc(struct key *key, const struct cred *cred,
			 unsigned long flags)
{
	return 0;
}

static void cap_key_free(struct key *key)
{
}

static int cap_key_permission(key_ref_t key_ref, const struct cred *cred,
			      key_perm_t perm)
{
	return 0;
}

static int cap_key_getsecurity(struct key *key, char **_buffer)
{
	*_buffer = NULL;
	return 0;
}

#endif /* CONFIG_KEYS */

#ifdef CONFIG_AUDIT
static int cap_audit_rule_init(u32 field, u32 op, char *rulestr, void **lsmrule)
{
	return 0;
}

static int cap_audit_rule_known(struct audit_krule *krule)
{
	return 0;
}

static int cap_audit_rule_match(u32 secid, u32 field, u32 op, void *lsmrule,
				struct audit_context *actx)
{
	return 0;
}

static void cap_audit_rule_free(void *lsmrule)
{
}
#endif /* CONFIG_AUDIT */

