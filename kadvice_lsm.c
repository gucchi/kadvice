

static inline int sc_ptrace_may_access(struct task_struct *child,

					     unsigned int mode)

{

	/* return cap_ptrace_may_access(child, mode); */
	return sc_check_ptrace_may_access(child,mode);
}



static inline int sc_ptrace_traceme(struct task_struct *parent)

{

	/* return cap_ptrace_traceme(parent); */
	return sc_check_ptrace_traceme(parent);
}



static inline int sc_capget(struct task_struct *target,

				   kernel_cap_t *effective,

				   kernel_cap_t *inheritable,

				   kernel_cap_t *permitted)

{

	/* return cap_capget(target, effective, inheritable, permitted); */
	return sc_check_capget(target,effective,inheritable,permitted);
}



static inline int sc_capset(struct cred *new,

				   const struct cred *old,

				   const kernel_cap_t *effective,

				   const kernel_cap_t *inheritable,

				   const kernel_cap_t *permitted)

{

	/* return cap_capset(new, old, effective, inheritable, permitted); */
	return sc_check_capset(new,old,effective,inheritable,permitted);
}



static inline int sc_capable(int cap)

{

	/* return cap_capable(current, current_cred(), cap, SECURITY_CAP_AUDIT); */
	return sc_check_capable(cap);
}



static inline int sc_real_capable(struct task_struct *tsk, int cap)

{

	int ret;



	rcu_read_lock();

	ret = cap_capable(tsk, __task_cred(tsk), cap, SECURITY_CAP_AUDIT);

	rcu_read_unlock();

	/* return ret; */
	return sc_check_real_capable(tsk,cap);
}



static inline

int security_real_capable_noaudit(struct task_struct *tsk, int cap)

{

	int ret;



	rcu_read_lock();

	ret = cap_capable(tsk, __task_cred(tsk), cap,

			       SECURITY_CAP_NOAUDIT);

	rcu_read_unlock();

	/* return ret; */
	return sc_check_real_capable(tsk,cap);
}



static inline int sc_acct(struct file *file)

{

	return sc_check_acct(file);
}



static inline int sc_sysctl(struct ctl_table *table, int op)

{

	return sc_check_sysctl(table,op);
}



static inline int sc_quotactl(int cmds, int type, int id,

				     struct super_block *sb)

{

	return sc_check_quotactl(cmds,type,id,sb);
}



static inline int sc_quota_on(struct dentry *dentry)

{

	return sc_check_quota_on(dentry);
}



static inline int sc_syslog(int type)

{

	/* return cap_syslog(type); */
	return sc_check_syslog(type);
}



static inline int sc_settime(struct timespec *ts, struct timezone *tz)

{

	/* return cap_settime(ts, tz); */
	return sc_check_settime(ts,tz);
}



static inline int sc_vm_enough_memory(long pages)

{

	WARN_ON(current->mm == NULL);

	/* return cap_vm_enough_memory(current->mm, pages); */
	return sc_check_vm_enough_memory(pages);
}



static inline int sc_vm_enough_memory_mm(struct mm_struct *mm, long pages)

{

	WARN_ON(mm == NULL);

	/* return cap_vm_enough_memory(mm, pages); */
	return sc_check_vm_enough_memory_mm(mm,pages);
}



static inline int sc_vm_enough_memory_kern(long pages)

{

	/* If current->mm is a kernel thread then we will pass NULL,

	   for this specific case that is fine */

	/* return cap_vm_enough_memory(current->mm, pages); */
	return sc_check_vm_enough_memory_kern(pages);
}



static inline int sc_bprm_set_creds(struct linux_binprm *bprm)

{

	/* return cap_bprm_set_creds(bprm); */
	return sc_check_bprm_set_creds(bprm);
}



static inline int sc_bprm_check(struct linux_binprm *bprm)

{

	return sc_check_bprm_check(bprm);
}



static inline void sc_bprm_committing_creds(struct linux_binprm *bprm)

{
	return sc_check_bprm_committing_creds(bprm);
}



static inline void sc_bprm_committed_creds(struct linux_binprm *bprm)

{
	return sc_check_bprm_committed_creds(bprm);
}



static inline int sc_bprm_secureexec(struct linux_binprm *bprm)

{

	/* return cap_bprm_secureexec(bprm); */
	return sc_check_bprm_secureexec(bprm);
}



static inline int sc_sb_alloc(struct super_block *sb)

{

	return sc_check_sb_alloc(sb);
}



static inline void sc_sb_free(struct super_block *sb)

{	return sc_check_sb_free(sb);}


static inline int sc_sb_copy_data(char *orig, char *copy)

{

	return sc_check_sb_copy_data(orig,copy);
}



static inline int sc_sb_kern_mount(struct super_block *sb, int flags, void *data)

{

	return sc_check_sb_kern_mount(sb,flags,data);
}



static inline int sc_sb_show_options(struct seq_file *m,

					   struct super_block *sb)

{

	return sc_check_sb_show_options(m,sb);
}



static inline int sc_sb_statfs(struct dentry *dentry)

{

	return sc_check_sb_statfs(dentry);
}



static inline int sc_sb_mount(char *dev_name, struct path *path,

				    char *type, unsigned long flags,

				    void *data)

{

	return sc_check_sb_mount(dev_name,path,type,flags,data);
}



static inline int sc_sb_check_sb(struct vfsmount *mnt,

				       struct path *path)

{

	return sc_check_sb_check_sb(mnt,path);
}



static inline int sc_sb_umount(struct vfsmount *mnt, int flags)

{

	return sc_check_sb_umount(mnt,flags);
}



static inline void sc_sb_umount_close(struct vfsmount *mnt)

{	return sc_check_sb_umount_close(mnt);}


static inline void sc_sb_umount_busy(struct vfsmount *mnt)

{	return sc_check_sb_umount_busy(mnt);}


static inline void sc_sb_post_remount(struct vfsmount *mnt,

					     unsigned long flags, void *data)

{	return sc_check_sb_post_remount(mnt,flags,data);}


static inline void sc_sb_post_addmount(struct vfsmount *mnt,

					     struct path *mountpoint)

{	return sc_check_sb_post_addmount(mnt,mountpoint);}


static inline int sc_sb_pivotroot(struct path *old_path,

					struct path *new_path)

{

	return sc_check_sb_pivotroot(old_path,new_path);
}



static inline void sc_sb_post_pivotroot(struct path *old_path,

					      struct path *new_path)

{	return sc_check_sb_post_pivotroot(old_path,new_path);}


static inline int sc_sb_set_mnt_opts(struct super_block *sb,

					   struct security_mnt_opts *opts)

{

	return sc_check_sb_set_mnt_opts(sb,opts);
}



static inline void sc_sb_clone_mnt_opts(const struct super_block *oldsb,

					      struct super_block *newsb)

{	return sc_check_sb_clone_mnt_opts(oldsb,newsb);}


static inline int sc_sb_parse_opts_str(char *options, struct sc_mnt_opts *opts)

{

	return sc_check_sb_parse_opts_str(options,opts);
}



static inline int sc_inode_alloc(struct inode *inode)

{

	return sc_check_inode_alloc(inode);
}



static inline void sc_inode_free(struct inode *inode)

{	return sc_check_inode_free(inode);}


static inline int sc_inode_init_security(struct inode *inode,

						struct inode *dir,

						char **name,

						void **value,

						size_t *len)

{

	/* return -EOPNOTSUPP; */
	return sc_check_inode_init_security(inode,dir,name,value,len);
}



static inline int sc_inode_create(struct inode *dir,

					 struct dentry *dentry,

					 int mode)

{

	return sc_check_inode_create(dir,dentry,mode);
}



static inline int sc_inode_link(struct dentry *old_dentry,

				       struct inode *dir,

				       struct dentry *new_dentry)

{

	return sc_check_inode_link(old_dentry,dir,new_dentry);
}



static inline int sc_inode_unlink(struct inode *dir,

					 struct dentry *dentry)

{

	return sc_check_inode_unlink(dir,dentry);
}



static inline int sc_inode_symlink(struct inode *dir,

					  struct dentry *dentry,

					  const char *old_name)

{

	return sc_check_inode_symlink(dir,dentry,old_name);
}



static inline int sc_inode_mkdir(struct inode *dir,

					struct dentry *dentry,

					int mode)

{

	return sc_check_inode_mkdir(dir,dentry,mode);
}



static inline int sc_inode_rmdir(struct inode *dir,

					struct dentry *dentry)

{

	return sc_check_inode_rmdir(dir,dentry);
}



static inline int sc_inode_mknod(struct inode *dir,

					struct dentry *dentry,

					int mode, dev_t dev)

{

	return sc_check_inode_mknod(dir,dentry,mode,dev);
}



static inline int sc_inode_rename(struct inode *old_dir,

					 struct dentry *old_dentry,

					 struct inode *new_dir,

					 struct dentry *new_dentry)

{

	return sc_check_inode_rename(old_dir,old_dentry,new_dir,new_dentry);
}



static inline int sc_inode_readlink(struct dentry *dentry)

{

	return sc_check_inode_readlink(dentry);
}



static inline int sc_inode_follow_link(struct dentry *dentry,

					      struct nameidata *nd)

{

	return sc_check_inode_follow_link(dentry,nd);
}



static inline int sc_inode_permission(struct inode *inode, int mask)

{

	return sc_check_inode_permission(inode,mask);
}



static inline int sc_inode_setattr(struct dentry *dentry,

					  struct iattr *attr)

{

	return sc_check_inode_setattr(dentry,attr);
}



static inline int sc_inode_getattr(struct vfsmount *mnt,

					  struct dentry *dentry)

{

	return sc_check_inode_getattr(mnt,dentry);
}



static inline void sc_inode_delete(struct inode *inode)

{	return sc_check_inode_delete(inode);}


static inline int sc_inode_setxattr(struct dentry *dentry,

		const char *name, const void *value, size_t size, int flags)

{

	/* return cap_inode_setxattr(dentry, name, value, size, flags); */
	return sc_check_inode_setxattr(dentry,name,value,size,flags);
}



static inline void sc_inode_post_setxattr(struct dentry *dentry,

		const char *name, const void *value, size_t size, int flags)

{	return sc_check_inode_post_setxattr(dentry,name,value,size,flags);}


static inline int sc_inode_getxattr(struct dentry *dentry,

			const char *name)

{

	return sc_check_inode_getxattr(dentry,name);
}



static inline int sc_inode_listxattr(struct dentry *dentry)

{

	return sc_check_inode_listxattr(dentry);
}



static inline int sc_inode_removexattr(struct dentry *dentry,

			const char *name)

{

	/* return cap_inode_removexattr(dentry, name); */
	return sc_check_inode_removexattr(dentry,name);
}



static inline int sc_inode_need_killpriv(struct dentry *dentry)

{

	/* return cap_inode_need_killpriv(dentry); */
	return sc_check_inode_need_killpriv(dentry);
}



static inline int sc_inode_killpriv(struct dentry *dentry)

{

	/* return cap_inode_killpriv(dentry); */
	return sc_check_inode_killpriv(dentry);
}



static inline int sc_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)

{

	/* return -EOPNOTSUPP; */
	return sc_check_inode_getsecurity(inode,name,buffer,alloc);
}



static inline int sc_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)

{

	/* return -EOPNOTSUPP; */
	return sc_check_inode_setsecurity(inode,name,value,size,flags);
}



static inline int sc_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size)

{

	return sc_check_inode_listsecurity(inode,buffer,buffer_size);
}



static inline void sc_inode_getsecid(const struct inode *inode, u32 *secid)

{
	return sc_check_inode_getsecid(inode,secid);
	*secid = 0;

}



static inline int sc_file_permission(struct file *file, int mask)

{

	return sc_check_file_permission(file,mask);
}



static inline int sc_file_alloc(struct file *file)

{

	return sc_check_file_alloc(file);
}



static inline void sc_file_free(struct file *file)

{	return sc_check_file_free(file);}


static inline int sc_file_ioctl(struct file *file, unsigned int cmd,

				      unsigned long arg)

{

	return sc_check_file_ioctl(file,cmd,arg);
}



static inline int sc_file_mmap(struct file *file, unsigned long reqprot,

				     unsigned long prot,

				     unsigned long flags,

				     unsigned long addr,

				     unsigned long addr_only)

{

	return sc_check_file_mmap(file,reqprot,prot,flags,addr,addr_only);
}



static inline int sc_file_mprotect(struct vm_area_struct *vma,

					 unsigned long reqprot,

					 unsigned long prot)

{

	return sc_check_file_mprotect(vma,reqprot,prot);
}



static inline int sc_file_lock(struct file *file, unsigned int cmd)

{

	return sc_check_file_lock(file,cmd);
}



static inline int sc_file_fcntl(struct file *file, unsigned int cmd,

				      unsigned long arg)

{

	return sc_check_file_fcntl(file,cmd,arg);
}



static inline int sc_file_set_fowner(struct file *file)

{

	return sc_check_file_set_fowner(file);
}



static inline int sc_file_send_sigiotask(struct task_struct *tsk,

					       struct fown_struct *fown,

					       int sig)

{

	return sc_check_file_send_sigiotask(tsk,fown,sig);
}



static inline int sc_file_receive(struct file *file)

{

	return sc_check_file_receive(file);
}



static inline int sc_dentry_open(struct file *file,

				       const struct cred *cred)

{

	return sc_check_dentry_open(file,cred);
}



static inline int sc_task_create(unsigned long clone_flags)

{

	return sc_check_task_create(clone_flags);
}



static inline void sc_cred_free(struct cred *cred)

{	return sc_check_cred_free(cred);}


static inline int sc_prepare_creds(struct cred *new,

					 const struct cred *old,

					 gfp_t gfp)

{

	return sc_check_prepare_creds(new,old,gfp);
}



static inline void sc_commit_creds(struct cred *new,

					 const struct cred *old)

{
	return sc_check_commit_creds(new,old);
}



static inline int sc_kernel_act_as(struct cred *cred, u32 secid)

{

	return sc_check_kernel_act_as(cred,secid);
}



static inline int sc_kernel_create_files_as(struct cred *cred,

						  struct inode *inode)

{

	return sc_check_kernel_create_files_as(cred,inode);
}



static inline int sc_task_setuid(uid_t id0, uid_t id1, uid_t id2,

				       int flags)

{

	return sc_check_task_setuid(id0,id1,id2,flags);
}



static inline int sc_task_fix_setuid(struct cred *new,

					   const struct cred *old,

					   int flags)

{

	/* return cap_task_fix_setuid(new, old, flags); */
	return sc_check_task_fix_setuid(new,old,flags);
}



static inline int sc_task_setgid(gid_t id0, gid_t id1, gid_t id2,

				       int flags)

{

	return sc_check_task_setgid(id0,id1,id2,flags);
}



static inline int sc_task_setpgid(struct task_struct *p, pid_t pgid)

{

	return sc_check_task_setpgid(p,pgid);
}



static inline int sc_task_getpgid(struct task_struct *p)

{

	return sc_check_task_getpgid(p);
}



static inline int sc_task_getsid(struct task_struct *p)

{

	return sc_check_task_getsid(p);
}



static inline void sc_task_getsecid(struct task_struct *p, u32 *secid)

{
	return sc_check_task_getsecid(p,secid);
	*secid = 0;

}



static inline int sc_task_setgroups(struct group_info *group_info)

{

	return sc_check_task_setgroups(group_info);
}



static inline int sc_task_setnice(struct task_struct *p, int nice)

{

	/* return cap_task_setnice(p, nice); */
	return sc_check_task_setnice(p,nice);
}



static inline int sc_task_setioprio(struct task_struct *p, int ioprio)

{

	/* return cap_task_setioprio(p, ioprio); */
	return sc_check_task_setioprio(p,ioprio);
}



static inline int sc_task_getioprio(struct task_struct *p)

{

	return sc_check_task_getioprio(p);
}



static inline int sc_task_setrlimit(unsigned int resource,

					  struct rlimit *new_rlim)

{

	return sc_check_task_setrlimit(resource,new_rlim);
}



static inline int sc_task_setscheduler(struct task_struct *p,

					     int policy,

					     struct sched_param *lp)

{

	/* return cap_task_setscheduler(p, policy, lp); */
	return sc_check_task_setscheduler(p,policy,lp);
}



static inline int sc_task_getscheduler(struct task_struct *p)

{

	return sc_check_task_getscheduler(p);
}



static inline int sc_task_movememory(struct task_struct *p)

{

	return sc_check_task_movememory(p);
}



static inline int sc_task_kill(struct task_struct *p,

				     struct siginfo *info, int sig,

				     u32 secid)

{

	return sc_check_task_kill(p,info,sig,secid);
}



static inline int sc_task_wait(struct task_struct *p)

{

	return sc_check_task_wait(p);
}



static inline int sc_task_prctl(int option, unsigned long arg2,

				      unsigned long arg3,

				      unsigned long arg4,

				      unsigned long arg5)

{

	/* return cap_task_prctl(option, arg2, arg3, arg3, arg5); */
	return sc_check_task_prctl(option,arg2,arg3,arg4,arg5);
}



static inline void sc_task_to_inode(struct task_struct *p, struct inode *inode)

{	return sc_check_task_to_inode(p,inode);}


static inline int sc_ipc_permission(struct kern_ipc_perm *ipcp,

					  short flag)

{

	return sc_check_ipc_permission(ipcp,flag);
}



static inline void sc_ipc_getsecid(struct kern_ipc_perm *ipcp, u32 *secid)

{
	return sc_check_ipc_getsecid(ipcp,secid);
	*secid = 0;

}



static inline int sc_msg_msg_alloc(struct msg_msg *msg)

{

	return sc_check_msg_msg_alloc(msg);
}



static inline void sc_msg_msg_free(struct msg_msg *msg)

{	return sc_check_msg_msg_free(msg);}


static inline int sc_msg_queue_alloc(struct msg_queue *msq)

{

	return sc_check_msg_queue_alloc(msq);
}



static inline void sc_msg_queue_free(struct msg_queue *msq)

{	return sc_check_msg_queue_free(msq);}


static inline int sc_msg_queue_associate(struct msg_queue *msq,

					       int msqflg)

{

	return sc_check_msg_queue_associate(msq,msqflg);
}



static inline int sc_msg_queue_msgctl(struct msg_queue *msq, int cmd)

{

	return sc_check_msg_queue_msgctl(msq,cmd);
}



static inline int sc_msg_queue_msgsnd(struct msg_queue *msq,

					    struct msg_msg *msg, int msqflg)

{

	return sc_check_msg_queue_msgsnd(msq,msg,msqflg);
}



static inline int sc_msg_queue_msgrcv(struct msg_queue *msq,

					    struct msg_msg *msg,

					    struct task_struct *target,

					    long type, int mode)

{

	return sc_check_msg_queue_msgrcv(msq,msg,target,type,mode);
}



static inline int sc_shm_alloc(struct shmid_kernel *shp)

{

	return sc_check_shm_alloc(shp);
}



static inline void sc_shm_free(struct shmid_kernel *shp)

{	return sc_check_shm_free(shp);}


static inline int sc_shm_associate(struct shmid_kernel *shp,

					 int shmflg)

{

	return sc_check_shm_associate(shp,shmflg);
}



static inline int sc_shm_shmctl(struct shmid_kernel *shp, int cmd)

{

	return sc_check_shm_shmctl(shp,cmd);
}



static inline int sc_shm_shmat(struct shmid_kernel *shp,

				     char __user *shmaddr, int shmflg)

{

	return sc_check_shm_shmat(shp,shmaddr,shmflg);
}



static inline int sc_sem_alloc(struct sem_array *sma)

{

	return sc_check_sem_alloc(sma);
}



static inline void sc_sem_free(struct sem_array *sma)

{	return sc_check_sem_free(sma);}


static inline int sc_sem_associate(struct sem_array *sma, int semflg)

{

	return sc_check_sem_associate(sma,semflg);
}



static inline int sc_sem_semctl(struct sem_array *sma, int cmd)

{

	return sc_check_sem_semctl(sma,cmd);
}



static inline int sc_sem_semop(struct sem_array *sma,

				     struct sembuf *sops, unsigned int nsops,

				     int alter)

{

	return sc_check_sem_semop(sma,sops,nsops,alter);
}



static inline void sc_d_instantiate(struct dentry *dentry, struct inode *inode)

{	return sc_check_d_instantiate(dentry,inode);}


static inline int sc_getprocattr(struct task_struct *p, char *name, char **value)

{

	/* return -EINVAL; */
	return sc_check_getprocattr(p,name,value);
}



static inline int sc_setprocattr(struct task_struct *p, char *name, void *value, size_t size)

{

	/* return -EINVAL; */
	return sc_check_setprocattr(p,name,value,size);
}



static inline int sc_netlink_send(struct sock *sk, struct sk_buff *skb)

{

	/* return cap_netlink_send(sk, skb); */
	return sc_check_netlink_send(sk,skb);
}



static inline int sc_netlink_recv(struct sk_buff *skb, int cap)

{

	/* return cap_netlink_recv(skb, cap); */
	return sc_check_netlink_recv(skb,cap);
}



static inline int sc_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)

{

	/* return -EOPNOTSUPP; */
	return sc_check_secid_to_secctx(secid,secdata,seclen);
}



static inline int sc_secctx_to_secid(const char *secdata,

					   u32 seclen,

					   u32 *secid)

{

	/* return -EOPNOTSUPP; */
	return sc_check_secctx_to_secid(secdata,seclen,secid);
}



static inline void sc_release_secctx(char *secdata, u32 seclen)

{
	return sc_check_release_secctx(secdata,seclen);
}

#endif	/* CONFIG_SECURITY */



#ifdef CONFIG_SECURITY_NETWORK







#else	/* CONFIG_SECURITY_NETWORK */

static inline int sc_unix_stream_connect(struct socket *sock,

					       struct socket *other,

					       struct sock *newsk)

{

	return sc_check_unix_stream_connect(sock,other,newsk);
}



static inline int sc_unix_may_send(struct socket *sock,

					 struct socket *other)

{

	return sc_check_unix_may_send(sock,other);
}



static inline int sc_socket_create(int family, int type,

					 int protocol, int kern)

{

	return sc_check_socket_create(family,type,protocol,kern);
}



static inline int sc_socket_post_create(struct socket *sock,

					      int family,

					      int type,

					      int protocol, int kern)

{

	return sc_check_socket_post_create(sock,family,type,protocol,kern);
}



static inline int sc_socket_bind(struct socket *sock,

				       struct sockaddr *address,

				       int addrlen)

{

	return sc_check_socket_bind(sock,address,addrlen);
}



static inline int sc_socket_connect(struct socket *sock,

					  struct sockaddr *address,

					  int addrlen)

{

	return sc_check_socket_connect(sock,address,addrlen);
}



static inline int sc_socket_listen(struct socket *sock, int backlog)

{

	return sc_check_socket_listen(sock,backlog);
}



static inline int sc_socket_accept(struct socket *sock,

					 struct socket *newsock)

{

	return sc_check_socket_accept(sock,newsock);
}



static inline int sc_socket_sendmsg(struct socket *sock,

					  struct msghdr *msg, int size)

{

	return sc_check_socket_sendmsg(sock,msg,size);
}



static inline int sc_socket_recvmsg(struct socket *sock,

					  struct msghdr *msg, int size,

					  int flags)

{

	return sc_check_socket_recvmsg(sock,msg,size,flags);
}



static inline int sc_socket_getsockname(struct socket *sock)

{

	return sc_check_socket_getsockname(sock);
}



static inline int sc_socket_getpeername(struct socket *sock)

{

	return sc_check_socket_getpeername(sock);
}



static inline int sc_socket_getsockopt(struct socket *sock,

					     int level, int optname)

{

	return sc_check_socket_getsockopt(sock,level,optname);
}



static inline int sc_socket_setsockopt(struct socket *sock,

					     int level, int optname)

{

	return sc_check_socket_setsockopt(sock,level,optname);
}



static inline int sc_socket_shutdown(struct socket *sock, int how)

{

	return sc_check_socket_shutdown(sock,how);
}

static inline int sc_sock_rcv_skb(struct sock *sk,

					struct sk_buff *skb)

{

	return sc_check_sock_rcv_skb(sk,skb);
}



static inline int sc_socket_getpeersec_stream(struct socket *sock, char __user *optval,

						    int __user *optlen, unsigned int len)

{

	/* return -ENOPROTOOPT; */
	return sc_check_socket_getpeersec_stream(sock,optval,optlen,len);
}



static inline int sc_socket_getpeersec_dgram(struct socket *sock, struct sk_buff *skb, u32 *secid)

{

	/* return -ENOPROTOOPT; */
	return sc_check_socket_getpeersec_dgram(sock,skb,secid);
}



static inline int sc_sk_alloc(struct sock *sk, int family, gfp_t priority)

{

	return sc_check_sk_alloc(sk,family,priority);
}



static inline void sc_sk_free(struct sock *sk)

{
	return sc_check_sk_free(sk);
}



static inline void sc_sk_clone(const struct sock *sk, struct sock *newsk)

{
	return sc_check_sk_clone(sk,newsk);
}



static inline void sc_sk_classify_flow(struct sock *sk, struct flowi *fl)

{
	return sc_check_sk_classify_flow(sk,fl);
}



static inline void sc_req_classify_flow(const struct request_sock *req, struct flowi *fl)

{
	return sc_check_req_classify_flow(req,fl);
}



static inline void sc_sock_graft(struct sock *sk, struct socket *parent)

{
	return sc_check_sock_graft(sk,parent);
}



static inline int sc_inet_conn_request(struct sock *sk,

			struct sk_buff *skb, struct request_sock *req)

{

	return sc_check_inet_conn_request(sk,skb,req);
}



static inline void sc_inet_csk_clone(struct sock *newsk,

			const struct request_sock *req)

{
	return sc_check_inet_csk_clone(newsk,req);
}



static inline void sc_inet_conn_established(struct sock *sk,

			struct sk_buff *skb)

{
	return sc_check_inet_conn_established(sk,skb);
}





static inline int sc_xfrm_policy_alloc(struct xfrm_sec_ctx **ctxp, struct xfrm_user_sec_ctx *sec_ctx)

{

	return sc_check_xfrm_policy_alloc(ctxp,sec_ctx);
}



static inline int sc_xfrm_policy_clone(struct xfrm_sec_ctx *old, struct xfrm_sec_ctx **new_ctxp)

{

	return sc_check_xfrm_policy_clone(old,new_ctxp);
}



static inline void sc_xfrm_policy_free(struct xfrm_sec_ctx *ctx)

{
	return sc_check_xfrm_policy_free(ctx);
}



static inline int sc_xfrm_policy_delete(struct xfrm_sec_ctx *ctx)

{

	return sc_check_xfrm_policy_delete(ctx);
}



static inline int sc_xfrm_state_alloc(struct xfrm_state *x,

					struct xfrm_user_sec_ctx *sec_ctx)

{

	return sc_check_xfrm_state_alloc(x,sec_ctx);
}



static inline int sc_xfrm_state_alloc_acquire(struct xfrm_state *x,

					struct xfrm_sec_ctx *polsec, u32 secid)

{

	return sc_check_xfrm_state_alloc_acquire(x,polsec,secid);
}



static inline void sc_xfrm_state_free(struct xfrm_state *x)

{
	return sc_check_xfrm_state_free(x);
}



static inline int sc_xfrm_state_delete(struct xfrm_state *x)

{

	return sc_check_xfrm_state_delete(x);
}



static inline int sc_xfrm_policy_lookup(struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir)

{

	return sc_check_xfrm_policy_lookup(ctx,fl_secid,dir);
}



static inline int sc_xfrm_state_pol_flow_match(struct xfrm_state *x,

			struct xfrm_policy *xp, struct flowi *fl)

{

	/* return 1; */
	return sc_check_xfrm_state_pol_flow_match(x,xp,fl);
}



static inline int sc_xfrm_decode_session(struct sk_buff *skb, u32 *secid)

{

	return sc_check_xfrm_decode_session(skb,secid);
}



static inline void sc_skb_classify_flow(struct sk_buff *skb, struct flowi *fl)

{
	return sc_check_skb_classify_flow(skb,fl);
}





static inline int sc_path_unlink(struct path *dir, struct dentry *dentry)

{

	return sc_check_path_unlink(dir,dentry);
}



static inline int sc_path_mkdir(struct path *dir, struct dentry *dentry,

				      int mode)

{

	return sc_check_path_mkdir(dir,dentry,mode);
}



static inline int sc_path_rmdir(struct path *dir, struct dentry *dentry)

{

	return sc_check_path_rmdir(dir,dentry);
}



static inline int sc_path_mknod(struct path *dir, struct dentry *dentry,

				      int mode, unsigned int dev)

{

	return sc_check_path_mknod(dir,dentry,mode,dev);
}



static inline int sc_path_truncate(struct path *path, loff_t length,

					 unsigned int time_attrs)

{

	return sc_check_path_truncate(path,length,time_attrs);
}



static inline int sc_path_symlink(struct path *dir, struct dentry *dentry,

					const char *old_name)

{

	return sc_check_path_symlink(dir,dentry,old_name);
}



static inline int sc_path_link(struct dentry *old_dentry,

				     struct path *new_dir,

				     struct dentry *new_dentry)

{

	return sc_check_path_link(old_dentry,new_dir,new_dentry);
}



static inline int sc_path_rename(struct path *old_dir,

				       struct dentry *old_dentry,

				       struct path *new_dir,

				       struct dentry *new_dentry)

{

	return sc_check_path_rename(old_dir,old_dentry,new_dir,new_dentry);
}

#endif	/* CONFIG_SECURITY_PATH */



#ifdef CONFIG_KEYS



static inline int sc_key_alloc(struct key *key,

				     const struct cred *cred,

				     unsigned long flags)

{

	return sc_check_key_alloc(key,cred,flags);
}



static inline void sc_key_free(struct key *key)

{
	return sc_check_key_free(key);
}



static inline int sc_key_permission(key_ref_t key_ref,

					  const struct cred *cred,

					  key_perm_t perm)

{

	return sc_check_key_permission(key_ref,cred,perm);
}



static inline int sc_key_getsecurity(struct key *key, char **_buffer)

{

	*_buffer = NULL;

	return sc_check_key_getsecurity(key,_buffer);
}



#endif /* CONFIG_KEYS */



#ifdef CONFIG_AUDIT





static inline int sc_audit_rule_init(u32 field, u32 op, char *rulestr,

					   void **lsmrule)

{

	return sc_check_audit_rule_init(field,op,rulestr,lsmrule);
}



static inline int sc_audit_rule_known(struct audit_krule *krule)

{

	return sc_check_audit_rule_known(krule);
}



static inline int sc_audit_rule_match(u32 secid, u32 field, u32 op,

				   void *lsmrule, struct audit_context *actx)

{

	return sc_check_audit_rule_match(secid,field,op,lsmrule,actx);
}



static inline void sc_audit_rule_free(void *lsmrule)

{	return sc_check_audit_rule_free(lsmrule);}


#endif /* CONFIG_SECURITY */

#endif /* CONFIG_AUDIT */



struct security_operations sc_ops = {
.ptrace_may_access = lsm_ptrace_may_access,
.ptrace_traceme = lsm_ptrace_traceme,
.capget = lsm_capget,
.capset = lsm_capset,
.capable = lsm_capable,
.acct = lsm_acct,
.sysctl = lsm_sysctl,
.quotactl = lsm_quotactl,
.quota_on = lsm_quota_on,
.syslog = lsm_syslog,
.settime = lsm_settime,
.vm_enough_memory = lsm_vm_enough_memory,
.bprm_set_creds = lsm_bprm_set_creds,
.bprm_check_security = lsm_bprm_check_security,
.bprm_secureexec = lsm_bprm_secureexec,
.bprm_committing_creds = lsm_bprm_committing_creds,
.bprm_committed_creds = lsm_bprm_committed_creds,
.sb_alloc_security = lsm_sb_alloc_security,
.sb_free_security = lsm_sb_free_security,
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
.path_unlink = lsm_path_unlink,
.path_mkdir = lsm_path_mkdir,
.path_rmdir = lsm_path_rmdir,
.path_mknod = lsm_path_mknod,
.path_truncate = lsm_path_truncate,
.path_symlink = lsm_path_symlink,
.path_link = lsm_path_link,
.path_rename = lsm_path_rename,
.inode_alloc_security = lsm_inode_alloc_security,
.inode_free_security = lsm_inode_free_security,
.inode_init_security = lsm_inode_init_security,
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
.file_alloc_security = lsm_file_alloc_security,
.file_free_security = lsm_file_free_security,
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
.cred_prepare = lsm_cred_prepare,
.cred_commit = lsm_cred_commit,
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
.msg_msg_alloc_security = lsm_msg_msg_alloc_security,
.msg_msg_free_security = lsm_msg_msg_free_security,
.msg_queue_alloc_security = lsm_msg_queue_alloc_security,
.msg_queue_free_security = lsm_msg_queue_free_security,
.msg_queue_associate = lsm_msg_queue_associate,
.msg_queue_msgctl = lsm_msg_queue_msgctl,
.msg_queue_msgsnd = lsm_msg_queue_msgsnd,
.msg_queue_msgrcv = lsm_msg_queue_msgrcv,
.shm_alloc_security = lsm_shm_alloc_security,
.shm_free_security = lsm_shm_free_security,
.shm_associate = lsm_shm_associate,
.shm_shmctl = lsm_shm_shmctl,
.shm_shmat = lsm_shm_shmat,
.sem_alloc_security = lsm_sem_alloc_security,
.sem_free_security = lsm_sem_free_security,
.sem_associate = lsm_sem_associate,
.sem_semctl = lsm_sem_semctl,
.sem_semop = lsm_sem_semop,
.netlink_send = lsm_netlink_send,
.netlink_recv = lsm_netlink_recv,
.d_instantiate = lsm_d_instantiate,
.getprocattr = lsm_getprocattr,
.setprocattr = lsm_setprocattr,
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
.socket_sock_rcv_skb = lsm_socket_sock_rcv_skb,
.socket_getpeersec_stream = lsm_socket_getpeersec_stream,
.socket_getpeersec_dgram = lsm_socket_getpeersec_dgram,
.sk_alloc_security = lsm_sk_alloc_security,
.sk_free_security = lsm_sk_free_security,
.sk_clone_security = lsm_sk_clone_security,
.sk_getsecid = lsm_sk_getsecid,
.sock_graft = lsm_sock_graft,
.inet_conn_request = lsm_inet_conn_request,
.inet_csk_clone = lsm_inet_csk_clone,
.inet_conn_established = lsm_inet_conn_established,
.req_classify_flow = lsm_req_classify_flow,
.xfrm_policy_alloc_security = lsm_xfrm_policy_alloc_security,
.xfrm_policy_clone_security = lsm_xfrm_policy_clone_security,
.xfrm_policy_free_security = lsm_xfrm_policy_free_security,
.xfrm_policy_delete_security = lsm_xfrm_policy_delete_security,
.xfrm_state_alloc_security = lsm_xfrm_state_alloc_security,
.xfrm_state_free_security = lsm_xfrm_state_free_security,
.xfrm_state_delete_security = lsm_xfrm_state_delete_security,
.xfrm_policy_lookup = lsm_xfrm_policy_lookup,
.xfrm_state_pol_flow_match = lsm_xfrm_state_pol_flow_match,
.xfrm_decode_session = lsm_xfrm_decode_session,
.key_alloc = lsm_key_alloc,
.key_free = lsm_key_free,
.key_permission = lsm_key_permission,
.key_getsecurity = lsm_key_getsecurity,
.audit_rule_init = lsm_audit_rule_init,
.audit_rule_known = lsm_audit_rule_known,
.audit_rule_match = lsm_audit_rule_match,
.audit_rule_free = lsm_audit_rule_free,
};

