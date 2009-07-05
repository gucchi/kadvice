extern int sc_check_ptrace_may_access(struct task_struct * child,unsigned int mode);
extern int sc_check_ptrace_traceme(struct task_struct * parent);
extern int sc_check_capget(struct task_struct * target,kernel_cap_t * effective,kernel_cap_t * inheritable,kernel_cap_t * permitted);
extern int sc_check_capset(struct cred * new,const struct cred * old,const kernel_cap_t * effective,const kernel_cap_t * inheritable,const kernel_cap_t * permitted);
extern int sc_check_capable(int cap);
extern int sc_check_real_capable(struct task_struct * tsk,int cap);
extern int sc_check_real_capable_noaudit(struct task_struct * tsk,int cap);
extern int sc_check_acct(struct file * file);
extern int sc_check_sysctl(struct ctl_table * table,int op);
extern int sc_check_quotactl(int cmds,int type,int id,struct super_block * sb);
extern int sc_check_quota_on(struct dentry * dentry);
extern int sc_check_syslog(int type);
extern int sc_check_settime(struct timespec * ts,struct timezone * tz);
extern int sc_check_vm_enough_memory(long pages);
extern int sc_check_vm_enough_memory_mm(struct mm_struct * mm,long pages);
extern int sc_check_vm_enough_memory_kern(long pages);
extern int sc_check_bprm_set_creds(struct linux_binprm * bprm);
extern int sc_check_bprm_check(struct linux_binprm * bprm);
extern void sc_check_bprm_committing_creds(struct linux_binprm * bprm);
extern void sc_check_bprm_committed_creds(struct linux_binprm * bprm);
extern int sc_check_bprm_secureexec(struct linux_binprm * bprm);
extern int sc_check_sb_alloc(struct super_block * sb);
extern void sc_check_sb_free(struct super_block * sb);
extern int sc_check_sb_copy_data(char * orig,char * copy);
extern int sc_check_sb_kern_mount(struct super_block * sb,int flags,void * data);
extern int sc_check_sb_show_options(struct seq_file * m,struct super_block * sb);
extern int sc_check_sb_statfs(struct dentry * dentry);
extern int sc_check_sb_mount(char * dev_name,struct path * path,char * type,unsigned long flags,void * data);
extern int sc_check_sb_check_sb(struct vfsmount * mnt,struct path * path);
extern int sc_check_sb_umount(struct vfsmount * mnt,int flags);
extern void sc_check_sb_umount_close(struct vfsmount * mnt);
extern void sc_check_sb_umount_busy(struct vfsmount * mnt);
extern void sc_check_sb_post_remount(struct vfsmount * mnt,unsigned long flags,void * data);
extern void sc_check_sb_post_addmount(struct vfsmount * mnt,struct path * mountpoint);
extern int sc_check_sb_pivotroot(struct path * old_path,struct path * new_path);
extern void sc_check_sb_post_pivotroot(struct path * old_path,struct path * new_path);
extern int sc_check_sb_set_mnt_opts(struct super_block * sb,struct security_mnt_opts * opts);
extern void sc_check_sb_clone_mnt_opts(const struct super_block * oldsb,struct super_block * newsb);
extern int sc_check_sb_parse_opts_str(char * options,struct mnt_opts * opts);
extern int sc_check_inode_alloc(struct inode * inode);
extern void sc_check_inode_free(struct inode * inode);
extern int sc_check_inode_init_security(struct inode * inode,struct inode * dir,char ** name,void ** value,size_t * len);
extern int sc_check_path_mknod(struct path * path,struct dentry * dentry,int mode,unsigned int dev);
extern int sc_check_path_mkdir(struct path * path,struct dentry * dentry,int mode);
extern int sc_check_path_rmdir(struct path * path,struct dentry * dentry);
extern int sc_check_path_unlink(struct path * path,struct dentry * dentry);
extern int sc_check_path_symlink(struct path * path,struct dentry * dentry,const char * old_name);
extern int sc_check_path_link(struct dentry * old_dentry,struct path * new_dir,struct dentry * new_dentry);
extern int sc_check_path_rename(struct path * old_dir,struct dentry * old_dentry,struct path * new_dir,struct dentry * new_dentry);
extern int sc_check_path_truncate(struct path * path,loff_t length,unsigned int time_attrs);
extern int sc_check_inode_create(struct inode * dir,struct dentry * dentry,int mode);
extern int sc_check_inode_link(struct dentry * old_dentry,struct inode * dir,struct dentry * new_dentry);
extern int sc_check_inode_unlink(struct inode * dir,struct dentry * dentry);
extern int sc_check_inode_symlink(struct inode * dir,struct dentry * dentry,const char * old_name);
extern int sc_check_inode_mkdir(struct inode * dir,struct dentry * dentry,int mode);
extern int sc_check_inode_rmdir(struct inode * dir,struct dentry * dentry);
extern int sc_check_inode_mknod(struct inode * dir,struct dentry * dentry,int mode,dev_t dev);
extern int sc_check_inode_rename(struct inode * old_dir,struct dentry * old_dentry,struct inode * new_dir,struct dentry * new_dentry);
extern int sc_check_inode_readlink(struct dentry * dentry);
extern int sc_check_inode_follow_link(struct dentry * dentry,struct nameidata * nd);
extern int sc_check_inode_permission(struct inode * inode,int mask);
extern int sc_check_inode_setattr(struct dentry * dentry,struct iattr * attr);
extern int sc_check_inode_getattr(struct vfsmount * mnt,struct dentry * dentry);
extern void sc_check_inode_delete(struct inode * inode);
extern int sc_check_inode_setxattr(struct dentry * dentry,const char * name,const void * value,size_t size,int flags);
extern void sc_check_inode_post_setxattr(struct dentry * dentry,const char * name,const void * value,size_t size,int flags);
extern int sc_check_inode_getxattr(struct dentry * dentry,const char * name);
extern int sc_check_inode_listxattr(struct dentry * dentry);
extern int sc_check_inode_removexattr(struct dentry * dentry,const char * name);
extern int sc_check_inode_need_killpriv(struct dentry * dentry);
extern int sc_check_inode_killpriv(struct dentry * dentry);
extern int sc_check_inode_getsecurity(const struct inode * inode,const char * name,void ** buffer,bool alloc);
extern int sc_check_inode_setsecurity(struct inode * inode,const char * name,const void * value,size_t size,int flags);
extern int sc_check_inode_listsecurity(struct inode * inode,char * buffer,size_t buffer_size);
extern void sc_check_inode_getsecid(const struct inode * inode,u32 * secid);
extern int sc_check_file_permission(struct file * file,int mask);
extern int sc_check_file_alloc(struct file * file);
extern void sc_check_file_free(struct file * file);
extern int sc_check_file_ioctl(struct file * file,unsigned int cmd,unsigned long arg);
extern int sc_check_file_mmap(struct file * file,unsigned long reqprot,unsigned long prot,unsigned long flags,unsigned long addr,unsigned long addr_only);
extern int sc_check_file_mprotect(struct vm_area_struct * vma,unsigned long reqprot,unsigned long prot);
extern int sc_check_file_lock(struct file * file,unsigned int cmd);
extern int sc_check_file_fcntl(struct file * file,unsigned int cmd,unsigned long arg);
extern int sc_check_file_set_fowner(struct file * file);
extern int sc_check_file_send_sigiotask(struct task_struct * tsk,struct fown_struct * fown,int sig);
extern int sc_check_file_receive(struct file * file);
extern int sc_check_dentry_open(struct file * file,const struct cred * cred);
extern int sc_check_task_create(unsigned long clone_flags);
extern void sc_check_cred_free(struct cred * cred);
extern int sc_check_prepare_creds(struct cred * new,const struct cred * old,gfp_t gfp);
extern void sc_check_commit_creds(struct cred * new,const struct cred * old);
extern int sc_check_kernel_act_as(struct cred * new,u32 secid);
extern int sc_check_kernel_create_files_as(struct cred * new,struct inode * inode);
extern int sc_check_task_setuid(uid_t id0,uid_t id1,uid_t id2,int flags);
extern int sc_check_task_fix_setuid(struct cred * new,const struct cred * old,int flags);
extern int sc_check_task_setgid(gid_t id0,gid_t id1,gid_t id2,int flags);
extern int sc_check_task_setpgid(struct task_struct * p,pid_t pgid);
extern int sc_check_task_getpgid(struct task_struct * p);
extern int sc_check_task_getsid(struct task_struct * p);
extern void sc_check_task_getsecid(struct task_struct * p,u32 * secid);
extern int sc_check_task_setgroups(struct group_info * group_info);
extern int sc_check_task_setnice(struct task_struct * p,int nice);
extern int sc_check_task_setioprio(struct task_struct * p,int ioprio);
extern int sc_check_task_getioprio(struct task_struct * p);
extern int sc_check_task_setrlimit(unsigned int resource,struct rlimit * new_rlim);
extern int sc_check_task_setscheduler(struct task_struct * p,int policy,struct sched_param * lp);
extern int sc_check_task_getscheduler(struct task_struct * p);
extern int sc_check_task_movememory(struct task_struct * p);
extern int sc_check_task_kill(struct task_struct * p,struct siginfo * info,int sig,u32 secid);
extern int sc_check_task_wait(struct task_struct * p);
extern int sc_check_task_prctl(int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5);
extern void sc_check_task_to_inode(struct task_struct * p,struct inode * inode);
extern int sc_check_ipc_permission(struct kern_ipc_perm * ipcp,short flag);
extern void sc_check_ipc_getsecid(struct kern_ipc_perm * ipcp,u32 * secid);
extern int sc_check_msg_msg_alloc(struct msg_msg * msg);
extern void sc_check_msg_msg_free(struct msg_msg * msg);
extern int sc_check_msg_queue_alloc(struct msg_queue * msq);
extern void sc_check_msg_queue_free(struct msg_queue * msq);
extern int sc_check_msg_queue_associate(struct msg_queue * msq,int msqflg);
extern int sc_check_msg_queue_msgctl(struct msg_queue * msq,int cmd);
extern int sc_check_msg_queue_msgsnd(struct msg_queue * msq,struct msg_msg * msg,int msqflg);
extern int sc_check_msg_queue_msgrcv(struct msg_queue * msq,struct msg_msg * msg,struct task_struct * target,long type,int mode);
extern int sc_check_shm_alloc(struct shmid_kernel * shp);
extern void sc_check_shm_free(struct shmid_kernel * shp);
extern int sc_check_shm_associate(struct shmid_kernel * shp,int shmflg);
extern int sc_check_shm_shmctl(struct shmid_kernel * shp,int cmd);
extern int sc_check_shm_shmat(struct shmid_kernel * shp,char * shmaddr,int shmflg);
extern int sc_check_sem_alloc(struct sem_array * sma);
extern void sc_check_sem_free(struct sem_array * sma);
extern int sc_check_sem_associate(struct sem_array * sma,int semflg);
extern int sc_check_sem_semctl(struct sem_array * sma,int cmd);
extern int sc_check_sem_semop(struct sem_array * sma,struct sembuf * sops,unsigned int nsops,int alter);
extern void sc_check_d_instantiate(struct dentry * dentry,struct inode * inode);
extern int sc_check_getprocattr(struct task_struct * p,char * name,char ** value);
extern int sc_check_setprocattr(struct task_struct * p,char * name,void * value,size_t size);
extern int sc_check_netlink_send(struct sock * sk,struct sk_buff * skb);
extern int sc_check_netlink_recv(struct sk_buff * skb,int cap);
extern int sc_check_secid_to_secctx(u32 secid,char ** secdata,u32 * seclen);
extern int sc_check_secctx_to_secid(const char * secdata,u32 seclen,u32 * secid);
extern void sc_check_release_secctx(char * secdata,u32 seclen);
extern int sc_check_unix_stream_connect(struct socket * sock,struct socket * other,struct sock * newsk);
extern int sc_check_unix_may_send(struct socket * sock,struct socket * other);
extern int sc_check_socket_create(int family,int type,int protocol,int kern);
extern int sc_check_socket_post_create(struct socket * sock,int family,int type,int protocol,int kern);
extern int sc_check_socket_bind(struct socket * sock,struct sockaddr * address,int addrlen);
extern int sc_check_socket_connect(struct socket * sock,struct sockaddr * address,int addrlen);
extern int sc_check_socket_listen(struct socket * sock,int backlog);
extern int sc_check_socket_accept(struct socket * sock,struct socket * newsock);
extern int sc_check_socket_sendmsg(struct socket * sock,struct msghdr * msg,int size);
extern int sc_check_socket_recvmsg(struct socket * sock,struct msghdr * msg,int size,int flags);
extern int sc_check_socket_getsockname(struct socket * sock);
extern int sc_check_socket_getpeername(struct socket * sock);
extern int sc_check_socket_getsockopt(struct socket * sock,int level,int optname);
extern int sc_check_socket_setsockopt(struct socket * sock,int level,int optname);
extern int sc_check_socket_shutdown(struct socket * sock,int how);
extern int sc_check_sock_rcv_skb(struct sock * sk,struct sk_buff * skb);
extern int sc_check_socket_getpeersec_stream(struct socket * sock,char * optval,int * optlen,unsigned int len);
extern int sc_check_socket_getpeersec_dgram(struct socket * sock,struct sk_buff * skb,u32 * secid);
extern int sc_check_sk_alloc(struct sock * sk,int family,gfp_t priority);
extern void sc_check_sk_free(struct sock * sk);
extern void sc_check_sk_clone(const struct sock * sk,struct sock * newsk);
extern void sc_check_sk_classify_flow(struct sock * sk,struct flowi * fl);
extern void sc_check_req_classify_flow(const struct request_sock * req,struct flowi * fl);
extern void sc_check_sock_graft(struct sock * sk,struct socket * parent);
extern int sc_check_inet_conn_request(struct sock * sk,struct sk_buff * skb,struct request_sock * req);
extern void sc_check_inet_csk_clone(struct sock * newsk,const struct request_sock * req);
extern void sc_check_inet_conn_established(struct sock * sk,struct sk_buff * skb);
extern int sc_check_xfrm_policy_alloc(struct xfrm_sec_ctx ** ctxp,struct xfrm_user_sec_ctx * sec_ctx);
extern int sc_check_xfrm_policy_clone(struct xfrm_sec_ctx * old_ctx,struct xfrm_sec_ctx ** new_ctxp);
extern void sc_check_xfrm_policy_free(struct xfrm_sec_ctx * ctx);
extern int sc_check_xfrm_policy_delete(struct xfrm_sec_ctx * ctx);
extern int sc_check_xfrm_state_alloc(struct xfrm_state * x,struct xfrm_user_sec_ctx * sec_ctx);
extern int sc_check_xfrm_state_alloc_acquire(struct xfrm_state * x,struct xfrm_sec_ctx * polsec,u32 secid);
extern int sc_check_xfrm_state_delete(struct xfrm_state * x);
extern void sc_check_xfrm_state_free(struct xfrm_state * x);
extern int sc_check_xfrm_policy_lookup(struct xfrm_sec_ctx * ctx,u32 fl_secid,u8 dir);
extern int sc_check_xfrm_state_pol_flow_match(struct xfrm_state * x,struct xfrm_policy * xp,struct flowi * fl);
extern int sc_check_xfrm_decode_session(struct sk_buff * skb,u32 * secid);
extern void sc_check_skb_classify_flow(struct sk_buff * skb,struct flowi * fl);
extern int sc_check_key_alloc(struct key * key,const struct cred * cred,unsigned long flags);
extern void sc_check_key_free(struct key * key);
extern int sc_check_key_permission(key_ref_t key_ref,const struct cred * cred,key_perm_t perm);
extern int sc_check_key_getsecurity(struct key * key,char ** _buffer);
extern int sc_check_audit_rule_init(u32 field,u32 op,char * rulestr,void ** lsmrule);
extern int sc_check_audit_rule_known(struct audit_krule * krule);
extern void sc_check_audit_rule_free(void * lsmrule);
extern int sc_check_audit_rule_match(u32 secid,u32 field,u32 op,void * lsmrule,struct audit_context * actx);
