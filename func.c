FUNC2INT(lsm_acc, ptrace_may_access, struct task_struct *, child, unsigned int, mode);
FUNC1INT(lsm_acc, ptrace_traceme, struct task_struct *, parent);
FUNC4INT(lsm_acc, capget, struct task_struct *, target, kernel_cap_t *, effective, kernel_cap_t *, inheritable, kernel_cap_t *, permitted);
FUNC5INT(lsm_acc, capset, struct cred *, new, const struct cred *, old, const kernel_cap_t *, effective, const kernel_cap_t *, inheritable, const kernel_cap_t *, permitted);
FUNC1INT(lsm_acc, capable, int, cap);
FUNC2INT(lsm_acc, real_capable, struct task_struct *, tsk, int, cap);
FUNC2INT(lsm_acc, real_capable_noaudit, struct task_struct *, tsk, int, cap);
FUNC1INT(lsm_acc, acct, struct file *, file);
FUNC2INT(lsm_acc, sysctl, struct ctl_table *, table, int, op);
FUNC4INT(lsm_acc, quotactl, int, cmds, int, type, int, id, struct super_block *, sb);
FUNC1INT(lsm_acc, quota_on, struct dentry *, dentry);
FUNC1INT(lsm_acc, syslog, int, type);
FUNC2INT(lsm_acc, settime, struct timespec *, ts, struct timezone *, tz);
FUNC1INT(lsm_acc, vm_enough_memory, long, pages);
FUNC2INT(lsm_acc, vm_enough_memory_mm, struct mm_struct *, mm, long, pages);
FUNC1INT(lsm_acc, vm_enough_memory_kern, long, pages);
FUNC1INT(lsm_acc, bprm_set_creds, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, bprm_check, struct linux_binprm *, bprm);
FUNC1VOID(lsm_acc, bprm_committing_creds, struct linux_binprm *, bprm);
FUNC1VOID(lsm_acc, bprm_committed_creds, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, bprm_secureexec, struct linux_binprm *, bprm);
FUNC1INT(lsm_acc, sb_alloc, struct super_block *, sb);
FUNC1VOID(lsm_acc, sb_free, struct super_block *, sb);
FUNC2INT(lsm_acc, sb_copy_data, char *, orig, char *, copy);
FUNC3INT(lsm_acc, sb_kern_mount, struct super_block *, sb, int, flags, void *, data);
FUNC2INT(lsm_acc, sb_show_options, struct seq_file *, m, struct super_block *, sb);
FUNC1INT(lsm_acc, sb_statfs, struct dentry *, dentry);
FUNC5INT(lsm_acc, sb_mount, char *, dev_name, struct path *, path, char *, type, unsigned long, flags, void *, data);
FUNC2INT(lsm_acc, sb_check_sb, struct vfsmount *, mnt, struct path *, path);
FUNC2INT(lsm_acc, sb_umount, struct vfsmount *, mnt, int, flags);
FUNC1VOID(lsm_acc, sb_umount_close, struct vfsmount *, mnt);
FUNC1VOID(lsm_acc, sb_umount_busy, struct vfsmount *, mnt);
FUNC3VOID(lsm_acc, sb_post_remount, struct vfsmount *, mnt, unsigned long, flags, void *, data);
FUNC2VOID(lsm_acc, sb_post_addmount, struct vfsmount *, mnt, struct path *, mountpoint);
FUNC2INT(lsm_acc, sb_pivotroot, struct path *, old_path, struct path *, new_path);
FUNC2VOID(lsm_acc, sb_post_pivotroot, struct path *, old_path, struct path *, new_path);
FUNC2INT(lsm_acc, sb_set_mnt_opts, struct super_block *, sb, struct security_mnt_opts *, opts);
FUNC2VOID(lsm_acc, sb_clone_mnt_opts, const struct super_block *, oldsb, struct super_block *, newsb);
FUNC2INT(lsm_acc, sb_parse_opts_str, char *, options, struct mnt_opts *, opts);
FUNC1INT(lsm_acc, inode_alloc, struct inode *, inode);
FUNC1VOID(lsm_acc, inode_free, struct inode *, inode);
FUNC5INT(lsm_acc, inode_init_security, struct inode *, inode, struct inode *, dir, char **, name, void **, value, size_t *, len);
FUNC4INT(lsm_acc, path_mknod, struct path *, path, struct dentry *, dentry, int, mode, unsigned int, dev);
FUNC3INT(lsm_acc, path_mkdir, struct path *, path, struct dentry *, dentry, int, mode);
FUNC2INT(lsm_acc, path_rmdir, struct path *, path, struct dentry *, dentry);
FUNC2INT(lsm_acc, path_unlink, struct path *, path, struct dentry *, dentry);
FUNC3INT(lsm_acc, path_symlink, struct path *, path, struct dentry *, dentry, const char *, old_name);
FUNC3INT(lsm_acc, path_link, struct dentry *, old_dentry, struct path *, new_dir, struct dentry *, new_dentry);
FUNC4INT(lsm_acc, path_rename, struct path *, old_dir, struct dentry *, old_dentry, struct path *, new_dir, struct dentry *, new_dentry);
FUNC3INT(lsm_acc, path_truncate, struct path *, path, loff_t, length, unsigned int, time_attrs);
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
FUNC2INT(lsm_acc, inode_permission, struct inode *, inode, int, mask);
FUNC2INT(lsm_acc, inode_setattr, struct dentry *, dentry, struct iattr *, attr);
FUNC2INT(lsm_acc, inode_getattr, struct vfsmount *, mnt, struct dentry *, dentry);
FUNC1VOID(lsm_acc, inode_delete, struct inode *, inode);
FUNC5INT(lsm_acc, inode_setxattr, struct dentry *, dentry, const char *, name, const void *, value, size_t, size, int, flags);
FUNC5VOID(lsm_acc, inode_post_setxattr, struct dentry *, dentry, const char *, name, const void *, value, size_t, size, int, flags);
FUNC2INT(lsm_acc, inode_getxattr, struct dentry *, dentry, const char *, name);
FUNC1INT(lsm_acc, inode_listxattr, struct dentry *, dentry);
FUNC2INT(lsm_acc, inode_removexattr, struct dentry *, dentry, const char *, name);
FUNC1INT(lsm_acc, inode_need_killpriv, struct dentry *, dentry);
FUNC1INT(lsm_acc, inode_killpriv, struct dentry *, dentry);
FUNC4INT(lsm_acc, inode_getsecurity, const struct inode *, inode, const char *, name, void **, buffer, bool, alloc);
FUNC5INT(lsm_acc, inode_setsecurity, struct inode *, inode, const char *, name, const void *, value, size_t, size, int, flags);
FUNC3INT(lsm_acc, inode_listsecurity, struct inode *, inode, char *, buffer, size_t, buffer_size);
FUNC2VOID(lsm_acc, inode_getsecid, const struct inode *, inode, u32 *, secid);
FUNC2INT(lsm_acc, file_permission, struct file *, file, int, mask);
FUNC1INT(lsm_acc, file_alloc, struct file *, file);
FUNC1VOID(lsm_acc, file_free, struct file *, file);
FUNC3INT(lsm_acc, file_ioctl, struct file *, file, unsigned int, cmd, unsigned long, arg);
FUNC6INT(lsm_acc, file_mmap, struct file *, file, unsigned long, reqprot, unsigned long, prot, unsigned long, flags, unsigned long, addr, unsigned long, addr_only);
FUNC3INT(lsm_acc, file_mprotect, struct vm_area_struct *, vma, unsigned long, reqprot, unsigned long, prot);
FUNC2INT(lsm_acc, file_lock, struct file *, file, unsigned int, cmd);
FUNC3INT(lsm_acc, file_fcntl, struct file *, file, unsigned int, cmd, unsigned long, arg);
FUNC1INT(lsm_acc, file_set_fowner, struct file *, file);
FUNC3INT(lsm_acc, file_send_sigiotask, struct task_struct *, tsk, struct fown_struct *, fown, int, sig);
FUNC1INT(lsm_acc, file_receive, struct file *, file);
FUNC2INT(lsm_acc, dentry_open, struct file *, file, const struct cred *, cred);
FUNC1INT(lsm_acc, task_create, unsigned long, clone_flags);
FUNC1VOID(lsm_acc, cred_free, struct cred *, cred);
FUNC3INT(lsm_acc, prepare_creds, struct cred *, new, const struct cred *, old, gfp_t, gfp);
FUNC2VOID(lsm_acc, commit_creds, struct cred *, new, const struct cred *, old);
FUNC2INT(lsm_acc, kernel_act_as, struct cred *, new, u32, secid);
FUNC2INT(lsm_acc, kernel_create_files_as, struct cred *, new, struct inode *, inode);
FUNC4INT(lsm_acc, task_setuid, uid_t, id0, uid_t, id1, uid_t, id2, int, flags);
FUNC3INT(lsm_acc, task_fix_setuid, struct cred *, new, const struct cred *, old, int, flags);
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
FUNC2VOID(lsm_acc, task_to_inode, struct task_struct *, p, struct inode *, inode);
FUNC2INT(lsm_acc, ipc_permission, struct kern_ipc_perm *, ipcp, short, flag);
FUNC2VOID(lsm_acc, ipc_getsecid, struct kern_ipc_perm *, ipcp, u32 *, secid);
FUNC1INT(lsm_acc, msg_msg_alloc, struct msg_msg *, msg);
FUNC1VOID(lsm_acc, msg_msg_free, struct msg_msg *, msg);
FUNC1INT(lsm_acc, msg_queue_alloc, struct msg_queue *, msq);
FUNC1VOID(lsm_acc, msg_queue_free, struct msg_queue *, msq);
FUNC2INT(lsm_acc, msg_queue_associate, struct msg_queue *, msq, int, msqflg);
FUNC2INT(lsm_acc, msg_queue_msgctl, struct msg_queue *, msq, int, cmd);
FUNC3INT(lsm_acc, msg_queue_msgsnd, struct msg_queue *, msq, struct msg_msg *, msg, int, msqflg);
FUNC5INT(lsm_acc, msg_queue_msgrcv, struct msg_queue *, msq, struct msg_msg *, msg, struct task_struct *, target, long, type, int, mode);
FUNC1INT(lsm_acc, shm_alloc, struct shmid_kernel *, shp);
FUNC1VOID(lsm_acc, shm_free, struct shmid_kernel *, shp);
FUNC2INT(lsm_acc, shm_associate, struct shmid_kernel *, shp, int, shmflg);
FUNC2INT(lsm_acc, shm_shmctl, struct shmid_kernel *, shp, int, cmd);
FUNC3INT(lsm_acc, shm_shmat, struct shmid_kernel *, shp, char *, shmaddr, int, shmflg);
FUNC1INT(lsm_acc, sem_alloc, struct sem_array *, sma);
FUNC1VOID(lsm_acc, sem_free, struct sem_array *, sma);
FUNC2INT(lsm_acc, sem_associate, struct sem_array *, sma, int, semflg);
FUNC2INT(lsm_acc, sem_semctl, struct sem_array *, sma, int, cmd);
FUNC4INT(lsm_acc, sem_semop, struct sem_array *, sma, struct sembuf *, sops, unsigned int, nsops, int, alter);
FUNC2VOID(lsm_acc, d_instantiate, struct dentry *, dentry, struct inode *, inode);
FUNC3INT(lsm_acc, getprocattr, struct task_struct *, p, char *, name, char **, value);
FUNC4INT(lsm_acc, setprocattr, struct task_struct *, p, char *, name, void *, value, size_t, size);
FUNC2INT(lsm_acc, netlink_send, struct sock *, sk, struct sk_buff *, skb);
FUNC2INT(lsm_acc, netlink_recv, struct sk_buff *, skb, int, cap);
FUNC3INT(lsm_acc, secid_to_secctx, u32, secid, char **, secdata, u32 *, seclen);
FUNC3INT(lsm_acc, secctx_to_secid, const char *, secdata, u32, seclen, u32 *, secid);
FUNC2VOID(lsm_acc, release_secctx, char *, secdata, u32, seclen);
FUNC3INT(lsm_acc, unix_stream_connect, struct socket *, sock, struct socket *, other, struct sock *, newsk);
FUNC2INT(lsm_acc, unix_may_send, struct socket *, sock, struct socket *, other);
FUNC4INT(lsm_acc, socket_create, int, family, int, type, int, protocol, int, kern);
FUNC5INT(lsm_acc, socket_post_create, struct socket *, sock, int, family, int, type, int, protocol, int, kern);
FUNC3INT(lsm_acc, socket_bind, struct socket *, sock, struct sockaddr *, address, int, addrlen);
FUNC3INT(lsm_acc, socket_connect, struct socket *, sock, struct sockaddr *, address, int, addrlen);
FUNC2INT(lsm_acc, socket_listen, struct socket *, sock, int, backlog);
FUNC2INT(lsm_acc, socket_accept, struct socket *, sock, struct socket *, newsock);
FUNC3INT(lsm_acc, socket_sendmsg, struct socket *, sock, struct msghdr *, msg, int, size);
FUNC4INT(lsm_acc, socket_recvmsg, struct socket *, sock, struct msghdr *, msg, int, size, int, flags);
FUNC1INT(lsm_acc, socket_getsockname, struct socket *, sock);
FUNC1INT(lsm_acc, socket_getpeername, struct socket *, sock);
FUNC3INT(lsm_acc, socket_getsockopt, struct socket *, sock, int, level, int, optname);
FUNC3INT(lsm_acc, socket_setsockopt, struct socket *, sock, int, level, int, optname);
FUNC2INT(lsm_acc, socket_shutdown, struct socket *, sock, int, how);
FUNC2INT(lsm_acc, sock_rcv_skb, struct sock *, sk, struct sk_buff *, skb);
FUNC4INT(lsm_acc, socket_getpeersec_stream, struct socket *, sock, char *, optval, int *, optlen, unsigned int, len);
FUNC3INT(lsm_acc, socket_getpeersec_dgram, struct socket *, sock, struct sk_buff *, skb, u32 *, secid);
FUNC3INT(lsm_acc, sk_alloc, struct sock *, sk, int, family, gfp_t, priority);
FUNC1VOID(lsm_acc, sk_free, struct sock *, sk);
FUNC2VOID(lsm_acc, sk_clone, const struct sock *, sk, struct sock *, newsk);
FUNC2VOID(lsm_acc, sk_classify_flow, struct sock *, sk, struct flowi *, fl);
FUNC2VOID(lsm_acc, req_classify_flow, const struct request_sock *, req, struct flowi *, fl);
FUNC2VOID(lsm_acc, sock_graft, struct sock *, sk, struct socket *, parent);
FUNC3INT(lsm_acc, inet_conn_request, struct sock *, sk, struct sk_buff *, skb, struct request_sock *, req);
FUNC2VOID(lsm_acc, inet_csk_clone, struct sock *, newsk, const struct request_sock *, req);
FUNC2VOID(lsm_acc, inet_conn_established, struct sock *, sk, struct sk_buff *, skb);
FUNC2INT(lsm_acc, xfrm_policy_alloc, struct xfrm_sec_ctx **, ctxp, struct xfrm_user_sec_ctx *, sec_ctx);
FUNC2INT(lsm_acc, xfrm_policy_clone, struct xfrm_sec_ctx *, old_ctx, struct xfrm_sec_ctx **, new_ctxp);
FUNC1VOID(lsm_acc, xfrm_policy_free, struct xfrm_sec_ctx *, ctx);
FUNC1INT(lsm_acc, xfrm_policy_delete, struct xfrm_sec_ctx *, ctx);
FUNC2INT(lsm_acc, xfrm_state_alloc, struct xfrm_state *, x, struct xfrm_user_sec_ctx *, sec_ctx);
FUNC3INT(lsm_acc, xfrm_state_alloc_acquire, struct xfrm_state *, x, struct xfrm_sec_ctx *, polsec, u32, secid);
FUNC1INT(lsm_acc, xfrm_state_delete, struct xfrm_state *, x);
FUNC1VOID(lsm_acc, xfrm_state_free, struct xfrm_state *, x);
FUNC3INT(lsm_acc, xfrm_policy_lookup, struct xfrm_sec_ctx *, ctx, u32, fl_secid, u8, dir);
FUNC3INT(lsm_acc, xfrm_state_pol_flow_match, struct xfrm_state *, x, struct xfrm_policy *, xp, struct flowi *, fl);
FUNC2INT(lsm_acc, xfrm_decode_session, struct sk_buff *, skb, u32 *, secid);
FUNC2VOID(lsm_acc, skb_classify_flow, struct sk_buff *, skb, struct flowi *, fl);
FUNC3INT(lsm_acc, key_alloc, struct key *, key, const struct cred *, cred, unsigned long, flags);
FUNC1VOID(lsm_acc, key_free, struct key *, key);
FUNC3INT(lsm_acc, key_permission, key_ref_t, key_ref, const struct cred *, cred, key_perm_t, perm);
FUNC2INT(lsm_acc, key_getsecurity, struct key *, key, char **, _buffer);
FUNC4INT(lsm_acc, audit_rule_init, u32, field, u32, op, char *, rulestr, void **, lsmrule);
FUNC1INT(lsm_acc, audit_rule_known, struct audit_krule *, krule);
FUNC1VOID(lsm_acc, audit_rule_free, void *, lsmrule);
FUNC5INT(lsm_acc, audit_rule_match, u32, secid, u32, field, u32, op, void *, lsmrule, struct audit_context *, actx);
