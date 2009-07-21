	.name =				"smack",

	.ptrace_may_access =		smack_ptrace_may_access,
	.ptrace_traceme =		smack_ptrace_traceme,
	.capget = 			cap_capget,
	.capset = 			cap_capset,
	.capable = 			cap_capable,
	.syslog = 			smack_syslog,
	.settime = 			cap_settime,
	.vm_enough_memory = 		cap_vm_enough_memory,

	.bprm_set_creds = 		cap_bprm_set_creds,
	.bprm_secureexec = 		cap_bprm_secureexec,

	.sb_alloc_security = 		smack_sb_alloc_security,
	.sb_free_security = 		smack_sb_free_security,
	.sb_copy_data = 		smack_sb_copy_data,
	.sb_kern_mount = 		smack_sb_kern_mount,
	.sb_statfs = 			smack_sb_statfs,
	.sb_mount = 			smack_sb_mount,
	.sb_umount = 			smack_sb_umount,

	.inode_alloc_security = 	smack_inode_alloc_security,
	.inode_free_security = 		smack_inode_free_security,
	.inode_init_security = 		smack_inode_init_security,
	.inode_link = 			smack_inode_link,
	.inode_unlink = 		smack_inode_unlink,
	.inode_rmdir = 			smack_inode_rmdir,
	.inode_rename = 		smack_inode_rename,
	.inode_permission = 		smack_inode_permission,
	.inode_setattr = 		smack_inode_setattr,
	.inode_getattr = 		smack_inode_getattr,
	.inode_setxattr = 		smack_inode_setxattr,
	.inode_post_setxattr = 		smack_inode_post_setxattr,
	.inode_getxattr = 		smack_inode_getxattr,
	.inode_removexattr = 		smack_inode_removexattr,
	.inode_need_killpriv =		cap_inode_need_killpriv,
	.inode_killpriv =		cap_inode_killpriv,
	.inode_getsecurity = 		smack_inode_getsecurity,
	.inode_setsecurity = 		smack_inode_setsecurity,
	.inode_listsecurity = 		smack_inode_listsecurity,
	.inode_getsecid =		smack_inode_getsecid,

	.file_permission = 		smack_file_permission,
	.file_alloc_security = 		smack_file_alloc_security,
	.file_free_security = 		smack_file_free_security,
	.file_ioctl = 			smack_file_ioctl,
	.file_lock = 			smack_file_lock,
	.file_fcntl = 			smack_file_fcntl,
	.file_set_fowner = 		smack_file_set_fowner,
	.file_send_sigiotask = 		smack_file_send_sigiotask,
	.file_receive = 		smack_file_receive,

	.cred_free =			smack_cred_free,
	.cred_prepare =			smack_cred_prepare,
	.cred_commit =			smack_cred_commit,
	.kernel_act_as =		smack_kernel_act_as,
	.kernel_create_files_as =	smack_kernel_create_files_as,
	.task_fix_setuid =		cap_task_fix_setuid,
	.task_setpgid = 		smack_task_setpgid,
	.task_getpgid = 		smack_task_getpgid,
	.task_getsid = 			smack_task_getsid,
	.task_getsecid = 		smack_task_getsecid,
	.task_setnice = 		smack_task_setnice,
	.task_setioprio = 		smack_task_setioprio,
	.task_getioprio = 		smack_task_getioprio,
	.task_setscheduler = 		smack_task_setscheduler,
	.task_getscheduler = 		smack_task_getscheduler,
	.task_movememory = 		smack_task_movememory,
	.task_kill = 			smack_task_kill,
	.task_wait = 			smack_task_wait,
	.task_to_inode = 		smack_task_to_inode,
	.task_prctl =			cap_task_prctl,

	.ipc_permission = 		smack_ipc_permission,
	.ipc_getsecid =			smack_ipc_getsecid,

	.msg_msg_alloc_security = 	smack_msg_msg_alloc_security,
	.msg_msg_free_security = 	smack_msg_msg_free_security,

	.msg_queue_alloc_security = 	smack_msg_queue_alloc_security,
	.msg_queue_free_security = 	smack_msg_queue_free_security,
	.msg_queue_associate = 		smack_msg_queue_associate,
	.msg_queue_msgctl = 		smack_msg_queue_msgctl,
	.msg_queue_msgsnd = 		smack_msg_queue_msgsnd,
	.msg_queue_msgrcv = 		smack_msg_queue_msgrcv,

	.shm_alloc_security = 		smack_shm_alloc_security,
	.shm_free_security = 		smack_shm_free_security,
	.shm_associate = 		smack_shm_associate,
	.shm_shmctl = 			smack_shm_shmctl,
	.shm_shmat = 			smack_shm_shmat,

	.sem_alloc_security = 		smack_sem_alloc_security,
	.sem_free_security = 		smack_sem_free_security,
	.sem_associate = 		smack_sem_associate,
	.sem_semctl = 			smack_sem_semctl,
	.sem_semop = 			smack_sem_semop,

	.netlink_send =			cap_netlink_send,
	.netlink_recv = 		cap_netlink_recv,

	.d_instantiate = 		smack_d_instantiate,

	.getprocattr = 			smack_getprocattr,
	.setprocattr = 			smack_setprocattr,

	.unix_stream_connect = 		smack_unix_stream_connect,
	.unix_may_send = 		smack_unix_may_send,

	.socket_post_create = 		smack_socket_post_create,
	.socket_connect =		smack_socket_connect,
	.socket_sendmsg =		smack_socket_sendmsg,
	.socket_sock_rcv_skb = 		smack_socket_sock_rcv_skb,
	.socket_getpeersec_stream =	smack_socket_getpeersec_stream,
	.socket_getpeersec_dgram =	smack_socket_getpeersec_dgram,
	.sk_alloc_security = 		smack_sk_alloc_security,
	.sk_free_security = 		smack_sk_free_security,
	.sock_graft = 			smack_sock_graft,
	.inet_conn_request = 		smack_inet_conn_request,
	.inet_csk_clone =		smack_inet_csk_clone,

 /* key management security hooks */
#ifdef CONFIG_KEYS
	.key_alloc = 			smack_key_alloc,
	.key_free = 			smack_key_free,
	.key_permission = 		smack_key_permission,
#endif /* CONFIG_KEYS */

 /* Audit hooks */
#ifdef CONFIG_AUDIT
	.audit_rule_init =		smack_audit_rule_init,
	.audit_rule_known =		smack_audit_rule_known,
	.audit_rule_match =		smack_audit_rule_match,
	.audit_rule_free =		smack_audit_rule_free,
#endif /* CONFIG_AUDIT */

	.secid_to_secctx = 		smack_secid_to_secctx,
	.secctx_to_secid = 		smack_secctx_to_secid,
	.release_secctx = 		smack_release_secctx,
