char *sc_security_str[] = {
"ptrace_may_access",
"ptrace_traceme",
"capget",
"capset",
"capable",
"acct",
"sysctl",
"quotactl",
"quota_on",
"syslog",
"settime",
"vm_enough_memory",
"bprm_set_creds",
"bprm_check_security",
"bprm_secureexec",
"bprm_committing_creds",
"bprm_committed_creds",
"sb_alloc_security",
"sb_free_security",
"sb_copy_data",
"sb_kern_mount",
"sb_show_options",
"sb_statfs",
"sb_mount",
"sb_check_sb",
"sb_umount",
"sb_umount_close",
"sb_umount_busy",
"sb_post_remount",
"sb_post_addmount",
"sb_pivotroot",
"sb_post_pivotroot",
"sb_set_mnt_opts",
"sb_clone_mnt_opts",
"sb_parse_opts_str",
"path_unlink",
"path_mkdir",
"path_rmdir",
"path_mknod",
"path_truncate",
"path_symlink",
"path_link",
"path_rename",
"inode_alloc_security",
"inode_free_security",
"inode_init_security",
"inode_create",
"inode_link",
"inode_unlink",
"inode_symlink",
"inode_mkdir",
"inode_rmdir",
"inode_mknod",
"inode_rename",
"inode_readlink",
"inode_follow_link",
"inode_permission",
"inode_setattr",
"inode_getattr",
"inode_delete",
"inode_setxattr",
"inode_post_setxattr",
"inode_getxattr",
"inode_listxattr",
"inode_removexattr",
"inode_need_killpriv",
"inode_killpriv",
"inode_getsecurity",
"inode_setsecurity",
"inode_listsecurity",
"inode_getsecid",
"file_permission",
"file_alloc_security",
"file_free_security",
"file_ioctl",
"file_mmap",
"file_mprotect",
"file_lock",
"file_fcntl",
"file_set_fowner",
"file_send_sigiotask",
"file_receive",
"dentry_open",
"task_create",
"cred_free",
"cred_prepare",
"cred_commit",
"kernel_act_as",
"kernel_create_files_as",
"task_setuid",
"task_fix_setuid",
"task_setgid",
"task_setpgid",
"task_getpgid",
"task_getsid",
"task_getsecid",
"task_setgroups",
"task_setnice",
"task_setioprio",
"task_getioprio",
"task_setrlimit",
"task_setscheduler",
"task_getscheduler",
"task_movememory",
"task_kill",
"task_wait",
"task_prctl",
"task_to_inode",
"ipc_permission",
"ipc_getsecid",
"msg_msg_alloc_security",
"msg_msg_free_security",
"msg_queue_alloc_security",
"msg_queue_free_security",
"msg_queue_associate",
"msg_queue_msgctl",
"msg_queue_msgsnd",
"msg_queue_msgrcv",
"shm_alloc_security",
"shm_free_security",
"shm_associate",
"shm_shmctl",
"shm_shmat",
"sem_alloc_security",
"sem_free_security",
"sem_associate",
"sem_semctl",
"sem_semop",
"netlink_send",
"netlink_recv",
"d_instantiate",
"getprocattr",
"setprocattr",
"secid_to_secctx",
"secctx_to_secid",
"release_secctx",
"unix_stream_connect",
"unix_may_send",
"socket_create",
"socket_post_create",
"socket_bind",
"socket_connect",
"socket_listen",
"socket_accept",
"socket_sendmsg",
"socket_recvmsg",
"socket_getsockname",
"socket_getpeername",
"socket_getsockopt",
"socket_setsockopt",
"socket_shutdown",
"socket_sock_rcv_skb",
"socket_getpeersec_stream",
"socket_getpeersec_dgram",
"sk_alloc_security",
"sk_free_security",
"sk_clone_security",
"sk_getsecid",
"sock_graft",
"inet_conn_request",
"inet_csk_clone",
"inet_conn_established",
"req_classify_flow",
"xfrm_policy_alloc_security",
"xfrm_policy_clone_security",
"xfrm_policy_free_security",
"xfrm_policy_delete_security",
"xfrm_state_alloc_security",
"xfrm_state_free_security",
"xfrm_state_delete_security",
"xfrm_policy_lookup",
"xfrm_state_pol_flow_match",
"xfrm_decode_session",
"key_alloc",
"key_free",
"key_permission",
"key_getsecurity",
"audit_rule_init",
"audit_rule_known",
"audit_rule_match",
"audit_rule_free",
0
};
