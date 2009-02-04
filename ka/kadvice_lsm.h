#ifndef CONFIG_SECURITY_NETWORK
#define CONFIG_SECURITY_NETWORK
#endif

#ifndef CONFIG_SECURITY_NETWORK_XFRM
#define CONFIG_SECURITY_NETWORK_XFRM
#endif

#ifndef CONFIG_KEYS
#define CONFIG_KEYS
#endif

#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/security.h>
#include <linux/key.h>
#include <cabi/common.h>

extern int ka_check_ptrace(struct task_struct *, struct task_struct *);
extern int ka_check_capget(struct task_struct *, kernel_cap_t *, kernel_cap_t *, kernel_cap_t *);
extern int ka_check_capset_check(struct task_struct *, kernel_cap_t *, kernel_cap_t *, kernel_cap_t *);
extern void ka_check_capset_set(struct task_struct *, kernel_cap_t *, kernel_cap_t *, kernel_cap_t *);
extern int ka_check_capable(struct task_struct *, int);
extern int ka_check_acct(struct file *);
extern int ka_check_sysctl(struct ctl_table *, int);
extern int ka_check_quotactl(int, int, int, struct super_block *);
extern int ka_check_quota_on(struct dentry *);
extern int ka_check_syslog(int);
extern int ka_check_settime(struct timespec *, struct timezone *);
extern int ka_check_vm_enough_memory(struct mm_struct *, long);
extern int ka_check_bprm_alloc_security(struct linux_binprm *);
extern void ka_check_bprm_free_security(struct linux_binprm *);
extern void ka_check_bprm_apply_creds(struct linux_binprm *, int);
extern void ka_check_bprm_post_apply_creds(struct linux_binprm *);
extern int ka_check_bprm_set_security(struct linux_binprm *);
extern int ka_check_bprm_check_security(struct linux_binprm *);
extern int ka_check_bprm_secureexec(struct linux_binprm *);
extern int ka_check_sb_alloc_security(struct super_block *);
extern void ka_check_sb_free_security(struct super_block *);
extern int ka_check_sb_copy_data(struct file_system_type *, void *, void *);
extern int ka_check_sb_kern_mount(struct super_block *, void *);
extern int ka_check_sb_statfs(struct dentry *);
extern int ka_check_sb_mount(char *, struct nameidata *, char *, unsigned long, void *);
extern int ka_check_sb_check_sb(struct vfsmount *, struct nameidata *);
extern int ka_check_sb_umount(struct vfsmount *, int);
extern void ka_check_sb_umount_close(struct vfsmount *);
extern void ka_check_sb_umount_busy(struct vfsmount *);
extern void ka_check_sb_post_remount(struct vfsmount *, unsigned long, void *);
extern void ka_check_sb_post_mountroot(void);
extern void ka_check_sb_post_addmount(struct vfsmount *, struct nameidata *);
extern int ka_check_sb_pivotroot(struct nameidata *, struct nameidata *);
extern void ka_check_sb_post_pivotroot(struct nameidata *, struct nameidata *);
extern int ka_check_inode_alloc_security(struct inode *);
extern void ka_check_inode_free_security(struct inode *);
extern int ka_check_inode_init_security(struct inode *, struct inode *, char **, void **, size_t *);
extern int ka_check_inode_create(struct inode *, struct dentry *, int);
extern int ka_check_inode_link(struct dentry *, struct inode *, struct dentry *);
extern int ka_check_inode_unlink(struct inode *, struct dentry *);
extern int ka_check_inode_symlink(struct inode *, struct dentry *, const char *);
extern int ka_check_inode_mkdir(struct inode *, struct dentry *, int);
extern int ka_check_inode_rmdir(struct inode *, struct dentry *);
extern int ka_check_inode_mknod(struct inode *, struct dentry *, int, dev_t);
extern int ka_check_inode_rename(struct inode *, struct dentry *, struct inode *, struct dentry *);
extern int ka_check_inode_readlink(struct dentry *);
extern int ka_check_inode_follow_link(struct dentry *, struct nameidata *);
extern int ka_check_inode_permission(struct inode *, int, struct nameidata *);
extern int ka_check_inode_setattr(struct dentry *, struct iattr *);
extern int ka_check_inode_getattr(struct vfsmount *, struct dentry *);
extern void ka_check_inode_delete(struct inode *);
extern int ka_check_inode_setxattr(struct dentry *, char *, void *, size_t, int);
extern void ka_check_inode_post_setxattr(struct dentry *, char *, void *, size_t, int);
extern int ka_check_inode_getxattr(struct dentry *, char *);
extern int ka_check_inode_listxattr(struct dentry *);
extern int ka_check_inode_removexattr(struct dentry *, char *);
extern int ka_check_inode_need_killpriv(struct dentry *);
extern int ka_check_inode_killpriv(struct dentry *);
extern int ka_check_inode_getsecurity(const struct inode *, const char *, void *, size_t, int);
extern int ka_check_inode_setsecurity(struct inode *, const char *, const void *, size_t, int);
extern int ka_check_inode_listsecurity(struct inode *, char *, size_t);
extern int ka_check_file_permission(struct file *, int);
extern int ka_check_file_alloc_security(struct file *);
extern void ka_check_file_free_security(struct file *);
extern int ka_check_file_ioctl(struct file *, unsigned int, unsigned long);
extern int ka_check_file_mmap(struct file *, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long);
extern int ka_check_file_mprotect(struct vm_area_struct *, unsigned long, unsigned long);
extern int ka_check_file_lock(struct file *, unsigned int);
extern int ka_check_file_fcntl(struct file *, unsigned int, unsigned long);
extern int ka_check_file_set_fowner(struct file *);
extern int ka_check_file_send_sigiotask(struct task_struct *, struct fown_struct *, int);
extern int ka_check_file_receive(struct file *);
extern int ka_check_dentry_open(struct file *);
extern int ka_check_task_create(unsigned long);
extern int ka_check_task_alloc_security(struct task_struct *);
extern void ka_check_task_free_security(struct task_struct *);
extern int ka_check_task_setuid(uid_t, uid_t, uid_t, int);
extern int ka_check_task_post_setuid(uid_t, uid_t, uid_t, int);
extern int ka_check_task_setgid(gid_t, gid_t, gid_t, int);
extern int ka_check_task_setpgid(struct task_struct *, pid_t);
extern int ka_check_task_getpgid(struct task_struct *);
extern int ka_check_task_getsid(struct task_struct *);
extern void ka_check_task_getsecid(struct task_struct *, u32 *);
extern int ka_check_task_setgroups(struct group_info *);
extern int ka_check_task_setnice(struct task_struct *, int);
extern int ka_check_task_setioprio(struct task_struct *, int);
extern int ka_check_task_getioprio(struct task_struct *);
extern int ka_check_task_setrlimit(unsigned int, struct rlimit *);
extern int ka_check_task_setscheduler(struct task_struct *, int, struct sched_param *);
extern int ka_check_task_getscheduler(struct task_struct *);
extern int ka_check_task_movememory(struct task_struct *);
extern int ka_check_task_kill(struct task_struct *, struct siginfo *, int, u32);
extern int ka_check_task_wait(struct task_struct *);
extern int ka_check_task_prctl(int, unsigned long, unsigned long, unsigned long, unsigned long);
extern void ka_check_task_reparent_to_init(struct task_struct *);
extern void ka_check_task_to_inode(struct task_struct *, struct inode *);
extern int ka_check_ipc_permission(struct kern_ipc_perm *, short);
extern int ka_check_msg_msg_alloc_security(struct msg_msg *);
extern void ka_check_msg_msg_free_security(struct msg_msg *);
extern int ka_check_msg_queue_alloc_security(struct msg_queue *);
extern void ka_check_msg_queue_free_security(struct msg_queue *);
extern int ka_check_msg_queue_associate(struct msg_queue *, int);
extern int ka_check_msg_queue_msgctl(struct msg_queue *, int);
extern int ka_check_msg_queue_msgsnd(struct msg_queue *, struct msg_msg *, int);
extern int ka_check_msg_queue_msgrcv(struct msg_queue *, struct msg_msg *, struct task_struct *, long, int);
extern int ka_check_shm_alloc_security(struct shmid_kernel *);
extern void ka_check_shm_free_security(struct shmid_kernel *);
extern int ka_check_shm_associate(struct shmid_kernel *, int);
extern int ka_check_shm_shmctl(struct shmid_kernel *, int);
extern int ka_check_shm_shmat(struct shmid_kernel *, char __user *, int);
extern int ka_check_sem_alloc_security(struct sem_array *);
extern void ka_check_sem_free_security(struct sem_array *);
extern int ka_check_sem_associate(struct sem_array *, int);
extern int ka_check_sem_semctl(struct sem_array *, int);
extern int ka_check_sem_semop(struct sem_array *, struct sembuf *, unsigned, int);
extern int ka_check_netlink_send(struct sock *, struct sk_buff *);
extern int ka_check_netlink_recv(struct sk_buff *, int);
extern int ka_check_register_security(const char *, struct security_operations *);
extern void ka_check_d_instantiate(struct dentry *, struct inode *);
extern int ka_check_getprocattr(struct task_struct *, char *, char **);
extern int ka_check_setprocattr(struct task_struct *, char *, void *, size_t);
extern int ka_check_secid_to_secctx(u32, char **, u32 *);
extern void ka_check_release_secctx(char *, u32);
extern int ka_check_unix_stream_connect(struct socket *, struct socket *, struct sock *);
extern int ka_check_unix_may_send(struct socket *, struct socket *);
extern int ka_check_socket_create(int, int, int, int);
extern int ka_check_socket_post_create(struct socket *, int, int, int, int);
extern int ka_check_socket_bind(struct socket *, struct sockaddr *, int);
extern int ka_check_socket_connect(struct socket *, struct sockaddr *, int);
extern int ka_check_socket_listen(struct socket *, int);
extern int ka_check_socket_accept(struct socket *, struct socket *);
extern void ka_check_socket_post_accept(struct socket *, struct socket *);
extern int ka_check_socket_sendmsg(struct socket *, struct msghdr *, int);
extern int ka_check_socket_recvmsg(struct socket *, struct msghdr *, int, int);
extern int ka_check_socket_getsockname(struct socket *);
extern int ka_check_socket_getpeername(struct socket *);
extern int ka_check_socket_getsockopt(struct socket *, int, int);
extern int ka_check_socket_setsockopt(struct socket *, int, int);
extern int ka_check_socket_shutdown(struct socket *, int);
extern int ka_check_socket_sock_rcv_skb(struct sock *, struct sk_buff *);
extern int ka_check_socket_getpeersec_stream(struct socket *, char __user *, int __user *, unsigned);
extern int ka_check_socket_getpeersec_dgram(struct socket *, struct sk_buff *, u32 *);
extern int ka_check_sk_alloc_security(struct sock *, int, gfp_t);
extern void ka_check_sk_free_security(struct sock *);
extern void ka_check_sk_clone_security(const struct sock *, struct sock *);
extern void ka_check_sk_getsecid(struct sock *, u32 *);
extern void ka_check_sock_graft(struct sock*, struct socket *);
extern int ka_check_inet_conn_request(struct sock *, struct sk_buff *, struct request_sock *);
extern void ka_check_inet_csk_clone(struct sock *, const struct request_sock *);
extern void ka_check_inet_conn_established(struct sock *, struct sk_buff *);
extern void ka_check_req_classify_flow(const struct request_sock *, struct flowi *);
extern int ka_check_xfrm_policy_alloc_security(struct xfrm_policy *, struct xfrm_user_sec_ctx *);
extern int ka_check_xfrm_policy_clone_security(struct xfrm_policy *, struct xfrm_policy *);
extern void ka_check_xfrm_policy_free_security(struct xfrm_policy *);
extern int ka_check_xfrm_policy_delete_security(struct xfrm_policy *);
extern int ka_check_xfrm_state_alloc_security(struct xfrm_state *, struct xfrm_user_sec_ctx *, u32);
extern void ka_check_xfrm_state_free_security(struct xfrm_state *);
extern int ka_check_xfrm_state_delete_security(struct xfrm_state *);
extern int ka_check_xfrm_policy_lookup(struct xfrm_policy *, u32, u8);
extern int ka_check_xfrm_state_pol_flow_match(struct xfrm_state *, struct xfrm_policy *, struct flowi *);
extern int ka_check_xfrm_decode_session(struct sk_buff *, u32 *, int);
extern int ka_check_key_alloc(struct key *, struct task_struct *, unsigned long);
extern void ka_check_key_free(struct key *);
//extern int ka_check_key_permission(key_ref_t, struct task_struct *, key_perm_t);

