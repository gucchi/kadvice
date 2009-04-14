#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include "ka/secops.h"

#include <linux/security.h>
#include "ka/kadvice_lsm.h"
#include "ka/resources.h"

extern void securitycube_fork(struct task_struct *);

MODULE_LICENSE("GPL");

static int lsm_ptrace(struct task_struct * parent, struct task_struct * child){
	return ka_check_ptrace(parent, child);
}
static int lsm_capget(struct task_struct * target, kernel_cap_t * effective, kernel_cap_t * inheritable, kernel_cap_t * permitted){
	return ka_check_capget(target, effective, inheritable, permitted);
}
static int lsm_capset_check(struct task_struct * target, kernel_cap_t * effective, kernel_cap_t * inheritable, kernel_cap_t * permitted){
	return ka_check_capset_check(target, effective, inheritable, permitted);
}
static void lsm_capset_set(struct task_struct * target, kernel_cap_t * effective, kernel_cap_t * inheritable, kernel_cap_t * permitted){
	return ka_check_capset_set(target, effective, inheritable, permitted);
}

static int lsm_capable(struct task_struct * tsk, int cap){
	return ka_check_capable(tsk, cap);
}
static int lsm_acct(struct file * file){
	return ka_check_acct(file);
}
static int lsm_sysctl(struct ctl_table * table, int op){
	return ka_check_sysctl(table, op);
}
static int lsm_quotactl(int cmds, int type, int id, struct super_block * sb){
	return ka_check_quotactl(cmds, type, id, sb);
}
static int lsm_quota_on(struct dentry * dentry){
	return ka_check_quota_on(dentry);
}
static int lsm_syslog(int type){
	return ka_check_syslog(type);
}
static int lsm_settime(struct timespec * ts, struct timezone * tz){
	return ka_check_settime(ts, tz);
}
static int lsm_vm_enough_memory(struct mm_struct * mm, long pages){
	return ka_check_vm_enough_memory(mm, pages);
}
static int lsm_bprm_alloc_security(struct linux_binprm * bprm){
	return ka_check_bprm_alloc_security(bprm);
}
static void lsm_bprm_free_security(struct linux_binprm * bprm){
	return ka_check_bprm_free_security(bprm);
}
static void lsm_bprm_apply_creds(struct linux_binprm * bprm, int unsafe){
	return ka_check_bprm_apply_creds(bprm, unsafe);
}
static void lsm_bprm_post_apply_creds(struct linux_binprm * bprm){
	return ka_check_bprm_post_apply_creds(bprm);
}
static int lsm_bprm_set_security(struct linux_binprm * bprm){
	return ka_check_bprm_set_security(bprm);
}
static int lsm_bprm_check_security(struct linux_binprm * bprm){
	return ka_check_bprm_check_security(bprm);
}
static int lsm_bprm_secureexec(struct linux_binprm * bprm){
	return ka_check_bprm_secureexec(bprm);
}
static int lsm_sb_alloc_security(struct super_block * sb){
	return ka_check_sb_alloc_security(sb);
}
static void lsm_sb_free_security(struct super_block * sb){
	return ka_check_sb_free_security(sb);
}
static int lsm_sb_copy_data(struct file_system_type * type, void * orig, void * copy){
	return ka_check_sb_copy_data(type, orig, copy);
}
static int lsm_sb_kern_mount(struct super_block * sb, void * data){
	return ka_check_sb_kern_mount(sb, data);
}
static int lsm_sb_statfs(struct dentry * dentry){
	return ka_check_sb_statfs(dentry);
}
static int lsm_sb_mount(char * dev_name, struct nameidata * nd, char * type, unsigned long flags, void * data){
	return ka_check_sb_mount(dev_name, nd, type, flags, data);
}
static int lsm_sb_check_sb(struct vfsmount * mnt, struct nameidata * nd){
	return ka_check_sb_check_sb(mnt, nd);
}
static int lsm_sb_umount(struct vfsmount * mnt, int flags){
	return ka_check_sb_umount(mnt, flags);
}
static void lsm_sb_umount_close(struct vfsmount * mnt){
	return ka_check_sb_umount_close(mnt);
}
static void lsm_sb_umount_busy(struct vfsmount * mnt){
	return ka_check_sb_umount_busy(mnt);
}
static void lsm_sb_post_remount(struct vfsmount * mnt, unsigned long flags, void * data){
	return ka_check_sb_post_remount(mnt, flags, data);
}
static void lsm_sb_post_mountroot(void){
	return ka_check_sb_post_mountroot();
}
static void lsm_sb_post_addmount(struct vfsmount * mnt, struct nameidata * mountpoint_nd){
	return ka_check_sb_post_addmount(mnt, mountpoint_nd);
}
static int lsm_sb_pivotroot(struct nameidata * old_nd, struct nameidata * new_nd){
	return ka_check_sb_pivotroot(old_nd, new_nd);
}
static void lsm_sb_post_pivotroot(struct nameidata * old_nd, struct nameidata * new_nd){
	return ka_check_sb_post_pivotroot(old_nd, new_nd);
}
static int lsm_inode_alloc_security(struct inode * inode){
  /*  int ret = 0;
  struct sc_inode_security *isec = NULL;
  int i;
  if (inode->i_security == NULL) {
    isec = (struct sc_inode_security *)
      kmalloc(sizeof(struct sc_inode_security), GFP_KERNEL);
    // no need to init label
    for (i = 0; i < MODEL_MAX; i++)
      isec->label[i] = NULL;
  } else {
    isec = inode->i_security;
  }
  inode->i_security = isec->label[isec->gid];
  
  ret = ka_check_inode_alloc_security(inode);
  inode->i_security = isec;
  return ret;
  */
  return ka_check_inode_alloc_security(inode);
}
static void lsm_inode_free_security(struct inode * inode){
  /*  struct sc_inode_security *isec;

  isec = inode->i_security;
  if (isec != NULL) {
    kfree(isec);
  }
  */
  return ka_check_inode_free_security(inode);
}
static int lsm_inode_init_security(struct inode * inode, struct inode * dir, char ** name, void ** value, size_t * len){
	return ka_check_inode_init_security(inode, dir, name, value, len);
}

static int lsm_inode_create(struct inode * dir, struct dentry * dentry, int mode){
  /*
  int ret;
  // pointer should always init with NULL!!!!!;
  struct sc_inode_security *isec = NULL;

  if (dir->i_security != NULL) {
    isec = dir->i_security;
    dir->i_security = isec->label[isec->gid];

  }
  ret = ka_check_inode_create(dir, dentry, mode);
  dir->i_security = isec;

  return  ret;
  */
  return ka_check_inode_create(dir, dentry, mode);
}
static int lsm_inode_link(struct dentry * old_dentry, struct inode * dir, struct dentry * new_dentry){
  /*  int ret;
  // pointer should always init with NULL!!!!!;
  struct sc_inode_security *isec = NULL;

  if (dir->i_security != NULL) {
    isec = dir->i_security;
    dir->i_security = isec->label[isec->gid];

  }
  ret = ka_check_inode_link(old_dentry, dir, new_dentry);
  dir->i_security = isec;
  
  return  ret;
  */
  return ka_check_inode_link(old_dentry, dir, new_dentry);

}
static int lsm_inode_unlink(struct inode * dir, struct dentry * dentry){
	return ka_check_inode_unlink(dir, dentry);
}
static int lsm_inode_symlink(struct inode * dir, struct dentry * dentry, const char * old_name){
	return ka_check_inode_symlink(dir, dentry, old_name);
}
static int lsm_inode_mkdir(struct inode * dir, struct dentry * dentry, int mode){
	return ka_check_inode_mkdir(dir, dentry, mode);
}
static int lsm_inode_rmdir(struct inode * dir, struct dentry * dentry){
	return ka_check_inode_rmdir(dir, dentry);
}
static int lsm_inode_mknod(struct inode * dir, struct dentry * dentry, int mode, dev_t dev){
	return ka_check_inode_mknod(dir, dentry, mode, dev);
}
static int lsm_inode_rename(struct inode * old_dir, struct dentry * old_dentry, struct inode * new_dir, struct dentry * new_dentry){
  /*  int ret;
  // pointer should always init with NULL!!!!!;
  struct sc_inode_security *isec = NULL;

  if (old_dir->i_security != NULL) {
    isec = old_dir->i_security;
    old_dir->i_security = isec->label[isec->gid];

  }
  ret = ka_check_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
  old_dir->i_security = isec;
  
  return  ret;
  */
  return ka_check_inode_rename(old_dir, old_dentry, new_dir, new_dentry);
}
static int lsm_inode_readlink(struct dentry * dentry){
	return ka_check_inode_readlink(dentry);
}
static int lsm_inode_follow_link(struct dentry * dentry, struct nameidata * nd){
	return ka_check_inode_follow_link(dentry, nd);
}
static int lsm_inode_permission(struct inode * inode, int mask, struct nameidata * nd){
  /*
  int ret;
  // pointer should always init with NULL!!!!!;
  struct sc_inode_security *isec = NULL;

  if (inode->i_security != NULL) {
    isec = inode->i_security;
    inode->i_security = isec->label[isec->gid];

  }
  ret = ka_check_inode_permission(inode, mask, nd);
  inode->i_security = isec;
  
  return  ret;
  */
  return ka_check_inode_permission(inode, mask, nd);
}

static int lsm_inode_setattr(struct dentry * dentry, struct iattr * attr){
	return ka_check_inode_setattr(dentry, attr);
}
static int lsm_inode_getattr(struct vfsmount * mnt, struct dentry * dentry){
	return ka_check_inode_getattr(mnt, dentry);
}
static void lsm_inode_delete(struct inode * inode){
	return ka_check_inode_delete(inode);
}
static int lsm_inode_setxattr(struct dentry * dentry, char * name, void * value, size_t size, int flags){
	return ka_check_inode_setxattr(dentry, name, value, size, flags);
}
static void lsm_inode_post_setxattr(struct dentry * dentry, char * name, void * value, size_t size, int flags){
	return ka_check_inode_post_setxattr(dentry, name, value, size, flags);
}
static int lsm_inode_getxattr(struct dentry * dentry, char * name){
	return ka_check_inode_getxattr(dentry, name);
}
static int lsm_inode_listxattr(struct dentry * dentry){
	return ka_check_inode_listxattr(dentry);
}
static int lsm_inode_removexattr(struct dentry * dentry, char * name){
	return ka_check_inode_removexattr(dentry, name);
}
static int lsm_inode_need_killpriv(struct dentry * dentry){
	return ka_check_inode_need_killpriv(dentry);
}
static int lsm_inode_killpriv(struct dentry * dentry){
	return ka_check_inode_killpriv(dentry);
}
static int lsm_inode_getsecurity(const struct inode * inode, const char * name, void * buffer, size_t size, int err){
	return ka_check_inode_getsecurity(inode, name, buffer, size, err);
}
static int lsm_inode_setsecurity(struct inode * inode, const char * name, const void * value, size_t size, int flags){
	return ka_check_inode_setsecurity(inode, name, value, size, flags);
}
static int lsm_inode_listsecurity(struct inode * inode, char * buffer, size_t buffer_size){
	return ka_check_inode_listsecurity(inode, buffer, buffer_size);
}
static int lsm_file_permission(struct file * file, int mask){
	return ka_check_file_permission(file, mask);
}
static int lsm_file_alloc_security(struct file * file){
  
  return ka_check_file_alloc_security(file);
}
static void lsm_file_free_security(struct file * file){
	return ka_check_file_free_security(file);
}
static int lsm_file_ioctl(struct file * file, unsigned int cmd, unsigned long arg){
	return ka_check_file_ioctl(file, cmd, arg);
}
static int lsm_file_mmap(struct file * file, unsigned long reqprot, unsigned long prot, unsigned long flags, unsigned long addr, unsigned long addr_only){
	return ka_check_file_mmap(file, reqprot, prot, flags, addr, addr_only);
}
static int lsm_file_mprotect(struct vm_area_struct * vma, unsigned long reqprot, unsigned long prot){
	return ka_check_file_mprotect(vma, reqprot, prot);
}
static int lsm_file_lock(struct file * file, unsigned int cmd){
	return ka_check_file_lock(file, cmd);
}
static int lsm_file_fcntl(struct file * file, unsigned int cmd, unsigned long arg){
	return ka_check_file_fcntl(file, cmd, arg);
}
static int lsm_file_set_fowner(struct file * file){
	return ka_check_file_set_fowner(file);
}
static int lsm_file_send_sigiotask(struct task_struct * tsk, struct fown_struct * fown, int sig){
	return ka_check_file_send_sigiotask(tsk, fown, sig);
}
static int lsm_file_receive(struct file * file){
	return ka_check_file_receive(file);
}
static int lsm_dentry_open(struct file * file){
	return ka_check_dentry_open(file);
}
static int lsm_task_create(unsigned long clone_flags){
	return ka_check_task_create(clone_flags);
}

static int lsm_task_alloc_security(struct task_struct * p){
  struct sc_task_security *isec = NULL;
  if (p->security == NULL) {
    securitycube_fork(p);
  }
  return ka_check_task_alloc_security(p);
}

static void lsm_task_free_security(struct task_struct * p){
	return ka_check_task_free_security(p);
}
static int lsm_task_setuid(uid_t id0, uid_t id1, uid_t id2, int flags){
	return ka_check_task_setuid(id0, id1, id2, flags);
}
static int lsm_task_post_setuid(uid_t old_ruid, uid_t old_euid, uid_t old_suid, int flags){
	return ka_check_task_post_setuid(old_ruid, old_euid, old_suid, flags);
}
static int lsm_task_setgid(gid_t id0, gid_t id1, gid_t id2, int flags){
	return ka_check_task_setgid(id0, id1, id2, flags);
}
static int lsm_task_setpgid(struct task_struct * p, pid_t pgid){
	return ka_check_task_setpgid(p, pgid);
}
static int lsm_task_getpgid(struct task_struct * p){
	return ka_check_task_getpgid(p);
}
static int lsm_task_getsid(struct task_struct * p){
	return ka_check_task_getsid(p);
}
static void lsm_task_getsecid(struct task_struct * p, u32 * secid){
	return ka_check_task_getsecid(p, secid);
}
static int lsm_task_setgroups(struct group_info * group_info){
	return ka_check_task_setgroups(group_info);
}
static int lsm_task_setnice(struct task_struct * p, int nice){
	return ka_check_task_setnice(p, nice);
}
static int lsm_task_setioprio(struct task_struct * p, int ioprio){
	return ka_check_task_setioprio(p, ioprio);
}
static int lsm_task_getioprio(struct task_struct * p){
	return ka_check_task_getioprio(p);
}
static int lsm_task_setrlimit(unsigned int resource, struct rlimit * new_rlim){
	return ka_check_task_setrlimit(resource, new_rlim);
}
static int lsm_task_setscheduler(struct task_struct * p, int policy, struct sched_param * lp){
	return ka_check_task_setscheduler(p, policy, lp);
}
static int lsm_task_getscheduler(struct task_struct * p){
	return ka_check_task_getscheduler(p);
}
static int lsm_task_movememory(struct task_struct * p){
	return ka_check_task_movememory(p);
}
static int lsm_task_kill(struct task_struct * p, struct siginfo * info, int sig, u32 secid){
	return ka_check_task_kill(p, info, sig, secid);
}
static int lsm_task_wait(struct task_struct * p){
	return ka_check_task_wait(p);
}
static int lsm_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5){
	return ka_check_task_prctl(option, arg2, arg3, arg4, arg5);
}
static void lsm_task_reparent_to_init(struct task_struct * p){
	return ka_check_task_reparent_to_init(p);
}
static void lsm_task_to_inode(struct task_struct * p, struct inode * inode){
	return ka_check_task_to_inode(p, inode);
}
static int lsm_ipc_permission(struct kern_ipc_perm * ipcp, short flag){
	return ka_check_ipc_permission(ipcp, flag);
}
static int lsm_msg_msg_alloc_security(struct msg_msg * msg){
	return ka_check_msg_msg_alloc_security(msg);
}
static void lsm_msg_msg_free_security(struct msg_msg * msg){
	return ka_check_msg_msg_free_security(msg);
}
static int lsm_msg_queue_alloc_security(struct msg_queue * msq){
	return ka_check_msg_queue_alloc_security(msq);
}
static void lsm_msg_queue_free_security(struct msg_queue * msq){
	return ka_check_msg_queue_free_security(msq);
}
static int lsm_msg_queue_associate(struct msg_queue * msq, int msqflg){
	return ka_check_msg_queue_associate(msq, msqflg);
}
static int lsm_msg_queue_msgctl(struct msg_queue * msq, int cmd){
	return ka_check_msg_queue_msgctl(msq, cmd);
}
static int lsm_msg_queue_msgsnd(struct msg_queue * msq, struct msg_msg * msg, int msqflg){
	return ka_check_msg_queue_msgsnd(msq, msg, msqflg);
}
static int lsm_msg_queue_msgrcv(struct msg_queue * msq, struct msg_msg * msg, struct task_struct * target, long type, int mode){
	return ka_check_msg_queue_msgrcv(msq, msg, target, type, mode);
}
static int lsm_shm_alloc_security(struct shmid_kernel * shp){
	return ka_check_shm_alloc_security(shp);
}
static void lsm_shm_free_security(struct shmid_kernel * shp){
	return ka_check_shm_free_security(shp);
}
static int lsm_shm_associate(struct shmid_kernel * shp, int shmflg){
	return ka_check_shm_associate(shp, shmflg);
}
static int lsm_shm_shmctl(struct shmid_kernel * shp, int cmd){
	return ka_check_shm_shmctl(shp, cmd);
}
static int lsm_shm_shmat(struct shmid_kernel * shp, char __user * shmaddr, int shmflg){
	return ka_check_shm_shmat(shp, shmaddr, shmflg);
}
static int lsm_sem_alloc_security(struct sem_array * sma){
	return ka_check_sem_alloc_security(sma);
}
static void lsm_sem_free_security(struct sem_array * sma){
	return ka_check_sem_free_security(sma);
}
static int lsm_sem_associate(struct sem_array * sma, int semflg){
	return ka_check_sem_associate(sma, semflg);
}
static int lsm_sem_semctl(struct sem_array * sma, int cmd){
	return ka_check_sem_semctl(sma, cmd);
}
static int lsm_sem_semop(struct sem_array * sma, struct sembuf * sops, unsigned nsops, int alter){
	return ka_check_sem_semop(sma, sops, nsops, alter);
}
static int lsm_netlink_send(struct sock * sk, struct sk_buff * skb){
	return ka_check_netlink_send(sk, skb);
}
static int lsm_netlink_recv(struct sk_buff * skb, int cap){
	return ka_check_netlink_recv(skb, cap);
}
static int lsm_register_security(const char * name, struct security_operations * ops){
	return ka_check_register_security(name, ops);
}
static void lsm_d_instantiate(struct dentry * dentry, struct inode * inode){
	return ka_check_d_instantiate(dentry, inode);
}
static int lsm_getprocattr(struct task_struct * p, char * name, char ** value){
	return ka_check_getprocattr(p, name, value);
}
static int lsm_setprocattr(struct task_struct * p, char * name, void * value, size_t size){
	return ka_check_setprocattr(p, name, value, size);
}
static int lsm_secid_to_secctx(u32 secid, char ** secdata, u32 * seclen){
	return ka_check_secid_to_secctx(secid, secdata, seclen);
}
static void lsm_release_secctx(char * secdata, u32 seclen){
	return ka_check_release_secctx(secdata, seclen);
}
static int lsm_unix_stream_connect(struct socket * sock, struct socket * other, struct sock * newsk){
	return ka_check_unix_stream_connect(sock, other, newsk);
}
static int lsm_unix_may_send(struct socket * sock, struct socket * other){
	return ka_check_unix_may_send(sock, other);
}
static int lsm_socket_create(int family, int type, int protocol, int kern){
	return ka_check_socket_create(family, type, protocol, kern);
}
static int lsm_socket_post_create(struct socket * sock, int family, int type, int protocol, int kern){
	return ka_check_socket_post_create(sock, family, type, protocol, kern);
}
static int lsm_socket_bind(struct socket * sock, struct sockaddr * address, int addrlen){
	return ka_check_socket_bind(sock, address, addrlen);
}
static int lsm_socket_connect(struct socket * sock, struct sockaddr * address, int addrlen){
	return ka_check_socket_connect(sock, address, addrlen);
}
static int lsm_socket_listen(struct socket * sock, int backlog){
	return ka_check_socket_listen(sock, backlog);
}
static int lsm_socket_accept(struct socket * sock, struct socket * newsock){
	return ka_check_socket_accept(sock, newsock);
}
static void lsm_socket_post_accept(struct socket * sock, struct socket * newsock){
	return ka_check_socket_post_accept(sock, newsock);
}
static int lsm_socket_sendmsg(struct socket * sock, struct msghdr * msg, int size){
	return ka_check_socket_sendmsg(sock, msg, size);
}
static int lsm_socket_recvmsg(struct socket * sock, struct msghdr * msg, int size, int flags){
	return ka_check_socket_recvmsg(sock, msg, size, flags);
}
static int lsm_socket_getsockname(struct socket * sock){
	return ka_check_socket_getsockname(sock);
}
static int lsm_socket_getpeername(struct socket * sock){
	return ka_check_socket_getpeername(sock);
}
static int lsm_socket_getsockopt(struct socket * sock, int level, int optname){
	return ka_check_socket_getsockopt(sock, level, optname);
}
static int lsm_socket_setsockopt(struct socket * sock, int level, int optname){
	return ka_check_socket_setsockopt(sock, level, optname);
}
static int lsm_socket_shutdown(struct socket * sock, int how){
	return ka_check_socket_shutdown(sock, how);
}
static int lsm_socket_sock_rcv_skb(struct sock * sk, struct sk_buff * skb){
	return ka_check_socket_sock_rcv_skb(sk, skb);
}
static int lsm_socket_getpeersec_stream(struct socket * sock, char __user * optval, int __user * optlen, unsigned len){
	return ka_check_socket_getpeersec_stream(sock, optval, optlen, len);
}
static int lsm_socket_getpeersec_dgram(struct socket * sock, struct sk_buff * skb, u32 * secid){
	return ka_check_socket_getpeersec_dgram(sock, skb, secid);
}
static int lsm_sk_alloc_security(struct sock * sk, int family, gfp_t priority){
	return ka_check_sk_alloc_security(sk, family, priority);
}
static void lsm_sk_free_security(struct sock * sk){
	return ka_check_sk_free_security(sk);
}
static void lsm_sk_clone_security(const struct sock * sk, struct sock * newsk){
	return ka_check_sk_clone_security(sk, newsk);
}
static void lsm_sk_getsecid(struct sock * sk, u32 * secid){
	return ka_check_sk_getsecid(sk, secid);
}
static void lsm_sock_graft(struct sock* sk, struct socket * parent){
	return ka_check_sock_graft(sk, parent);
}
static int lsm_inet_conn_request(struct sock * sk, struct sk_buff * skb, struct request_sock * req){
	return ka_check_inet_conn_request(sk, skb, req);
}
static void lsm_inet_csk_clone(struct sock * newsk, const struct request_sock * req){
	return ka_check_inet_csk_clone(newsk, req);
}
static void lsm_inet_conn_established(struct sock * sk, struct sk_buff * skb){
	return ka_check_inet_conn_established(sk, skb);
}
static void lsm_req_classify_flow(const struct request_sock * req, struct flowi * fl){
	return ka_check_req_classify_flow(req, fl);
}

#ifdef CONFIG_SECURITY_NETWORK_XFRM
static int lsm_xfrm_policy_alloc_security(struct xfrm_policy * xp, struct xfrm_user_sec_ctx * sec_ctx){
	return ka_check_xfrm_policy_alloc_security(xp, sec_ctx);
}
static int lsm_xfrm_policy_clone_security(struct xfrm_policy * old, struct xfrm_policy * new){
	return ka_check_xfrm_policy_clone_security(old, new);
}
static void lsm_xfrm_policy_free_security(struct xfrm_policy * xp){
	return ka_check_xfrm_policy_free_security(xp);
}
static int lsm_xfrm_policy_delete_security(struct xfrm_policy * xp){
	return ka_check_xfrm_policy_delete_security(xp);
}
static int lsm_xfrm_state_alloc_security(struct xfrm_state * x, struct xfrm_user_sec_ctx * sec_ctx, u32 secid){
	return ka_check_xfrm_state_alloc_security(x, sec_ctx, secid);
}
static void lsm_xfrm_state_free_security(struct xfrm_state * x){
	return ka_check_xfrm_state_free_security(x);
}
static int lsm_xfrm_state_delete_security(struct xfrm_state * x){
	return ka_check_xfrm_state_delete_security(x);
}
static int lsm_xfrm_policy_lookup(struct xfrm_policy * xp, u32 fl_secid, u8 dir){
	return ka_check_xfrm_policy_lookup(xp, fl_secid, dir);
}
static int lsm_xfrm_state_pol_flow_match(struct xfrm_state * x, struct xfrm_policy * xp, struct flowi * fl){
	return ka_check_xfrm_state_pol_flow_match(x, xp, fl);
}
static int lsm_xfrm_decode_session(struct sk_buff * skb, u32 * secid, int ckall){
	return ka_check_xfrm_decode_session(skb, secid, ckall);
}
#endif/* CONFIG_SECURITY_NETWORK_XFRM */

/*
static int lsm_key_alloc(struct key * key, struct task_struct * tsk, unsigned long flags){
	return ka_check_key_alloc(key, tsk, flags);
}
static void lsm_key_free(struct key * key){
	return ka_check_key_free(key);
}
*/


struct security_operations lsm_security_ops = {
	.ptrace = lsm_ptrace,
	.capget = lsm_capget,
	.capset_check = lsm_capset_check,
	.capset_set = lsm_capset_set,
	.capable = lsm_capable,
	.acct = lsm_acct,
	.sysctl = lsm_sysctl,
	.quotactl = lsm_quotactl,
	.quota_on = lsm_quota_on,
	.syslog = lsm_syslog,
	.settime = lsm_settime,
	.vm_enough_memory = lsm_vm_enough_memory,
	.bprm_alloc_security = lsm_bprm_alloc_security,
	.bprm_free_security = lsm_bprm_free_security,
	.bprm_apply_creds = lsm_bprm_apply_creds,
	.bprm_post_apply_creds = lsm_bprm_post_apply_creds,
	.bprm_set_security = lsm_bprm_set_security,
	.bprm_check_security = lsm_bprm_check_security,
	.bprm_secureexec = lsm_bprm_secureexec,
	.sb_alloc_security = lsm_sb_alloc_security,
	.sb_free_security = lsm_sb_free_security,
	.sb_copy_data = lsm_sb_copy_data,
	.sb_kern_mount = lsm_sb_kern_mount,
	.sb_statfs = lsm_sb_statfs,
	.sb_mount = lsm_sb_mount,
	.sb_check_sb = lsm_sb_check_sb,
	.sb_umount = lsm_sb_umount,
	.sb_umount_close = lsm_sb_umount_close,
	.sb_umount_busy = lsm_sb_umount_busy,
	.sb_post_remount = lsm_sb_post_remount,
	.sb_post_mountroot = lsm_sb_post_mountroot,
	.sb_post_addmount = lsm_sb_post_addmount,
	.sb_pivotroot = lsm_sb_pivotroot,
	.sb_post_pivotroot = lsm_sb_post_pivotroot,
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
	.task_alloc_security = lsm_task_alloc_security,
	.task_free_security = lsm_task_free_security,
	.task_setuid = lsm_task_setuid,
	.task_post_setuid = lsm_task_post_setuid,
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
	.task_reparent_to_init = lsm_task_reparent_to_init,
	.task_to_inode = lsm_task_to_inode,
	.ipc_permission = lsm_ipc_permission,
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
	.register_security = lsm_register_security,
	.d_instantiate = lsm_d_instantiate,
	.getprocattr = lsm_getprocattr,
	.setprocattr = lsm_setprocattr,
	.secid_to_secctx = lsm_secid_to_secctx,
	.release_secctx = lsm_release_secctx,
	.unix_stream_connect = lsm_unix_stream_connect,
	.unix_may_send = lsm_unix_may_send,
	.socket_create = lsm_socket_create,
	.socket_post_create = lsm_socket_post_create,
	.socket_bind = lsm_socket_bind,
	.socket_connect = lsm_socket_connect,
	.socket_listen = lsm_socket_listen,
	.socket_accept = lsm_socket_accept,
	.socket_post_accept = lsm_socket_post_accept,
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
	//.key_alloc = lsm_key_alloc,
	//.key_free = lsm_key_free,
	//.key_permission = lsm_key_permission,
};



static int __init kadvicelsm_init(void){
  if(register_security(&lsm_security_ops)){
    printk(KERN_INFO "failure register\n");
  }
  printk(KERN_INFO "addhookbase module init\n");
  return 0;
}


static void __exit kadvicelsm_exit(void){
  if(unregister_security(&lsm_security_ops)){
    printk(KERN_INFO "failure unregister\n");
  }
  printk(KERN_INFO "addhookbase module remove\n");
}

//security_initcall(kadvicelsm_init);
module_init(kadvicelsm_init);
module_exit(kadvicelsm_exit);
EXPORT_SYMBOL(lsm_security_ops);
