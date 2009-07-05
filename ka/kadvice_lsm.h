
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/security.h>
#include <linux/key.h>



extern int sc_check_cred_prepare(struct cred * new, const struct cred * old, gfp_t gfp);
extern int sc_check_sysctl(struct ctl_table *table, int op);
extern int sc_check_bprm_set_creds(struct ctl_table *table, int op);
extern int sc_check_bprm_check_security(struct linux_bprm *bprm);
extern int sc_check_path_mknod(struct path * path,struct dentry * dentry,int mode,unsigned int dev);
extern int sc_check_path_mkdir(struct path * path,struct dentry * dentry,int mode);
extern int sc_check_path_rmdir(struct path * path,struct dentry * dentry);
extern int sc_check_path_unlink(struct path * path,struct dentry * dentry);
extern int sc_check_path_symlink(struct path * path,struct dentry * dentry,const char * old_name);
extern int sc_check_path_link(struct dentry * old_dentry,struct path * new_dir,struct dentry * new_dentry);
extern int sc_check_path_rename(struct path * old_dir,struct dentry * old_dentry,struct path * new_dir,struct dentry * new_dentry);
extern int sc_check_path_truncate(struct path * path,loff_t length,unsigned int time_attrs);
