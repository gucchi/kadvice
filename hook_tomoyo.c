#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include "ka/kadvice_security_lsm.h"
#include "ka/ka_advice.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("shinpei Nakata");

extern int tomoyo_cred_prepare(struct cred *new, const struct cred *old,
			gfp_t gfp);
extern int tomoyo_bprm_set_creds(struct linux_binprm *bprm);
extern int tomoyo_bprm_check_security(struct linux_binprm *bprm);
extern int tomoyo_sysctl(struct ctl_table *table, int op);
extern int tomoyo_path_truncate(struct path *path, loff_t length,
			 unsigned int time_attrs);
extern int tomoyo_path_unlink(struct path *parent, struct dentry *dentry);
extern int tomoyo_path_mkdir(struct path *parent, struct dentry *dentry,
		      int mod);
extern int tomoyo_path_rmdir(struct path *parent, struct dentry *dentry);
extern int tomoyo_path_symlink(struct path *parent, struct dentry *dentry,
			const char *old_name);
extern int tomoyo_path_mknod(struct path *parent, struct dentry *dentry,
		      int mode, unsigned int dev);
extern int tomoyo_path_link(struct dentry *old_dentry, struct path *new_dir,
		     struct dentry *new_dentry);
extern int tomoyo_path_rename(struct path *old_parent,
			      struct dentry *old_dentry,
			      struct path *new_parent,
		       struct dentry *new_dentry);
extern int tomoyo_file_fcntl(struct file *file, unsigned int cmd,
		      unsigned long arg);
extern int tomoyo_dentry_open(struct file *f, const struct cred *cred);


static int __init tomoyohook_init(void){
  kadvice_register_advice(0, __SC_cred_prepare, &tomoyo_cred_prepare, 0);
  kadvice_register_advice(0, __SC_bprm_set_creds, &tomoyo_bprm_set_creds, 0);
  kadvice_register_advice(0, __SC_sysctl, &tomoyo_sysctl, 0);
  kadvice_register_advice(0, __SC_bprm_check_security, &tomoyo_bprm_check_security, 0);
  kadvice_register_advice(0, __SC_path_truncate, &tomoyo_path_truncate, 0);
  kadvice_register_advice(0, __SC_path_unlink, &tomoyo_path_unlink, 0);
  kadvice_register_advice(0, __SC_path_mkdir, &tomoyo_path_mkdir, 0);
  kadvice_register_advice(0, __SC_path_rmdir, &tomoyo_path_rmdir, 0);
  kadvice_register_advice(0, __SC_path_symlink, &tomoyo_path_symlink, 0);
  kadvice_register_advice(0, __SC_path_mknod, &tomoyo_path_mknod, 0);
  kadvice_register_advice(0, __SC_path_link, &tomoyo_path_link, 0);
  kadvice_register_advice(0, __SC_path_rename, &tomoyo_path_rename, 0);
  kadvice_register_advice(0, __SC_file_fcntl, &tomoyo_file_fcntl, 0);
  kadvice_register_advice(0, __SC_dentry_open, &tomoyo_dentry_open, 0);

  return 0;
}

module_init(tomoyohook_init);
