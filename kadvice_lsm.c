#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/security.h>

#include "ka/kadvice_lsm.h"




static int sc_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
  return sc_check_cred_prepare(new, old, gfp);
}

static int sc_sysctl(struct ctl_table *table, int op)
{
  return sc_check_sysctl(table, op);
}

//cap_bprm_set_creds needs to export
static int sc_bprm_set_creds(struct ctl_table *table, int op)
{
  return sc_check_bprm_set_creds(table, op);
}

static int sc_bprm_check_security(struct linux_binprm *bprm)
{

  return sc_check_bprm_check_security(bprm);
}

static int sc_path_unlink (struct path *dir, struct dentry *dentry)
{
  return sc_check_path_unlink(dir, dentry);
}

static int sc_path_mkdir (struct path *dir, struct dentry *dentry, int mode)
{
  return sc_check_path_mkdir(dir, dentry, mode);
}

static int sc_path_rmdir (struct path *dir, struct dentry *dentry)
{

  return sc_check_path_rmdir(dir, dentry);

}

static int sc_path_mknod (struct path *dir, struct dentry *dentry, int mode,
			   unsigned int dev)
{
  return sc_check_path_mknod(dir, dentry, mode, dev);

}

static int sc_path_truncate (struct path *path, loff_t length,
			      unsigned int time_attrs)
{
  return sc_check_path_truncate(path, length, time_attrs);
}

static int sc_path_symlink (struct path *dir, struct dentry *dentry,
			    const char *old_name)
{
  return sc_check_path_symlink(dir, dentry, old_name);
}
static	int sc_path_link (struct dentry *old_dentry, struct path *new_dir,
			  struct dentry *new_dentry)
{
  return sc_check_path_link(old_dentry, new_dir, new_dentry);
}

static	int sc_path_rename (struct path *old_dir, struct dentry *old_dentry,
			    struct path *new_dir, struct dentry *new_dentry)
{
  printk("hi!!!\n");
  return sc_check_path_rename(old_dir, old_dentry, new_dir, new_dentry);
}


struct security_operations sc_security_ops = {
  .name = "securitycube",
  .cred_prepare = sc_cred_prepare,
  .sysctl = sc_sysctl,
  .bprm_set_creds = sc_bprm_set_creds,
  .bprm_check_security = sc_bprm_check_security,
  .path_mkdir = sc_path_mkdir,
  .path_rmdir = sc_path_rmdir,
  .path_unlink = sc_path_unlink,
  .path_symlink = sc_path_symlink,
  .path_rename = sc_path_rename,
  .path_truncate = sc_path_truncate,
  .path_mknod = sc_path_mknod,
  .path_link = sc_path_link,
};

static int __init securitycube_init(void)
{
  if(!security_module_enable(&sc_security_ops))
    return 0;

  if(register_security(&sc_security_ops)) {
	printk(KERN_INFO "failure register\n");
  }
  printk(KERN_INFO "security cube properly registered\n");
  
  return 0;
}

static void security_exit(void)
{

}

security_initcall(securitycube_init);
module_exit(security_exit);
EXPORT_SYMBOL(sc_security_ops);
