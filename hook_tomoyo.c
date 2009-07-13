#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/security.h>
#include "ka/kadvice_security_lsm.h"
//#include "ka/ka_advice.h"
#include "ka/securitycube.h"
#include "ka_def.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("shinpei Nakata");


DEF_SC_QUERY("tomoyo", cred_prepare);
DEF_SC_QUERY("tomoyo", bprm_set_creds);
DEF_SC_QUERY("tomoyo", sysctl);
DEF_SC_QUERY("tomoyo", bprm_check_security);
DEF_SC_QUERY("tomoyo", path_truncate);
DEF_SC_QUERY("tomoyo", path_unlink);
DEF_SC_QUERY("tomoyo", path_mkdir);
DEF_SC_QUERY("tomoyo", path_rmdir);
DEF_SC_QUERY("tomoyo", path_symlink);
DEF_SC_QUERY("tomoyo", path_mknod);
DEF_SC_QUERY("tomoyo", path_link);
DEF_SC_QUERY("tomoyo", path_rename);
DEF_SC_QUERY("tomoyo", file_fcntl);
DEF_SC_QUERY("tomoyo", dentry_open);

static int __init tomoyohook_init(void){
  scube_post_query(&scq_cred_prepare);
  scube_post_query(&scq_bprm_set_creds);
  scube_post_query(&scq_sysctl);
  scube_post_query(&scq_bprm_check_security);
  scube_post_query(&scq_path_truncate);
  scube_post_query(&scq_path_unlink);
  scube_post_query(&scq_path_mkdir);
  scube_post_query(&scq_path_rmdir);
  scube_post_query(&scq_path_symlink);
  scube_post_query(&scq_path_mknod);
  scube_post_query(&scq_path_link);
  scube_post_query(&scq_path_rename);
  scube_post_query(&scq_file_fcntl);
  scube_post_query(&scq_dentry_open);
  return 0;
}

module_init(tomoyohook_init);
