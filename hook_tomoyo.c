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


SC_POST("tomoyo", cred_prepare);
SC_POST("tomoyo", bprm_set_creds);
SC_POST("tomoyo", sysctl);
SC_POST("tomoyo", bprm_check_security);
SC_POST("tomoyo", path_truncate);
SC_POST("tomoyo", path_unlink);
SC_POST("tomoyo", path_mkdir);
SC_POST("tomoyo", path_rmdir);
SC_POST("tomoyo", path_symlink);
SC_POST("tomoyo", path_mknod);
SC_POST("tomoyo", path_link);
SC_POST("tomoyo", path_rename);
SC_POST("tomoyo", file_fcntl);
SC_POST("tomoyo", dentry_open);

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
