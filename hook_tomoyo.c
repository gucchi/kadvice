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


struct sc_query scq_cred_prepare = {
  .funcname = "tomoyo_cred_prepare",
  .gid = 0,
  .priority = 0,
  .hookpoint = "cred_prepare"
};

struct sc_query scq_bprm_set_creds = {
  .funcname = "tomoyo_bprm_set_creds",
  .gid = 0,
  .priority = 0,
  .hookpoint = "bprm_set_creds"
};

struct sc_query scq_sysctl = {
  .funcname = "tomoyo_sysctl",
  .gid = 0,
  .priority = 0,
  .hookpoint = "sysctl"
};

struct sc_query scq_bprm_check_security = {
  .funcname = "tomoyo_bprm_check_security",
  .gid = 0,
  .priority = 0,
  .hookpoint = "bprm_check_security"
};


struct sc_query scq_path_truncate = {
  .funcname = "tomoyo_path_truncate",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_truncate"
};

struct sc_query scq_path_unlink = {
  .funcname = "tomoyo_path_unlink",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_unlink"
};

struct sc_query scq_path_mkdir = {
  .funcname = "tomoyo_path_mkdir",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_mkdir"
};


struct sc_query scq_path_rmdir = {
  .funcname = "tomoyo_path_rmdir",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_rmdir"
};


struct sc_query scq_path_symlink = {
  .funcname = "tomoyo_path_symlink",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_symlink"
};


struct sc_query scq_path_mknod = {
  .funcname = "tomoyo_path_mknod",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_mknod"
};

struct sc_query scq_path_link = {
  .funcname = "tomoyo_path_link",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_link"
};

struct sc_query scq_path_rename = {
  .funcname = "tomoyo_path_rename",
  .gid = 0,
  .priority = 0,
  .hookpoint = "path_rename"
};

struct sc_query scq_file_fcntl = {
  .funcname = "tomoyo_file_fcntl",
  .gid = 0,
  .priority = 0,
  .hookpoint = "file_fcntl"
};

struct sc_query scq_dentry_open = {
  .funcname = "tomoyo_dentry_open",
  .gid = 0,
  .priority = 0,
  .hookpoint = "dentry_open"
};



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
  /*
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
  */
  return 0;
}

module_init(tomoyohook_init);
