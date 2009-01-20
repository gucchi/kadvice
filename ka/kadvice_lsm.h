#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <cabi/common.h>
extern int ka_check_inode_permission(struct inode *inode, int mask, struct nameidata *nd, struct cabi_account *cabi);
extern int ka_check_socket_sendmsg(struct socket *, struct msghdr *, int, struct cabi_account *);
extern int ka_check_file_permission(struct file *, int, struct cabi_account *);
