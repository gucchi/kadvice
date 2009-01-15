#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/net.h>

extern int ka_check_inode_permission(struct inode *inode, int mask, struct nameidata *nd);
extern int ka_check_socket_sendmsg(struct socket *, struct msghdr *, int);
extern int ka_check_file_permission(struct file *, int);
