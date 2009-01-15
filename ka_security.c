#include "ka/security_ops.h"

#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/security.h>

#include"ka_def.h"
#include"ka/secops.h"

#include<cabi/common.h>

extern unsigned int lsm_acm[LSMIDMAX + 1][AOIDMAX][FUNCMAX];

#define FUNCNAME(name) ka_check_##name

#define FUNC1(type, name, type1, arg1) type FUNCNAME(name)(type1 arg1)


#define FUNC4(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4)
#define FUNC5(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5)
#define FUNC6(type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6)

#define FUNC2(type, name, type1, arg1, type2, arg2)			\
  type FUNCNAME(name)(type1 arg1, type2 arg2)				\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int ret[8] = {0, 0, 0, 0, 0, 0, 0, 0};				\
    int (*p)(type1 arg1, type2 arg2);					\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(lsm_acm[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)lsm_acm[__KA_##name][cabiid][i];			\
	ret[i] = p(arg1, arg2);						\
      }									\
    }									\
    if(ret[0] || ret[1] || ret[2] || ret[3] || ret[4] || ret[5] || ret[6] || ret[7]){ \
      printk("access denied\n");					\
       return -1;							\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC3(type, name, type1, arg1, type2, arg2, type3, arg3)	\
  type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3)		\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int ret[8] = {0, 0, 0, 0, 0, 0, 0, 0};				\
    int (*p)(type1 arg1, type2 arg2, type3 arg3);			\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(lsm_acm[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)lsm_acm[__KA_##name][cabiid][i];			\
	ret[i] = p(arg1, arg2, arg3);					\
      }									\
      if(ret[0] || ret[1] || ret[2] || ret[3] || ret[4] || ret[5] || ret[6] || ret[7]){	\
	printk("access denied\n");					\
	return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

FUNC2(int, file_permission, struct file *, file, int, mask);
FUNC3(int, inode_permission, struct inode *, inode, int, mask, struct nameidata *, nd);
FUNC3(int, socket_sendmsg, struct socket *, sock, struct msghdr *, msg, int, size);

/*
int ka_check_inode_permission(struct inode * inode, int mask, struct nameidata * nd)
{									
  struct cabi_account *cabi_ac;					
  int cabiid, i;								
  if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	
    return 0;					
  cabiid = cabi_ac->cabi_id;						
  int (*p)(struct inode *inode, int mask, struct nameidata *nd);
  for(i = 0; i < 8; i++){			
    if(lsm_acm[__KA_inode_permission][cabiid][i] != 0){
      int ret;
      printk("security check\n");
      p = (void *)lsm_acm[__KA_inode_permission][cabiid][i];
      if((ret = p(inode, mask, nd)) != 0)
	return ret;							
    }									
  }									
  return 0;								
}									
EXPORT_SYMBOL(ka_check_inode_permission);
*/

int addhook(int aoid, int lsmid, void *func){
  int i;
  for(i = 0; i < 8; i++){
    if(lsm_acm[lsmid][aoid][i] == 0)
      break;
  }
  if(i == 8)
    return -1;
  lsm_acm[lsmid][aoid][i] = (unsigned long)func;
  printk("addhook lsmid:%d aoid:%d [%d] %p\n", lsmid, aoid, i, func);
  return 0;
}

int rmhook(int aoid, int lsmid, void *func){
  int i;
  for(i = 0; i < 8; i++){
    if(lsm_acm[lsmid][aoid][i] == (unsigned long)func){
      lsm_acm[lsmid][aoid][i] = 0;
      printk("remove hook %p", func);
    }
  }
  return 0;
}

int clearhook(int aoid, int lsmid){
  int i;
  for(i = 0; i < 8; i++){
    lsm_acm[lsmid][aoid][i] = 0;
  }
  printk("addhook clear\n");
  return 0;
}

unsigned long *checkhook(int aoid, int lsmid){
  int i;
  unsigned long *p = NULL;
  for(i = 0; i < 8; i++){
    if((*p = lsm_acm[lsmid][aoid][i]))
      p++;
  }
  return p;
}


EXPORT_SYMBOL(addhook);
EXPORT_SYMBOL(clearhook);
EXPORT_SYMBOL(rmhook);
EXPORT_SYMBOL(checkhook);
