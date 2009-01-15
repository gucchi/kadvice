extern int lookup_module_symbol_name(unsigned long, char *);
extern int lookup_module_symbol_attrs(unsigned long, unsigned long *, unsigned long *, char *, char *);

#define FUNCNAME(name) ka_check_##name

/* acc check function */
#define FUNC1(acc, type, name, type1, arg1)				\
  type FUNCNAME(name)(type1 arg1)					\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*p)(type1 arg1);						\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)acc[__KA_##name][cabiid][i];			\
	if(p(arg1) != 0)						\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC2(acc, type, name, type1, arg1, type2, arg2)		\
  type FUNCNAME(name)(type1 arg1, type2 arg2)				\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*p)(type1 arg1, type2 arg2);					\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)acc[__KA_##name][cabiid][i];			\
	if(p(arg1, arg2) != 0)						\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC3(acc, type, name, type1, arg1, type2, arg2, type3, arg3)	\
  type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3)		\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*p)(type1 arg1, type2 arg2, type3 arg3);			\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)acc[__KA_##name][cabiid][i];			\
	if(p(arg1, arg2, arg3) != 0)					\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC4(acc, type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
  type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4)	\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int ret[8] = {0, 0, 0, 0, 0, 0, 0, 0};				\
    int (*p)(type1 arg1, type2 arg2, type3 arg3, type4 arg4);		\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)acc[__KA_##name][cabiid][i];			\
	ret[i] = p(arg1, arg2, arg3, arg4);					\
      }									\
      if(ret[0] || ret[1] || ret[2] || ret[3] || ret[4] || ret[5] || ret[6] || ret[7]){	\
	printk("access denied\n");					\
	return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC5(acc, type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
  type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) \
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int ret[8] = {0, 0, 0, 0, 0, 0, 0, 0};				\
    int (*p)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)acc[__KA_##name][cabiid][i];			\
	ret[i] = p(arg1, arg2, arg3, arg4, arg5);			\
      }									\
      if(ret[0] || ret[1] || ret[2] || ret[3] || ret[4] || ret[5] || ret[6] || ret[7]){	\
	printk("access denied\n");					\
	return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC6(acc, type, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
  type FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) \
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int ret[8] = {0, 0, 0, 0, 0, 0, 0, 0};				\
    int (*p)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	printk(#name "security check\n");				\
	p = (void *)acc[__KA_##name][cabiid][i];			\
	ret[i] = p(arg1, arg2, arg3, arg4, arg5, arg6);			\
      }									\
      if(ret[0] || ret[1] || ret[2] || ret[3] || ret[4] || ret[5] || ret[6] || ret[7]){	\
	printk("access denied\n");					\
	return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       
