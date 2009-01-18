extern int lookup_module_symbol_name(unsigned long, char *);
extern int lookup_module_symbol_attrs(unsigned long, unsigned long *, unsigned long *, char *, char *);

#define FUNCNAME(name) ka_check_##name

/* acc check function */
#define FUNC1INT(acc, name, type1, arg1)				\
  int FUNCNAME(name)(type1 arg1)					\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*func)(type1 arg1);						\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return 0;							\
	}								\
	if(func(arg1) != 0)						\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC2INT(acc, name, type1, arg1, type2, arg2)		\
  int FUNCNAME(name)(type1 arg1, type2 arg2)				\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*func)(type1 arg1, type2 arg2);					\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return 0;							\
	}								\
	if(func(arg1, arg2) != 0)						\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC3INT(acc, name, type1, arg1, type2, arg2, type3, arg3)	\
  int FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3)		\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*func)(type1 arg1, type2 arg2, type3 arg3);			\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return 0;							\
	}								\
	if(func(arg1, arg2, arg3) != 0)					\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC4INT(acc, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
  int FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4)	\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4);		\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return 0;							\
	}								\
	if(func(arg1, arg2, arg3, arg4) != 0)				\
	  return -1;							\
      }									\
     }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC5INT(acc, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
  int FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) \
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return 0;							\
	}								\
	if(func(arg1, arg2, arg3, arg4, arg5) != 0)			\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC6INT(acc, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
  int FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) \
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return 0;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return 0;							\
	}								\
	if(func(arg1, arg2, arg3, arg4, arg5, arg6) != 0)			\
	  return -1;							\
      }									\
    }									\
    return 0;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       


#define FUNC0VOID(acc, name, type1)						\
  void FUNCNAME(name)(void)					\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(void);						\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func();								\
      }									\
    }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       


#define FUNC1VOID(acc, name, type1, arg1)				\
  void FUNCNAME(name)(type1 arg1)					\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(type1 arg1);						\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func(arg1);							\
      }									\
    }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC2VOID(acc, name, type1, arg1, type2, arg2)			\
  void FUNCNAME(name)(type1 arg1, type2 arg2)				\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(type1 arg1, type2 arg2);					\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func(arg1, arg2);							\
      }									\
    }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC3VOID(acc, name, type1, arg1, type2, arg2, type3, arg3)	\
  void FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3)		\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(type1 arg1, type2 arg2, type3 arg3);			\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func(arg1, arg2, arg3);						\
      }									\
    }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC4VOID(acc, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
  void FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4)	\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4);		\
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func(arg1, arg2, arg3, arg4);					\
      }									\
     }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC5VOID(acc, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5) \
  void FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) \
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func(arg1, arg2, arg3, arg4, arg5);				\
      }									\
    }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       

#define FUNC6VOID(acc, name, type1, arg1, type2, arg2, type3, arg3, type4, arg4, type5, arg5, type6, arg6) \
  void FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6) \
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    if(!(cabi_ac = (struct cabi_account *)(current->cabi_info)))	\
      return;								\
    cabiid = cabi_ac->cabi_id;						\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	char symname[128];						\
	printk(#name "security check\n");				\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	if(lookup_module_symbol_name((unsigned long)func, symname) != 0){	\
	  acc[__KA_##name][cabiid][i] = 0;				\
	  return;							\
	}								\
	func(arg1, arg2, arg3, arg4, arg5, arg6);				\
      }									\
    }									\
    return;								\
  }									\
  EXPORT_SYMBOL(ka_check_##name)			       
