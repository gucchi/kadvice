#include "../securitycube/securitycube.h"
#include "kadvice_security_lsm.h"

extern int lookup_module_symbol_name(unsigned long, char *);
extern int lookup_module_symbol_attrs(unsigned long, unsigned long *, unsigned long *, char *, char *);

#define FUNCNAME(name) sc_check_##name

//#define CHECK

#ifdef CHECK
#define CHECK_MSG(name) printk(#name " security check\n")
#else
#define CHECK_MSG(name) 
#endif  

//extern struct security_operations default_security_ops;


#define FUNC1INT(acc, name,type1, arg1)		\
  int FUNCNAME(name)(type1 arg1)		\
  {						\
    int group_id = 0;				\
    int (*func)(type1 arg1);			\
      CHECK_MSG(name);					\
    struct cred *locred = get_current_cred();		\
    struct sc_task_security *tsec_current =		\
      (struct sc_task_security *)(locred->security);	\
    if(acc[__SC_##name][group_id][0] != 0) {		\
      func = (void *)acc[__SC_##name][group_id][0];	\
      if(func(arg1) != 0) {				\
	return -1;					\
      }							\
    }							\
    return 0;						\
  }							\
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC2INT(acc, name,type1, arg1,type2, arg2) \
int FUNCNAME(name)(type1 arg1,type2 arg2) \
{   \
  int group_id = 0;			 \
    CHECK_MSG(name);					\
  int (*func)(type1 arg1, type2 arg2);	      \
  struct cred *locred = get_current_cred();	\
  struct sc_task_security *tsec_current =	     \
    (struct sc_task_security *)(locred->security);   \
  if(acc[__SC_##name][group_id][0] != 0) {	     \
    func = (void *)acc[__SC_##name][group_id][0];	\
    if(func(arg1, arg2) != 0) {				\
      return -1;					\
    }							\
  }							\
  return 0;						\
}							\
  EXPORT_SYMBOL(sc_check_##name)


#define FUNC3INT(acc, name,type1, arg1,type2, arg2,type3, arg3) \
int FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3) \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    int (*func)(type1 arg1, type2 arg2, type3 arg3); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      func = (void *)acc[__SC_##name][group_id][0];	\
      if(func(arg1, arg2, arg3) != 0) {			\
	return -1;					\
      }							\
    }							\
    return 0;						\
}							\
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC4INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
	func = (void *)acc[__SC_##name][group_id][0];	\
	if(func(arg1, arg2, arg3, arg4) != 0) {		\
	  return -1;					\
	}						\
    } 						\
    return 0;						\
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC5INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{   \
    int group_id=0; \
      CHECK_MSG(name); \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	      \
      if(func(arg1, arg2, arg3, arg4, arg5) != 0) {	      \
	return -1;					      \
      }							      \
    }							      \
    return 0;						      \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC6INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5,type6, arg6) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{   \
    int group_id=0; \
      CHECK_MSG(name); \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];		    \
      if(func(arg1, arg2, arg3, arg4, arg5, arg6) != 0) {	    \
	return -1;						    \
      }								    \
    }						\
    return 0;						\
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC0VOID(acc, name) \
void FUNCNAME(name)() \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    void (*func)(void); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	\
      func();						\
    } else {						\
      return;						\
    }							\
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC1VOID(acc, name,type1, arg1) \
void FUNCNAME(name)(type1 arg1) \
{   \
    int group_id=0; \
      CHECK_MSG(name); \
    void (*func)(type1 arg1); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	      \
      func(arg1);					      \
    }						      \
}						\
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC2VOID(acc, name,type1, arg1,type2, arg2) \
void FUNCNAME(name)(type1 arg1,type2 arg2) \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    void (*func)(type1 arg1, type2 arg2); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	\
      func(arg1, arg2);					\
    }							\
}							\
 EXPORT_SYMBOL(sc_check_##name)

#define FUNC3VOID(acc, name,type1, arg1,type2, arg2,type3, arg3) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3) \
{   \
  int group_id = 0;				      \
      CHECK_MSG(name); \
  void (*func)(type1 arg1, type2 arg2, type3 arg3);   \
  struct cred *locred = get_current_cred();	      \
  struct sc_task_security *tsec_current =	      \
    (struct sc_task_security *)(locred->security);    \
  if(acc[__SC_##name][group_id][0] != 0) {	      \
    CHECK_MSG(name);					      \
    func = (void *)acc[__SC_##name][group_id][0];	      \
    func(arg1, arg2, arg3);				      \
  }							      \
}							      \
 EXPORT_SYMBOL(sc_check_##name)

#define FUNC4VOID(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	      \
      func(arg1, arg2, arg3, arg4);			      \
    }							      \
}							      \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC5VOID(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	      \
      func(arg1, arg2, arg3, arg4, arg5);		      \
    }						     \
}						     \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC6VOID(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5,type6, arg6) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{   \
    int group_id = 0; \
      CHECK_MSG(name); \
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      func = (void *)acc[__SC_##name][group_id][0];	     \
      func(arg1, arg2, arg3, arg4, arg5, arg6);		     \
    }							     \
}							     \
 EXPORT_SYMBOL(sc_check_##name)

