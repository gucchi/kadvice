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

extern struct security_operations default_security_ops;
#define FUNC1INT(acc, name,type1, arg1) \
int FUNCNAME(name)(type1 arg1) \
{   \
    int group_id; \
    int (*func)(type1 arg1); \
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		if(func(arg1) != 0) { \
		  cred->security = tsec_current; \
		  return -1; \
		} \
		cred->security = tsec_current; \
      } \
    } \
    return func(arg1); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC2INT(acc, name,type1, arg1,type2, arg2) \
int FUNCNAME(name)(type1 arg1,type2 arg2) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		if(func(arg1, arg2) != 0) { \
		  locred->security = tsec_current; \
		  return -1; \
		} \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2); \
  } \
  EXPORT_SYMBOL(sc_check_##name)


#define FUNC3INT(acc, name,type1, arg1,type2, arg2,type3, arg3) \
int FUNCNAME(name)(type1 arg1, type2 arg2, type3 arg3) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		if(func(arg1, arg2, arg3) != 0) { \
		  locred->security = tsec_current; \
		  return -1; \
		} \
		locred->security = tsec_current; \
      }					 \
    } \
    return func(arg1, arg2, arg3); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC4INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
      printk("group id is %d\n", group_id);   \
    } else { \
      group_id = 0; \
      return 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
	func = (void *)acc[__SC_##name][group_id][0];	\
	if (tsec_current->label[group_id] != NULL) {	\
	  printk("resolving func addr\n");		\
	  locred->security = (void *)(tsec_current->label[group_id]); \
	  if(func(arg1, arg2, arg3, arg4) != 0) {	\
	    locred->security = tsec_current;		\
	    return -1;					\
	  }						\
	  locred->security = tsec_current; \
	} else {					\
	  printk("its null, group label\n");		\
	}						\
    } else {						\
      return 0;					\
    } \
    return func(arg1, arg2, arg3, arg4); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC5INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4, arg5) != 0) { \
		  locred->security = tsec_current; \
		  return -1; \
		} \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4, arg5); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC6INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5,type6, arg6) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4, arg5, arg6) != 0) { \
		  locred->security = tsec_current; \
		  return -1; \
		} \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4, arg5, arg6); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC0VOID(acc, name) \
void FUNCNAME(name)() \
{   \
    int group_id; \
    void (*func)(void); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func();\
		locred->security = tsec_current; \
      } \
    } \
    return func(); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC1VOID(acc, name,type1, arg1) \
void FUNCNAME(name)(type1 arg1) \
{   \
    int group_id; \
    void (*func)(type1 arg1); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func(arg1);				      \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC2VOID(acc, name,type1, arg1,type2, arg2) \
void FUNCNAME(name)(type1 arg1,type2 arg2) \
{   \
    int group_id; \
    void (*func)(type1 arg1, type2 arg2); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func(arg1, arg2);     \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC3VOID(acc, name,type1, arg1,type2, arg2,type3, arg3) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3) \
{   \
    int group_id; \
    void (*func)(type1 arg1, type2 arg2, type3 arg3); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func(arg1, arg2, arg3);			      \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC4VOID(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{   \
    int group_id; \
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func(arg1, arg2, arg3, arg4);		      \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC5VOID(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{   \
    int group_id; \
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func(arg1, arg2, arg3, arg4, arg5);  \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4, arg5); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC6VOID(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5,type6, arg6) \
void FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5,type6 arg6) \
{   \
    int group_id; \
    void (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5, type6 arg6); \
    struct cred *locred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(locred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__SC_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		locred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__SC_##name][group_id][0]; \
		func(arg1, arg2, arg3, arg4, arg5, arg6);    \
		locred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4, arg5, arg6); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

