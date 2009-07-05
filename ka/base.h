#include "../securitycube/securitycube.h"

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
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2) != 0) { \
		  cred->security = tsec_current; \
		  return -1; \
		} \
		cred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC3INT(acc, name,type1, arg1,type2, arg2,type3, arg3) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3); \
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3) != 0) { \
		  cred->security = tsec_current; \
		  return -1; \
		} \
		cred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC4INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4); \
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4) != 0) { \
		  cred->security = tsec_current; \
		  return -1; \
		} \
		cred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

#define FUNC5INT(acc, name,type1, arg1,type2, arg2,type3, arg3,type4, arg4,type5, arg5) \
int FUNCNAME(name)(type1 arg1,type2 arg2,type3 arg3,type4 arg4,type5 arg5) \
{   \
    int group_id; \
    int (*func)(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5); \
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4, arg5) != 0) { \
		  cred->security = tsec_current; \
		  return -1; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4, arg5, arg6) != 0) { \
		  cred->security = tsec_current; \
		  return -1; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func() != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1) != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2) != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3) != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4) != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4, arg5) != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
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
    struct cred *cred = get_current_cred(); \
    struct sc_task_security *tsec_current =	\
      (struct sc_task_security *)(cred->security); \
    if (tsec_current != NULL) {	\
      group_id  = tsec_current->gid; \
    } else { \
      group_id = 0; \
    } \
    if(acc[__KA_##name][group_id][0] != 0) { \
      CHECK_MSG(name); \
      if (tsec_current->label[group_id] != NULL) { \
		cred->security =	\
		  (void *)(tsec_current->label[group_id]); \
		func = (void *)acc[__KA_##name][group_id][0]; \
		if(func(arg1, arg2, arg3, arg4, arg5, arg6) != 0) { \
		  cred->security = tsec_current; \
		  return ; \
		} \
		cred->security = tsec_current; \
      } \
    } \
    return func(arg1, arg2, arg3, arg4, arg5, arg6); \
  } \
  EXPORT_SYMBOL(sc_check_##name)

