#!/usr/local/bin/konoha

FILENAME = 'base.out';
os = new OutputStream(FILENAME, "w");

// there is two types of return value;
// int or void.
os << '''
#include "../securitycube/securitycube.h"

extern int lookup_module_symbol_name(unsigned long, char *);
extern int lookup_module_symbol_attrs(unsigned long, unsigned long *, unsigned long *, char *, char *);

#define FUNCNAME(name) ka_check_##name

//#define CHECK

#ifdef CHECK
#define CHECK_MSG(name) printk(#name " security check\\n")
#else
#define CHECK_MSG(name)
#endif  

extern struct security_operations dummy_security_ops;
''';

void gen_macroname (int num_args, String type)
{
	String line;
	if (type == 'int') {
		line = "#define FUNC%d{0}INT(acc, name";
	} else if (type == 'void') {
		line = "#define FUNC%d{0}VOID(acc, name";		
	} else {
		OUT << "erorr" << EOL;
		return;
	}
	line = %(line, num_args);
	for (i = 1; i <= num_args; i++) {
		line = line + %(",type%d{0}, arg%d{0}", i);
	}
	line = line + ") \\";
	os << line << EOL;
}

void gen_funcname(int num_args, String type)
{
	String line;
	if (type == 'int') {
		line = "int FUNCNAME(name)(";
	} else if (type == 'void') {
		line = "void FUNCNAME(name)(";
	} else {
		OUT << "error" << EOL;
		return;
	}
	for (i = 1; i <= num_args; i++) {
		if (i > 1) {
			line = line + %(",type%d{0} arg%d{0}", i);
		} else {
			line = line + %("type%d{0} arg%d{0}", i);
		}
	}
	line = line + ") \\";
	os << line << EOL;
}

void gen_body(int num_args, String type)
{
	line = '''
{   \\
    int group_id; \\
    %s{0}; \\
    struct sc_task_security *tsec_current =	\\
      (struct sc_task_security *)(current->security); \\
    if (tsec_current != NULL) {	\\
      group_id  = tsec_current->gid; \\
    } else { \\
      group_id = 0; \\
    } \\
    if(acc[__KA_##name][group_id][0] != 0) { \\
      CHECK_MSG(name); \\
      if (tsec_current->label[group_id] != NULL) { \\
		current->security =	\\
		  (void *)(tsec_current->label[group_id]); \\
		func = (void *)acc[__KA_##name][group_id][0]; \\
		if(func(%s{1}) != 0) { \\
		  current->security = tsec_current; \\
		  return -1; \\
		} \\
		current->security = tsec_current; \\
      } \\
    } \\
    func = (void *)(dummy_security_ops.name); \\
    return func(%s{1}); \\
  } \\
  EXPORT_SYMBOL(ka_check_##name)

''';
	String l1, l2;
	l2 = "";
	if (type == 'int') {
		l1 ="int (*func)(";
	} else if (type == 'void') {
		l1 = "void (*func)(";
	} else {
		OUT << "error" << EOL;
		return ;
	}
	for (i = 1; i <= num_args; i++) {
		if (i == 1) {
			l1 = l1 + %("type%d{0} arg%d{0}", i);
			l2 = l2 + %("arg%d{0}", i);
		} else {
			l1 = l1 + %(", type%d{0} arg%d{0}", i);
			l2 = l2 + %(", arg%d{0}", i);
		}
	}
	l1 = l1 + ")";
	line = %(line, l1, l2);
	os << line << EOL;
}
	
void generate(int num_args, String type)
{
	gen_macroname(num_args, type);
	gen_funcname(num_args, type);
	gen_body(num_args, type);

}

for (i=1; i <= 6; i++) {
	generate(i, "int");
}

os << '''
#define FUNC0VOID(acc, name, type1)					\
  void FUNCNAME(name)(type1)						\
  {									\
    struct cabi_account *cabi_ac;					\
    int cabiid, i;							\
    void (*func)(void);							\
    if((cabi_ac = (struct cabi_account *)(current->cabi_info)))		\
      cabiid = cabi_ac->cabi_id;					\
    else								\
      cabiid = 0;							\
    for(i = 0; i < 8; i++){						\
      if(acc[__KA_##name][cabiid][i] != 0){				\
	CHECK_MSG(name);						\
	func = (void *)acc[__KA_##name][cabiid][i];			\
	func();								\
      }									\
    }									\
    func = (void *)(dummy_security_ops.name);				\
    return func();							\
  }									\
  EXPORT_SYMBOL(ka_check_##name)''' << EOL;	       


for (i=1; i <= 6; i++) {
	generate(i, "void");
}

os.close();
