#ifndef _KADVICE_KA_DEF_H
#define _KADVICE_KA_DEF_H
#define LSMIDMAX 180
#define AOIDMAX   32
#define FUNCMAX    8

typedef unsigned long ka_ptr;

struct ka_query{
  char *acc;
  char *weavepoint;
  int aoid;
  int priority;
  char *funcname;
  unsigned long funcaddr;
};


#endif //_KADVICE_KA_DEF_H
