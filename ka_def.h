#ifndef _KADVICE_KA_DEF_H
#define _KADVICE_KA_DEF_H
#define LSMIDMAX 182
#define AOIDMAX   8
#define FUNCMAX    8

typedef unsigned long ka_ptr;

struct sc_query {
  char *acc;
  char *hookpoint;
  int gid;
  int priority;
  char *funcname;
  unsigned long funcaddr;
};


#endif //_KADVICE_KA_DEF_H
