

#define MODEL_MAX 8

struct sc_task_security {
  int gid;
  void *label[MODEL_MAX];
};

struct ka_inode_security {
  int gid;
  void *label[MODEL_MAX];
};
