

#define MODEL_MAX 8

struct sc_task_security {
  int gid;
  void *label[MODEL_MAX];
};

struct sc_inode_security {
  int gid;
  void *label[MODEL_MAX];
};
