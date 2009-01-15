#include "ka_def.h"
#define KAOACM(i) acm[i]

void  *lsm_acm[LSMIDMAX + 1][AOIDMAX][FUNCMAX];

//lsm_acm_t lsm_acm[32][8];

static void *ka_start(struct seq_file *, loff_t *);
static void *ka_next(struct seq_file *, void *, loff_t *);
static void ka_stop(struct seq_file *, void *);

static int lsmacc_module_init(void);
static void lsmacc_module_exit(void);

//extern int create_acmcontrol();

