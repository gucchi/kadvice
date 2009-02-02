/* shinpei(c)2008
 * Kadvice string_put sample
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/percpu.h>
#include <linux/ktime.h>
#include <linux/mutex.h>
#include "kadvice_io.h"

MODULE_LICENSE("GPL");

#define PROCNAME "ttt"

struct proc_dir_entry* e;

static DEFINE_MUTEX(advice_iotest_mutex);
static int test_read(char *page, char **start, off_t off,
			int count, int *eof, void *data)
{
  unsigned long long t0, t1, time_passed_ns;
  t0 = cpu_clock(0);
  //  preempt_disable();
    mutex_lock(&advice_iotest_mutex);
    kadvice_uri_put("test2.k");
    kadvice_string_put("hi");
    kadvice_send();
    mutex_unlock(&advice_iotest_mutex);
    //  preempt_enable();
  //printk("aloha, world");
  t1 = cpu_clock(0);
  time_passed_ns = t1 - t0;
  printk("time:%lld\n", time_passed_ns);
  
  return 0;
}

static int test_init(void)
{
  e = create_proc_entry(PROCNAME, 0666, NULL);
  e->read_proc = test_read;
  return 0;
}

static void test_fini(void)
{
  remove_proc_entry(PROCNAME, NULL);
  printk("finish\n");

}

module_init(test_init);
module_fini(test_fini);
