#ifndef __KADVICE_DEBUG_H
#define __KADVICE_DEBUG_H

#include <stdarg.h>


#define DBG_P(fmt, ...) \
  printk("[%s:%d](%s)", __FILE__, __LINE__, __FUNCTION__); \
  printk(fmt, ##__VA_ARGS__); \
  printk("\n"); \


#endif  /* __KADVICE_DEBUG_H */




