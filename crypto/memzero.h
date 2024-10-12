#ifdef __cplusplus
extern "C" {
#endif

#ifndef __MEMZERO_H__
#define __MEMZERO_H__

#include <stddef.h>

void memzero(void* const pnt, const size_t len);

#endif

#ifdef __cplusplus
} // extern "C"
#endif
