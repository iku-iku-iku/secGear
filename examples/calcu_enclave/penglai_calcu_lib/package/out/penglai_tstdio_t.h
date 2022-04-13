#ifndef CODEGENER_PENGLAI_TSTDIO_T_H
#define CODEGENER_PENGLAI_TSTDIO_T_H

#include "enclave.h"
#include "ocall.h"
#include "print.h"

#include "penglai_tstdio_args.h"
#include "status.h"
#include "penglai.h"
#include "penglai_ocall.h"
#include "memory_check.h"

#ifdef __cplusplus
extern "C" {
#endif

/**** Trusted function prototypes. ****/
;
/**** Untrusted function prototypes. ****/
cc_enclave_result_t ocall_printf(
    int* retval,
    char* buf);

#ifdef __cplusplus
}
#endif

#endif
