#ifndef CODEGENER_PENGLAI_TSTDIO_ARGS_H
#define CODEGENER_PENGLAI_TSTDIO_ARGS_H

#include <stdint.h>
#include <stdlib.h>

#include "enclave.h"
/* #include <errno.h> - Errno propagation not enabled so not included. */

/**** User includes. ****/
/* There were no user defined types. */
#ifdef __cplusplus
extern "C" {
#endif

/**** User defined types in EDL. ****/
/* There were no user defined types. */

/**** Trusted function marshalling structs. ****/

/**** Untrusted function marshalling structs. ****/
typedef struct _ocall_printf_size_t
{
    size_t retval_size;
    size_t buf_size;
} ocall_printf_size_t;

/**** Trusted function IDs ****/
enum
{

    fid_trusted_call_id_max = SECGEAR_ENUM_MAX
};
/**** Untrusted function IDs ****/
enum
{
    fid_ocall_printf = 0,
    fid_untrusted_call_id_max = SECGEAR_ENUM_MAX
};

#ifdef __cplusplus
}
#endif

#endif
