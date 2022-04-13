/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <unistd.h>
#include <linux/limits.h>
#include "enclave.h"
#include "helloworld_with_ocall_u.h"
#include "string.h"

#define BUF_LEN 32
#define TA_HELLO_WORLD        "secgear hello world!"

int get_string(char *buf)
{
    strncpy(buf, TA_HELLO_WORLD, strlen(TA_HELLO_WORLD) + 1);
    return 0;
}

int main()
{
    char *path = PATH;
    cc_enclave_t *context = NULL;
    context = (cc_enclave_t *)malloc(sizeof(cc_enclave_t));
    if (!context) {
        return CC_ERROR_OUT_OF_MEMORY;
    }
    cc_enclave_result_t res = CC_FAIL;

    printf("Create secgear enclave\n");

    char real_p[PATH_MAX];
    /* check file exists, if not exist then use absolute path */
    if (realpath(path, real_p) == NULL) {
        if (getcwd(real_p, sizeof(real_p)) == NULL) {
            printf("Cannot find penglai-ELF");
            goto end;
        }
        if (PATH_MAX - strlen(real_p) <= strlen("/penglai-ELF")) {
            printf("Failed to strcat penglai-ELF path");
            goto end;
        }
        (void)strcat(real_p, "/penglai-ELF");
    }

    res = cc_enclave_create(real_p, AUTO_ENCLAVE_TYPE, 0, SECGEAR_DEBUG_FLAG, NULL, 0, context);
    if (res != CC_SUCCESS) {
        printf("Create enclave error\n");
        goto end; 
    }

    res = helloworld(context);
    if (res != CC_SUCCESS) {
        printf("Ecall enclave error\n");
    }

    res = cc_enclave_destroy(context);
    if(res != CC_SUCCESS) {
        printf("Destroy enclave error\n");
    }
end:
    free(context);
    return res;
}

