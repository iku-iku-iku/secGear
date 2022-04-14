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
#include <string.h>
#include "calculate.h"
#include "calcu_enclave_t.h"

#define BUF_LEN 32
void helloworld()
{
    eapp_print("enclave start ocall get_string\n");
    int retval = 0;
    char buf[BUF_LEN];
    cc_enclave_result_t res = get_string(&retval, buf);
    if (res != CC_SUCCESS || retval != (int)CC_SUCCESS) {
        eapp_print("Ocall enclave error\n");
    } else {
        eapp_print("%s\n", buf);
    }
    eapp_print("enclave end ocall get_string\n");
    
    // test lib function
    eapp_print("- - - enclave test lib function - - -\n");
    calcu_two_num(ADD, 1, 4);
    calcu_two_num(MINOR, 6, 2);
    calcu_two_num(MULTIPLY, 2, 3);
    calcu_two_num(DEVIDE, 9, 3);
    eapp_print("- - - test lib finish - - -\n");
    return;
}
