/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "gp_enclave.h"

#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include <tee_client_type.h>

#include "secgear_defs.h"
#include "enclave_log.h"
#include "secgear_uswitchless.h"
#include "register_agent.h"
#include "gp_uswitchless.h"
#include "gp_shared_memory_defs.h"
#include "gp_shared_memory.h"

#define OCALL_AGENT_REGISTER_SUCCESS 0
#define OCALL_AGENT_REGISTER_FAIL    1
#define SECGEAR_OCALL 0
#define MAX_LEN 4096

static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t g_mtx_flag = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_mtx_cond = PTHREAD_MUTEX_INITIALIZER;
static unsigned int g_agent_flag = OCALL_AGENT_REGISTER_FAIL;

struct _agent_register {
    uint32_t agent_id;
    int dev_fd;
    void *c_buffer;
} g_agent_info = {0,0,NULL};


#define UUID_LEN 36

static cc_enclave_result_t extract_path(const char *path, const char **uuid_pos)
{
    const size_t suffix_len = 4;
    const char end = '/';
    path = strrchr(path, end);
    /* find the last directory separator */
    if (path == NULL) {
        print_error_term("Enclave path error \n");
        return CC_FAIL;
    }
    /* point to file name */
    ++path;
    /* Remove ".sec" extension, if one is present */
    size_t len = strlen(path);
    if ((len > suffix_len) && (strcmp(path + len - suffix_len, ".sec") == 0)) {
        len -= suffix_len;
    }
    if (len != UUID_LEN) {
        print_error_term("Path length is not valid \n");
        return CC_FAIL;
    }
    *uuid_pos = path;
    return CC_SUCCESS;
}

static cc_enclave_result_t ta_path_to_uuid(const char *path, TEEC_UUID *uuid)
{
    const int pos_time_low = 0;
    const int pos_time_mid = 1;
    const int pos_time_hi_ver = 2;
    const int clock_pos01 = 3;
    const int clock_pos27 = 4;
    const int gp_token_nums = 5;
    const int clock_start = 2;
    const int clock_end = 7;
    const int unit = 8;
    const int uuid_base = 16;
    char uuid_str[UUID_LEN + 1] = {0};
    uint64_t uuid_split[gp_token_nums];

    const char *uuid_pos = NULL;
    cc_enclave_result_t res = extract_path(path, &uuid_pos);
    if (res != CC_SUCCESS) {
        return res;
    }
    memcpy(uuid_str, uuid_pos, UUID_LEN);
    char *ptr = uuid_str;
    int uuid_cnt = 0;
    for (; uuid_cnt < gp_token_nums && ptr < uuid_str + UUID_LEN; ++uuid_cnt) {
        if(uuid_cnt < 4) {
            uuid_split[uuid_cnt] = strtoull(ptr, &ptr, uuid_base);
            ++ptr;
        } else {
            uuid_split[uuid_cnt] = strtoull(ptr, NULL, uuid_base);
        }
    }
    if (uuid_cnt != gp_token_nums) {
        print_error_term("Path can not be converted into a valid uuid\n");
        return CC_FAIL;
    }

    uuid->timeLow = (uint32_t)uuid_split[pos_time_low];
    uuid->timeMid = (uint16_t)uuid_split[pos_time_mid];
    uuid->timeHiAndVersion = (uint16_t)uuid_split[pos_time_hi_ver];
    uuid->clockSeqAndNode[0] = (uint8_t)(uuid_split[clock_pos01] >> (unit * 1));
    uuid->clockSeqAndNode[1] = (uint8_t)(uuid_split[clock_pos01] >> (unit * 0));
    uint64_t tmp = uuid_split[clock_pos27];
    for (int i = clock_end; i >= clock_start; --i) {
        uuid->clockSeqAndNode[i] = (uint8_t)tmp;
        tmp >>= unit;
    }
    return CC_SUCCESS;
}

cc_enclave_result_t conversion_res_status(uint32_t enclave_res, enclave_type_version_t type_version)
{
    cc_enclave_result_t result_table1[] = {
        CC_SUCCESS,
        CC_ERROR_INVALID_CMD, CC_ERROR_SERVICE_NOT_EXIST, CC_ERROR_ENCLAVE_LOST,
        CC_ERROR_ENCLAVE_MAXIMUM, CC_ERROR_REGISTER_EXIST_SERVICE, CC_ERROR_TARGET_DEAD_FATAL,
        CC_ERROR_READ_DATA, CC_ERROR_WRITE_DATA, CC_ERROR_TRUNCATE_OBJECT, CC_ERROR_SEEK_DATA, CC_ERROR_SYNC_DATA,
        CC_ERROR_RENAME_OBJECT, CC_ERROR_INVALID_ENCLAVE,
    };

    cc_enclave_result_t result_table2[] = {
        CC_ERROR_GENERIC,
        CC_ERROR_ACCESS_DENIED, CC_ERROR_CANCEL, CC_ERROR_ACCESS_CONFLICT, CC_ERROR_EXCESS_DATA,
        CC_ERROR_BAD_FORMAT, CC_ERROR_BAD_PARAMETERS, CC_ERROR_BAD_STATE, CC_ERROR_ITEM_NOT_FOUND,
        CC_ERROR_NOT_IMPLEMENTED, CC_ERROR_NOT_SUPPORTED, CC_ERROR_NO_DATA, CC_ERROR_OUT_OF_MEMORY,
        CC_ERROR_BUSY, CC_ERROR_COMMUNICATION, CC_ERROR_SECURITY, CC_ERROR_SHORT_BUFFER
    };

    if (type_version != GP_ENCLAVE_TYPE_0) {
        print_error_term("The input type is not supported \n");
        return CC_FAIL;
    }
    switch (enclave_res) {
        case TEEC_ERROR_MAC_INVALID:
            return CC_ERROR_MAC_INVALID;
        case TEEC_ERROR_TARGET_DEAD:
            return CC_ERROR_TARGET_DEAD_FATAL;
        case TEEC_FAIL:
            return CC_FAIL;
        default:
            break;
    }
    const unsigned int res_table2_begin = 0xFFFF0000U;
    if (enclave_res < res_table2_begin) {
        if (enclave_res < sizeof(result_table1) / sizeof(cc_enclave_result_t)) {
            return result_table1[enclave_res];
        }
    } else {
        enclave_res -= res_table2_begin;
        if (enclave_res < sizeof(result_table2) / sizeof(cc_enclave_result_t)) {
            return result_table2[enclave_res];
        }
    }
    return CC_ERROR_UNEXPECTED;
}

static cc_ocall_func_t get_ocall_func(const cc_ocall_func_t *ocall_table, int num, int id)
{
    cc_ocall_func_t func;
    if (id >= num || id < 0) {
        print_error_term("Failed to get ocall funtion id\n");
        return NULL;
    }
    func = ocall_table[id];
    if (func == NULL) {
        print_error_term("Failed to get ocall function\n");
    }
    return func;
}

static bool malloc_and_copy(uint8_t ** const input, uint8_t ** const output, const void *ocall_buffer)
{
    cc_enclave_ocall_function_args_t *ocall_args = (cc_enclave_ocall_function_args_t *)ocall_buffer;
    size_t input_size = ocall_args->input_buffer_size;
    size_t output_size = ocall_args->output_buffer_size;
    uint8_t *pos = (uint8_t*)ocall_buffer + sizeof(cc_enclave_ocall_function_args_t);
    if (input_size > 0) {
        *input = (uint8_t*)malloc(input_size);
        if (!*input) {
            goto done;
        }
        memcpy(*input, pos, input_size);
    }
    pos += input_size;
    if (output_size > 0) {
        *output = (uint8_t*)malloc(output_size);
        if (!*output) {
            goto done;
        }
        memcpy(*output, pos, output_size);
    }
    return true;
done:
    if(*input) {
        free(*input);
    }
    if(*output) {
        free(*output);
    }
    *input = NULL;
    *output = NULL;
    return false;
}

static bool handle_ocall(uint32_t agent_id, int dev_fd, void *buffer, cc_ocall_func_t *ocalls, uint64_t num)
{
    bool ret = false;
    cc_enclave_result_t res_cc;
    TEEC_Result res_tee;

    res_tee = TEEC_EXT_WaitEvent(agent_id, dev_fd);
    if (res_tee != TEEC_SUCCESS) {
        print_error_term("Failed to wait event from TA!\n");
        return false;
    }

    cc_enclave_ocall_function_args_t args = *(cc_enclave_ocall_function_args_t *)buffer;
    cc_ocall_func_t func = get_ocall_func(ocalls, num, args.function_id);
    if (!func) {
        return false;
    }
    uint8_t *tmp_input_buffer = NULL;
    size_t   tmp_input_buffer_size = args.input_buffer_size;
    uint8_t *tmp_output_buffer = NULL;
    size_t   tmp_output_buffer_size = args.output_buffer_size;
    bool malloc_ok;
    malloc_ok = malloc_and_copy(&tmp_input_buffer, &tmp_output_buffer, buffer);
    if (!malloc_ok) {
        goto done;
    }
    res_cc = func(tmp_input_buffer, tmp_input_buffer_size, tmp_output_buffer, tmp_output_buffer_size);
    SECGEAR_CHECK_RES_NO_LOG(res_cc);

    if (tmp_output_buffer_size != 0) {
        if (MAX_LEN - sizeof(args) - tmp_input_buffer_size >= tmp_output_buffer_size) {
            memcpy((uint8_t *) buffer + sizeof(args) + tmp_input_buffer_size, tmp_output_buffer,
                   tmp_output_buffer_size);
        } else {
            print_error_goto("The output buffer is too large\n");
        }
    }

    res_tee = TEEC_EXT_SendEventResponse(agent_id, dev_fd);
    if (res_tee != TEEC_SUCCESS) {
        print_error_term("Failed to send response to TA\n");
        goto done;
    }
    ret = true;
done:
    if (tmp_input_buffer != NULL) {
        free(tmp_input_buffer);
        tmp_input_buffer = NULL;
    }
    if (tmp_output_buffer != NULL) {
        free(tmp_output_buffer);
        tmp_output_buffer = NULL;
    }
    
    return ret;
}

void *agent_thread(void *param) 
{
    int dev_fd = 0;
    int32_t ires;
    void *buffer = NULL;

    TEEC_Result ret;
    uint32_t agent_id = (uint32_t)((thread_param_t *)param)->agent_id;
    uint64_t num = ((thread_param_t *)param)->num;
    cc_ocall_func_t *ocalls  = (((thread_param_t *)param)->ocalls);
    ret = TEEC_EXT_RegisterAgent(agent_id, &dev_fd, &buffer);
    if (ret != TEEC_SUCCESS) {
        print_error_term("Failed to register agent %d\n", agent_id);
        goto done;
    }

    g_agent_info.agent_id = agent_id;
    g_agent_info.dev_fd = dev_fd;
    g_agent_info.c_buffer = buffer;

    ires = pthread_mutex_lock(&g_mtx_cond);
    SECGEAR_CHECK_MUTEX_RES(ires);

    g_agent_flag = OCALL_AGENT_REGISTER_SUCCESS;
    pthread_cond_broadcast(&g_cond);

    ires = pthread_mutex_unlock(&g_mtx_cond);
    SECGEAR_CHECK_MUTEX_RES(ires);

    bool ocall_success = true;
    while (ocall_success) {
        ocall_success = handle_ocall(agent_id, dev_fd, buffer, ocalls, num);
    }

    /* to do: ocall handle failure may secure exit */
    ret = TEEC_EXT_UnregisterAgent(agent_id, dev_fd, &buffer);
    if (ret != TEEC_SUCCESS) {
        print_error_term("Failed to unregister agent\n");
    }
    g_list_ops.pthread_flag = false;

    return NULL;
done:
    /* to do: need ocall agent support
     * acquire lock and set g_agent_flag to false
     */
    pthread_mutex_lock(&g_mtx_cond);
    g_agent_flag = OCALL_AGENT_REGISTER_FAIL;
    pthread_cond_broadcast(&g_cond);
    pthread_mutex_unlock(&g_mtx_cond);
    return NULL;
}

static cc_enclave_result_t malloc_and_init_context(gp_context_t **gp_context,
    const char *uuid_str, enclave_type_version_t type)
{
    cc_enclave_result_t res_cc;
    TEEC_Result res_tee;
    *gp_context = (gp_context_t *)calloc(1, sizeof(gp_context_t));
    if (*gp_context == NULL) {
        print_error_term("Memory out\n");
        return CC_ERROR_OUT_OF_MEMORY;
    }
    res_cc = ta_path_to_uuid(uuid_str, &(*gp_context)->uuid);
    if (res_cc != CC_SUCCESS) {
        goto cleanup;
    }
    res_tee = TEEC_InitializeContext(NULL, &(*gp_context)->ctx);
    if (res_tee != TEEC_SUCCESS) {
        res_cc = conversion_res_status(res_tee, type);
        print_error_term("GP context initialize failure\n");
        goto cleanup;
    }
    return CC_SUCCESS;
cleanup:
    free(*gp_context);
    *gp_context = NULL;
    return res_cc;
}

static void fini_context(gp_context_t *gp_context)
{
    if (gp_context != NULL) {
        TEEC_CloseSession(&gp_context->session);
        TEEC_FinalizeContext(&(gp_context->ctx));
        free(gp_context->sl_task_pool);
        free(gp_context);
    }
}

cc_enclave_result_t init_uswitchless(cc_enclave_t *enclave, const enclave_features_t *feature)
{
    gp_context_t *gp_ctx = (gp_context_t *)enclave->private_data;
    if (gp_ctx->sl_task_pool != NULL) {
        return CC_ERROR_SWITCHLESS_REINIT;
    }

    cc_sl_config_t cfg = *((cc_sl_config_t *)feature->feature_desc);
    if (!uswitchless_is_valid_config(&cfg)) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    uswitchless_adjust_config(&cfg);

    size_t pool_buf_len = sl_get_pool_buf_len_by_config(&cfg);
    void *pool_buf = gp_malloc_shared_memory(enclave, pool_buf_len, true);
    if (pool_buf == NULL) {
        return CC_ERROR_OUT_OF_MEMORY;
    }
    (void)memset(pool_buf, 0, pool_buf_len);

    // Fill config
    (void)memcpy(pool_buf, &cfg, sizeof(cc_sl_config_t));

    // Layout task pool
    sl_task_pool_t *pool = uswitchless_create_task_pool(pool_buf, &cfg);
    if (pool == NULL) {
        (void)gp_free_shared_memory(enclave, pool_buf);
        return CC_ERROR_OUT_OF_MEMORY;
    }

    // Registering a task pool
    cc_enclave_result_t ret = gp_register_shared_memory(enclave, pool_buf);
    if (ret != CC_SUCCESS) {
        free(pool);
        (void)gp_free_shared_memory(enclave, pool_buf);
        return ret;
    }

    gp_ctx->sl_task_pool = pool;
    return CC_SUCCESS;
}

void fini_uswitchless(cc_enclave_t *enclave)
{
    cc_enclave_result_t ret;
    gp_context_t *gp_ctx = (gp_context_t *)enclave->private_data;
    sl_task_pool_t *pool = gp_ctx->sl_task_pool;

    if (pool != NULL) {
        ret = gp_unregister_shared_memory(enclave, pool->pool_buf);
        if (ret != CC_SUCCESS) {
            print_error_term("finish uswitchless, failed to unregister task pool, ret=%d\n", ret);
        }
        (void)gp_free_shared_memory(enclave, pool->pool_buf);
        free(pool);
        gp_ctx->sl_task_pool = NULL;
    }
}

typedef cc_enclave_result_t (*func_init_feature)(cc_enclave_t *enclave, const enclave_features_t *feature);


static const struct {
    enclave_features_flag_t flag;
    func_init_feature init_func;
} g_gp_handle_feature_func_array[] = {
    {ENCLAVE_FEATURE_SWITCHLESS, init_uswitchless}
};

func_init_feature get_handle_feature_func(enclave_features_flag_t feature_flag)
{
    for (size_t i = 0; i < CC_ARRAY_LEN(g_gp_handle_feature_func_array); ++i) {
        if (g_gp_handle_feature_func_array[i].flag == feature_flag) {
            return g_gp_handle_feature_func_array[i].init_func;
        }
    }

    return NULL;
}

cc_enclave_result_t init_features(cc_enclave_t *enclave, const enclave_features_t *features, const uint32_t count)
{
    cc_enclave_result_t ret;
    func_init_feature init_func = NULL;

    for (uint32_t i = 0; i < count; ++i) {
        init_func = get_handle_feature_func((enclave_features_flag_t)features[i].setting_type);
        if (init_func == NULL) {
            return CC_ERROR_FEATURE_FUNC_NOT_EXIST;
        }

        ret = init_func(enclave, features + i);
        if (ret != CC_SUCCESS) {
            return ret;
        }
    }
 
    return CC_SUCCESS;
}

void fini_features(cc_enclave_t *enclave)
{
    fini_uswitchless(enclave);
}

/* itrustee enclave engine create func */
cc_enclave_result_t _gp_create(cc_enclave_t *enclave, const enclave_features_t *features, const uint32_t features_count)
{
    TEEC_Result result_tee;
    cc_enclave_result_t result_cc;

    if ((enclave == NULL) || (features_count > 0 && features == NULL)) {
        print_error_term("Context parameter error\n");
        return CC_ERROR_BAD_PARAMETERS;
    }

    gp_context_t *gp_context = NULL;
    result_cc = malloc_and_init_context(&gp_context, enclave->path, enclave->type);
    if (result_cc != CC_SUCCESS) {
        return result_cc;
    }

    /* filling operation */
    TEEC_Operation operation;
    memset(&operation, 0x00, sizeof(operation));
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);

    (gp_context->ctx).ta_path = (uint8_t*)enclave->path;

    uint32_t origin;
    result_tee = TEEC_OpenSession(&(gp_context->ctx), &(gp_context->session), &gp_context->uuid,
        TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    if (result_tee != TEEC_SUCCESS) {
        result_cc = conversion_res_status(result_tee, enclave->type);
        print_error_term("TEEC open session failed\n");
        goto cleanup;
    }
    enclave->private_data = (void *)gp_context;

    result_cc = init_features(enclave, features, features_count);
    if (result_cc != CC_SUCCESS) {
        goto cleanup;
    }

    return CC_SUCCESS;
cleanup:
    fini_context(gp_context);
    gp_context = NULL;
    enclave->private_data = NULL;
    return result_cc;
}

cc_enclave_result_t _gp_destroy(cc_enclave_t *context)
{
    int res;
    TEEC_Result ret;

    if (!context || !context->private_data) {
        print_error_term("The input parameters are wrong \n");
        return CC_ERROR_BAD_PARAMETERS;
    }

    fini_features(context);

    gp_context_t *tmp = (gp_context_t*)context->private_data;
    TEEC_CloseSession(&tmp->session);
    TEEC_FinalizeContext(&tmp->ctx);

    /* free enclave engine context memory */
    free(tmp);
    context->private_data = NULL;

    /* unregister agent */
    res = pthread_mutex_lock(&g_mtx_flag);
    SECGEAR_CHECK_MUTEX_RES(res);
    if(g_list_ops.pthread_flag == true && g_list_ops.enclaveState.enclave_count == 1) {
        g_list_ops.pthread_flag = false;
        g_agent_flag = OCALL_AGENT_REGISTER_FAIL;
        ret = TEEC_EXT_UnregisterAgent(g_agent_info.agent_id, g_agent_info.dev_fd, &g_agent_info.c_buffer);
        if (ret != TEEC_SUCCESS) {
            pthread_mutex_unlock(&g_mtx_flag);
            print_error_goto("Failed to unregister agent\n");
        }
    }
    res = pthread_mutex_unlock(&g_mtx_flag);
    SECGEAR_CHECK_MUTEX_RES(res);

    return CC_SUCCESS;

done:
    return CC_FAIL;
}

#define GET_HOST_BUF_FROM_INPUT_PARAMS(in_param_buf) \
    ({ \
        void *ptr = NULL; \
        (void)memcpy(&ptr, (char *)(in_param_buf) + size_to_aligned_size(sizeof(gp_register_shared_memory_size_t)), \
            sizeof(void *)); \
        ptr; \
    })

static cc_enclave_result_t init_operation(TEEC_Operation *operation, cc_enclave_call_function_args_t *args)
{
    const int input_pos = 0;
    const int output_pos = 1;
    const int inout_pos = 2;
    const int other_pos = 3;

    memset(operation, 0x00, sizeof(TEEC_Operation));
    operation->started = 1;
    uint32_t paramtypes[] = { TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE };
    /* Fill input buffer */
    if (args->input_buffer_size) {
        operation->params[input_pos].tmpref.buffer = (void *)args->input_buffer;
        operation->params[input_pos].tmpref.size = (uint32_t)args->input_buffer_size;
        paramtypes[input_pos] = TEEC_MEMREF_TEMP_INPUT;
    }
    /* Fill output buffer */
    if (args->output_buffer_size) {
        operation->params[output_pos].tmpref.buffer = (void *)args->output_buffer;
        operation->params[output_pos].tmpref.size = (uint32_t)args->output_buffer_size;
        paramtypes[output_pos] = TEEC_MEMREF_TEMP_OUTPUT;
    }
    operation->params[inout_pos].tmpref.buffer = args;
    operation->params[inout_pos].tmpref.size = sizeof(*args);
    paramtypes[inout_pos] = TEEC_MEMREF_TEMP_INOUT;

    /* Fill shared buffer */
    if (args->function_id == fid_register_shared_memory) {
        gp_shared_memory_t *shared_mem = GP_SHARED_MEMORY_ENTRY(GET_HOST_BUF_FROM_INPUT_PARAMS(args->input_buffer));
        TEEC_SharedMemory *teec_shared_mem = (TEEC_SharedMemory *)(&shared_mem->shared_mem);
        operation->params[other_pos].memref.parent = teec_shared_mem;
        operation->params[other_pos].memref.size = teec_shared_mem->size;
        paramtypes[other_pos] = TEEC_MEMREF_SHARED_INOUT;
    }

    operation->paramTypes = TEEC_PARAM_TYPES(
        paramtypes[input_pos], paramtypes[output_pos],
        paramtypes[inout_pos], paramtypes[other_pos]);
    return CC_SUCCESS;
}

void *handle_ecall_function_with_new_session(void *data)
{
    cc_enclave_call_function_args_t *args = (cc_enclave_call_function_args_t *)data;
    gp_context_t *gp = (gp_context_t *)(((cc_enclave_t *)args->enclave)->private_data);

    TEEC_Operation oper;
    memset(&oper, 0, sizeof(oper));
    oper.started = 1;
    oper.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);

    uint32_t origin;
    TEEC_Session session;
    TEEC_Result result = TEEC_OpenSession(&gp->ctx, &session, &gp->uuid, TEEC_LOGIN_IDENTIFY, NULL, &oper, &origin);
    if (result != TEEC_SUCCESS) {
        print_error_goto("Handle ecall with new session, failed to open session, ret:%x, origin:%x\n", result, origin);
    }

    cc_enclave_result_t cc_res = init_operation(&oper, args);
    if (cc_res != CC_SUCCESS) {
        TEEC_CloseSession(&session);
        print_error_goto("Handle ecall with new session, failed to init operation, ret:%x\n", cc_res);
    }

    result = TEEC_InvokeCommand(&session, SECGEAR_ECALL_FUNCTION, &oper, &origin);
    if (result != TEEC_SUCCESS || args->result != CC_SUCCESS) {
        TEEC_CloseSession(&session);
        print_error_goto("Handle ecall with new session, failed to invoke cmd, ret:%x\n", result);
    }

    TEEC_CloseSession(&session);

done:
    free(args);
    return NULL;
}

#define REGISTER_SHAREDMEM_GETTIME_PER_CNT 100000000
#define REGISTER_SHAREDMEM_TIMEOUT_IN_SEC 3

cc_enclave_result_t handle_ecall_function_register_shared_memory(cc_enclave_t *enclave,
                                                                 cc_enclave_call_function_args_t *args)
{
    CC_IGNORE(enclave);
    int count = 0;
    struct timespec start;
    struct timespec end;

    size_t buf_len = sizeof(cc_enclave_call_function_args_t) + args->input_buffer_size + args->output_buffer_size;
    char *buf = (char *)calloc(buf_len, sizeof(char));
    if (buf == NULL) {
        return CC_ERROR_OUT_OF_MEMORY;
    }

    /* Copy parameters */
    cc_enclave_call_function_args_t *tmpArgs = (cc_enclave_call_function_args_t *)buf;
    (void)memcpy(tmpArgs, args, sizeof(cc_enclave_call_function_args_t));

    tmpArgs->input_buffer = buf + sizeof(cc_enclave_call_function_args_t);
    (void)memcpy(buf + sizeof(cc_enclave_call_function_args_t), args->input_buffer, args->input_buffer_size);

    tmpArgs->output_buffer = buf + sizeof(cc_enclave_call_function_args_t) + args->input_buffer_size;
    (void)memcpy(buf + sizeof(cc_enclave_call_function_args_t) + args->input_buffer_size, args->output_buffer,
        args->output_buffer_size);

    gp_shared_memory_t *shared_mem = GP_SHARED_MEMORY_ENTRY(GET_HOST_BUF_FROM_INPUT_PARAMS(args->input_buffer));
    if (pthread_create(&shared_mem->register_tid, NULL, handle_ecall_function_with_new_session, tmpArgs) != 0) {
        free(buf);
        return CC_FAIL;
    }

    /* Waiting for registration success */
    clock_gettime(CLOCK_MONOTONIC_COARSE, &start);
    while (__atomic_load_n(&shared_mem->is_registered, __ATOMIC_ACQUIRE) == false) {
        __asm__ __volatile__("yield" : : : "memory");

        if (count > REGISTER_SHAREDMEM_GETTIME_PER_CNT) {
            clock_gettime(CLOCK_MONOTONIC_COARSE, &end);
            if (end.tv_sec - start.tv_sec > REGISTER_SHAREDMEM_TIMEOUT_IN_SEC) {
                return CC_ERROR_TIMEOUT;
            }
            count = 0;
        }
        ++count;
    }

    return CC_SUCCESS;
}

static cc_enclave_result_t handle_ecall_function(cc_enclave_t *enclave, cc_enclave_call_function_args_t *args)
{
    cc_enclave_result_t cc_res;
    TEEC_Result result;
    TEEC_Operation operation;
    uint32_t origin;
    gp_context_t *gp = (gp_context_t*)enclave->private_data;

    if (args->function_id == fid_register_shared_memory) {
        return handle_ecall_function_register_shared_memory(enclave, args);
    }

    cc_res = init_operation(&operation, args);
    if (cc_res != CC_SUCCESS) {
        goto done;
    }
    /* Perform the ECALL */
    result = TEEC_InvokeCommand(&gp->session, SECGEAR_ECALL_FUNCTION, &operation, &origin);
    if (result != TEEC_SUCCESS || args->result != CC_SUCCESS) {
        cc_res = conversion_res_status(result, enclave->type);
        print_error_term("invoke failed, codes=0x%x, origin=0x%x.\n", result, origin);
        goto done;
    }
    return CC_SUCCESS;
done:
    return cc_res;
}

static void create_thread(thread_param_t *param)
{
    int ret;
    pthread_t threads;
    pthread_attr_t attr;
    sigset_t set;
    sigemptyset(&set);
    sigfillset(&set);
    ret = pthread_sigmask(SIG_BLOCK, &set, NULL);
    if (ret) {
        print_error_term("pthread_sigmask Failed\n");
    }
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    ret = pthread_create(&threads, &attr, &agent_thread, param);
    if (ret) {
        print_error_term("Failed to create thread\n");
    }
    pthread_attr_destroy(&attr);
    g_list_ops.pthread_flag = true;
}

/* trustzone ecall , sgx call sgx_ecall */
cc_enclave_result_t cc_enclave_call_function(
    cc_enclave_t *enclave,
    uint32_t function_id,
    const void *input_buffer,
    size_t input_buffer_size,
    void *output_buffer,
    size_t output_buffer_size,
    void *ms,
    const void *ocall_table)
{
    cc_enclave_result_t result = CC_FAIL;
    cc_enclave_call_function_args_t args;
    thread_param_t param;
    int ires;

    /* enclave will not be invalid */
    if (!enclave) {
        result = CC_ERROR_INVALID_ENCLAVE;
        goto done;
    }

    /* for ocall thread */
    ires = pthread_mutex_lock(&g_mtx_flag);
    SECGEAR_CHECK_MUTEX_RES(ires);
    if (g_list_ops.pthread_flag || SECGEAR_OCALL) {
        param.agent_id = *(uint32_t *)ms;
        param.num = ((ocall_enclave_table_t *)ocall_table)->num;
        param.ocalls = ((ocall_enclave_table_t *)ocall_table)->ocalls;
        create_thread(&param);
        /* wait only when the registered agent thread is created successfully */
        if (!g_list_ops.pthread_flag) {
            pthread_mutex_unlock(&g_mtx_flag);
            goto done;
        }
        ires = pthread_mutex_lock(&g_mtx_cond);
        GP_CHECK_MUTEX_RES_UNLOCK(ires);
        pthread_cond_wait(&g_cond, &g_mtx_cond);
        /* the registration thread registration failed,
        *  need to try to register the next time ecall or exit directly
        *  to do : currently do not call*/
        if (g_agent_flag != OCALL_AGENT_REGISTER_SUCCESS) {
            g_list_ops.pthread_flag = false;
            result = CC_ERROR_OCALL_NOT_ALLOWED;
            pthread_mutex_unlock(&g_mtx_cond);
            pthread_mutex_unlock(&g_mtx_flag);
            print_error_goto("the registration thread registration ocall failed\n");
        }
        ires = pthread_mutex_unlock(&g_mtx_cond);
        GP_CHECK_MUTEX_RES_UNLOCK(ires);
    }
    ires = pthread_mutex_unlock(&g_mtx_flag);
    SECGEAR_CHECK_MUTEX_RES(ires);

    /* initialize the args */
    args.function_id = function_id;
    args.input_buffer = input_buffer;
    args.input_buffer_size = input_buffer_size;
    args.output_buffer = output_buffer;
    args.output_buffer_size = output_buffer_size;
    args.output_bytes_written = 0;
    args.result = CC_FAIL;
    args.enclave = enclave;
    result = handle_ecall_function(enclave, &args);
    if (result != CC_SUCCESS) {
        goto done;
    }

    result = CC_SUCCESS;
done:
    return result;
}

cc_enclave_result_t cc_sl_enclave_call_function(cc_enclave_t *enclave, void *retval, sl_ecall_func_info_t *func_info)
{
    if (!uswitchless_is_switchless_enabled(enclave)) {
        return CC_ERROR_SWITCHLESS_DISABLED;
    }

    if (!uswitchless_is_valid_param_num(enclave, func_info->argc)) {
        return CC_ERROR_SWITCHLESS_INVALID_ARG_NUM;
    }

    int task_index = uswitchless_get_idle_task_index(enclave);
    if (task_index < 0) {
        return CC_ERROR_SWITCHLESS_TASK_POOL_FULL;
    }

    uswitchless_fill_task(enclave, task_index, func_info->func_id, func_info->retval_size, func_info->argc,
        func_info->args);
    uswitchless_submit_task(enclave, task_index);
    cc_enclave_result_t ret = uswitchless_get_task_result(enclave, task_index, retval);
    uswitchless_put_idle_task_by_index(enclave, task_index);

    return ret;
}

cc_enclave_result_t cc_sl_async_ecall(cc_enclave_t *enclave, int *task_id, sl_ecall_func_info_t *func_info)
{
    if (task_id == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    if (!uswitchless_is_switchless_enabled(enclave)) {
        return CC_ERROR_SWITCHLESS_DISABLED;
    }

    if (!uswitchless_is_valid_param_num(enclave, func_info->argc)) {
        return CC_ERROR_SWITCHLESS_INVALID_ARG_NUM;
    }

    int task_index = uswitchless_get_idle_task_index(enclave);
    if (task_index < 0) {
        return CC_ERROR_SWITCHLESS_TASK_POOL_FULL;
    }

    uswitchless_fill_task(enclave, task_index, func_info->func_id, func_info->retval_size, func_info->argc,
        func_info->args);
    uswitchless_submit_task(enclave, task_index);
    *task_id = task_index;

    return CC_SUCCESS;
}

cc_enclave_result_t cc_sl_async_ecall_check_result(cc_enclave_t *enclave, int task_id, void *retval)
{
    if (!uswitchless_is_switchless_enabled(enclave)) {
        return CC_ERROR_SWITCHLESS_DISABLED;
    }

    if (!uswitchless_is_valid_task_index(enclave, task_id)) {
        return CC_ERROR_SWITCHLESS_INVALID_TASK_ID;
    }

    cc_enclave_result_t ret = uswitchless_get_async_task_result(enclave, task_id, retval);
    if (ret != CC_ERROR_SWITCHLESS_ASYNC_TASK_UNFINISHED) {
        uswitchless_put_idle_task_by_index(enclave, task_id);
    }

    return ret;
}

const struct cc_enclave_ops g_ops = {
    .cc_create_enclave  = _gp_create,
    .cc_destroy_enclave = _gp_destroy,
    .cc_ecall_enclave =  cc_enclave_call_function,
    .cc_sl_ecall_enclave = cc_sl_enclave_call_function,
    .cc_sl_async_ecall = cc_sl_async_ecall,
    .cc_sl_async_ecall_get_result = cc_sl_async_ecall_check_result,
    .cc_malloc_shared_memory = gp_malloc_shared_memory,
    .cc_free_shared_memory = gp_free_shared_memory,
    .cc_register_shared_memory = gp_register_shared_memory,
    .cc_unregister_shared_memory = gp_unregister_shared_memory
};

struct cc_enclave_ops_desc g_name = {
        .name = "gp",
        .ops = &g_ops,
        .type_version = GP_ENCLAVE_TYPE_0,
        .count = 0,
};

struct list_ops_desc g_node = {
        .ops_desc = &g_name,
        .next = NULL,
};


#define OPS_NAME g_name
#define OPS_NODE g_node
#define OPS_STRU g_ops

/* enclave engine registered */
cc_enclave_result_t cc_tee_registered(cc_enclave_t *context, void *handle)
{
    /* 1 check enclave type; 2-4 check node fill */
    size_t len = strlen(OPS_NAME.name);
    if (OPS_NAME.type_version != context->type || OPS_NODE.ops_desc != &OPS_NAME ||
        len >= MAX_ENGINE_NAME_LEN || OPS_NAME.ops != &OPS_STRU) {
        print_error_goto("The struct cc_enclave_ops_desc initialization error\n");
    }

    OPS_NAME.handle = handle;
    context->list_ops_node = &OPS_NODE;
    add_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
done:
    return CC_ERROR_BAD_PARAMETERS;
}

/* enclave engine unregistered */
cc_enclave_result_t cc_tee_unregistered(cc_enclave_t *context, enclave_type_version_t type_version)
{
    if (context == NULL || context->list_ops_node != &OPS_NODE || type_version != OPS_NAME.type_version) {
        print_error_goto("Engine parameter check error\n");
    }
    remove_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
done:
    return CC_ERROR_BAD_PARAMETERS;
}
