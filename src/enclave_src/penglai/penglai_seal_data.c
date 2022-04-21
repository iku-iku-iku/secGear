/*
 * Copyright (c) IPADS@SJTU 2021. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "status.h"
#include "seal.h"
#include "dataseal_internal.h"


uint32_t get_sealed_data_size_ex(uint32_t aad_len, uint32_t seal_data_len)
{
    return penglai_calc_sealed_data_size(aad_len, seal_data_len);
}

uint32_t get_encrypted_text_size_ex(const void *sealed_data)
{
    const penglai_sealed_data_t *real_sealed_data = (const penglai_sealed_data_t *)sealed_data;
    return penglai_get_encrypt_txt_len(real_sealed_data);
}

uint32_t get_add_text_size_ex(const void *sealed_data)
{
    const penglai_sealed_data_t *real_sealed_data = (const penglai_sealed_data_t *)sealed_data;
    return penglai_get_add_mac_txt_len(real_sealed_data);
}

uint32_t internel_penglai_seal_data(uint8_t *seal_data, uint32_t seal_data_len,
    void *sealed_data, uint32_t sealed_data_len, uint8_t *mac_data, uint32_t mac_data_len)
{
    int result;
    penglai_sealed_data_t *real_sealed_data = (penglai_sealed_data_t *)sealed_data;
    result = penglai_seal_data(mac_data_len, mac_data, seal_data_len, seal_data, sealed_data_len, real_sealed_data);
    return result;
}

uint32_t internel_penglai_unseal_data(void *sealed_data, uint8_t *decrypted_data,
    uint32_t *decrypted_data_len,uint8_t *mac_data, uint32_t *mac_data_len)
{
    int result;
    penglai_sealed_data_t *real_sealed_data = (penglai_sealed_data_t *)sealed_data;
    result = penglai_unseal_data(real_sealed_data, mac_data, mac_data_len, decrypted_data, decrypted_data_len);
    return result;
}
