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
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "tls_enclave_t.h"
#include "status.h"
#include "secgear_dataseal.h"
#include "print.h"

#define BUF_SIZE 1024
#define MAX_ENC_KEY_LEN 4096
#define ADD_DATA_RAW "add mac text"
#define REPORT_SIZE 328

void printHexsecGear(unsigned char *c, int n)
{
    int m = n / 16;
    int left = n - m * 16;
    char buf[33] = {0};
    char num;
    int top, below;
    eapp_print("n: %d, m: %d, left: %d", n, m, left);
    for(int j = 0; j < m; j++){
        for(int i = 0; i < 16; i++){
            num = *(c + j*16 + i);
            top = (num >> 4) & 0xF;
            below = num & 0xF;
            buf[2 * i] = (top < 10 ? '0'+top : 'a'+top-10);
            buf[2 * i + 1] = (below < 10 ? '0'+below : 'a'+below-10);
        }
        buf[32] = '\0';
        eapp_print("%d - %d: %s", j*16, j*16+15, buf);
    }
	if(left != 0){
        for(int i = 0; i < left; i++){
            num = *(c + m*16 + i);
            top = (num >> 4) & 0xF;
            below = num & 0xF;
            buf[2 * i] = (top < 10 ? '0'+top : 'a'+top-10);
            buf[2 * i + 1] = (below < 10 ? '0'+below : 'a'+below-10);
        }
        buf[2 * left] = '\0';
        eapp_print("%d - %d: %s", m*16, m*16+left-1, buf);
    }
}
/**
 * @brief Encrypts the RSA private key and fill into enc_buf
 * @param file_name 
 * @param file_name_len 
 * @param password 
 * @param pw_len 
 * @param enc_buf 
 * @param enc_buf_len 
 * @return sealed_data_len
 */
size_t seal_key(const char *file_name, size_t file_name_len, char *password, size_t pw_len, 
                char *enc_buf, size_t enc_buf_len)
{
    BIO *r_key = NULL;
    BIO *r_prikey = NULL;
    RSA *rsa_key = NULL;
    uint8_t *buf = NULL;
    uint32_t buf_len, sealed_data_len;
    int res = 0;
    int retval = CC_FAIL;

    if (file_name == NULL || file_name_len == 0 || password == NULL || pw_len == 0 || enc_buf == NULL) {
        return 0;
    }
    eapp_print("[seal_key] Before BIO_new_file()\n");
    r_key = BIO_new_file(file_name, "r");
    if (r_key == NULL) {
        goto end;
    };
    rsa_key = PEM_read_bio_RSAPrivateKey(r_key, NULL, NULL, password);
    if (rsa_key == NULL) {
        goto end;
    };
    r_prikey = BIO_new(BIO_s_mem());
    if (r_prikey == NULL) {
        goto end;
    }
    if (!PEM_write_bio_RSAPrivateKey(r_prikey, rsa_key, NULL, NULL, 0, NULL, NULL)) {
        goto end;
    }

    buf_len = BIO_ctrl_pending(r_prikey);
    if (buf_len == 0) {
        goto end;
    }
    eapp_print("[seal_key] Before malloc()\n");
    buf = (uint8_t *)malloc(buf_len);
    if (buf == NULL) {
        goto end;
    }
    eapp_print("[seal_key] Before BIO_read()\n");
    if ((size_t)BIO_read(r_prikey, buf, buf_len) != buf_len) {
        goto end;
    }
    eapp_print("[seal_key] Before cc_enclave_get_sealed_data_size()\n");
    sealed_data_len = cc_enclave_get_sealed_data_size(strlen((const char *)ADD_DATA_RAW),buf_len);//TODO: Change order？
    if (sealed_data_len == UINT32_MAX || enc_buf_len < sealed_data_len) {
        goto end;
    }
    retval = cc_enclave_seal_data((uint8_t *)buf, buf_len, (cc_enclave_sealed_data_t *)enc_buf, enc_buf_len, 
                                  (uint8_t*)ADD_DATA_RAW, strlen((const char*)ADD_DATA_RAW));
    if (retval != CC_SUCCESS) {
        goto end;
    }

    /******** prepare to unseal data ***********/
    uint32_t encrypt_add_len = cc_enclave_get_add_text_size((const cc_enclave_sealed_data_t *)enc_buf);
    uint32_t encrypt_data_len = cc_enclave_get_encrypted_text_size((const cc_enclave_sealed_data_t *)enc_buf);

    uint8_t *decrypted_seal_data = malloc(encrypt_data_len);
    if (decrypted_seal_data == NULL) {
        retval = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    uint8_t *demac_data = malloc(encrypt_add_len);
    if (demac_data == NULL) {
        retval = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    eapp_print("-----  start unseal  -----");
    retval = cc_enclave_unseal_data((const cc_enclave_sealed_data_t *)enc_buf,
        decrypted_seal_data, &encrypt_data_len, demac_data, &encrypt_add_len);
    if (retval != CC_SUCCESS) {
        eapp_print("!!!!!-----  unseal error  -----!!!!!");
    } else {
        eapp_print("unseal return succ");
    }
    eapp_print("-----  start check unseal out  -----");
    for(int i = 0; i < encrypt_data_len; i++){
        if(decrypted_seal_data[i] != buf[i])
            eapp_print("[seal_key]byte %d changed, before: %c, after: %c", i, buf[i], decrypted_seal_data[i]);
    }
    res = sealed_data_len;

    // eapp_print("[seal_key] sealed_data_len: %d\n", sealed_data_len);
    // eapp_print("[seal_key] sealed_data content:");
    // printHexsecGear((unsigned char *)enc_buf, sealed_data_len);
end:
    eapp_print("[seal_key] Before end() res:%d\n",res);
    BIO_free(r_key);
    BIO_free(r_prikey);
    RSA_free(rsa_key);
    if (buf != NULL) {
        memset(buf, 0, buf_len);
        free(buf);
    };
    memset(password, 0, pw_len);
    return res;
}

int unseal_enc_data(char **data_p, size_t *data_len_p, const char *enc_data)
{
    BIO *r_key = NULL;
    BIO *r_prikey = NULL;
    RSA *rsa_key = NULL;
    uint8_t *buf = NULL;//server.key content
    uint32_t buf_len, sealed_data_len;
    int res = 0;
    int retval = CC_FAIL;

    char *file_name = "server.key";
    size_t file_name_len = strlen(file_name);
    char *password = "12345";
    size_t pw_len = strlen(password);
    char *enc_buf = malloc(4096);//server.key sealed
    size_t enc_buf_len = 4096;
    if (file_name == NULL || file_name_len == 0 || password == NULL || pw_len == 0 || enc_buf == NULL) {
        return 0;
    }
    eapp_print("[unseal_enc_data] Before BIO_new_file()\n");
    r_key = BIO_new_file(file_name, "r");
    if (r_key == NULL) {
        goto end;
    };
    eapp_print("[unseal_enc_data] Before PEM_read_bio_RSAPrivateKey()\n");
    rsa_key = PEM_read_bio_RSAPrivateKey(r_key, NULL, NULL, password);
    if (rsa_key == NULL) {
        goto end;
    };
    eapp_print("[unseal_enc_data] Before BIO_new()\n");
    r_prikey = BIO_new(BIO_s_mem());
    if (r_prikey == NULL) {
        goto end;
    }
    eapp_print("[unseal_enc_data] Before PEM_write_bio_RSAPrivateKey()\n");
    if (!PEM_write_bio_RSAPrivateKey(r_prikey, rsa_key, NULL, NULL, 0, NULL, NULL)) {
        goto end;
    }
    eapp_print("[unseal_enc_data] Before BIO_ctrl_pending()\n");
    buf_len = BIO_ctrl_pending(r_prikey);
    if (buf_len == 0) {
        goto end;
    }
    eapp_print("[unseal_enc_data] Before malloc()\n");
    buf = (uint8_t *)malloc(buf_len);
    if (buf == NULL) {
        goto end;
    }
    eapp_print("[unseal_enc_data] Before BIO_read()\n");
    if ((size_t)BIO_read(r_prikey, buf, buf_len) != buf_len) {
        goto end;
    }
    eapp_print("[unseal_enc_data] Before cc_enclave_get_sealed_data_size()\n");
    sealed_data_len = cc_enclave_get_sealed_data_size(strlen((const char *)ADD_DATA_RAW),buf_len);//TODO: Change order?
    if (sealed_data_len == UINT32_MAX || enc_buf_len < sealed_data_len) {
        goto end;
    }
    retval = cc_enclave_seal_data((uint8_t *)buf, buf_len, (cc_enclave_sealed_data_t *)enc_buf, enc_buf_len, 
                                  (uint8_t*)ADD_DATA_RAW, strlen((const char*)ADD_DATA_RAW));
    if (retval != CC_SUCCESS) {
        goto end;
    }
    /******** prepare to unseal data ***********/
    uint32_t encrypt_add_len = cc_enclave_get_add_text_size((const cc_enclave_sealed_data_t *)enc_buf);
    uint32_t encrypt_data_len = cc_enclave_get_encrypted_text_size((const cc_enclave_sealed_data_t *)enc_buf);

    uint8_t *decrypted_seal_data = malloc(encrypt_data_len);//seal server.key
    if (decrypted_seal_data == NULL) {
        retval = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    uint8_t *demac_data = malloc(encrypt_add_len);
    if (demac_data == NULL) {
        retval = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    eapp_print("-----  start unseal  -----");
    retval = cc_enclave_unseal_data((cc_enclave_sealed_data_t *)enc_buf,
        decrypted_seal_data, &encrypt_data_len, demac_data, &encrypt_add_len);
    if (retval != CC_SUCCESS) {
        eapp_print("!!!!!-----  unseal error  -----!!!!!");
    } else {
        eapp_print("unseal return succ");
    }
    eapp_print("-----  start check unseal out  -----");
    for(int i = 0; i < encrypt_data_len; i++){
        if(decrypted_seal_data[i] != buf[i])
            eapp_print("byte %d changed, before: %c, after: %c", i, buf[i], decrypted_seal_data[i]);
    }
    eapp_print("ADD_DATA:%s \n", demac_data);
    char *add_data = NULL;//enc_key unsealed length
    char *data = NULL;  //enc_key unsealed
    size_t add_len = 0;
    size_t data_len = 0;
    // int retval = CC_FAIL;
    //暂时取消check,两次运行sealed_data不一样
    // eapp_print("- - - - -");
    // eapp_print("- - - - -");
    // eapp_print("- - - - -");
    // eapp_print("- - - check - - -");
    // for(int i = 0; i < sealed_data_len; i++){
    //     if(enc_data[i] != enc_buf[i])
    //         eapp_print("byte %d changed, true: %c, false: %c", i, enc_buf[i], enc_data[i]);
    // }
    // eapp_print("ADD_DATA:%s \n", demac_data);
    // eapp_print("end check");
    add_len = cc_enclave_get_add_text_size((const cc_enclave_sealed_data_t *)enc_data);
    data_len = cc_enclave_get_encrypted_text_size((const cc_enclave_sealed_data_t *)enc_data);
    if (data_len == 0 || add_len != strlen((const char*)ADD_DATA_RAW)) {
        return CC_FAIL;
    }
    data = malloc(data_len);
    add_data = malloc(add_len);
    if (data == NULL || add_data == NULL) {
        goto end;
    }
    memset(data, 0, data_len);
    retval = cc_enclave_unseal_data((cc_enclave_sealed_data_t *)enc_data, (uint8_t *)data, (uint32_t *)&data_len,
                                    (uint8_t *)add_data, (uint32_t *)&add_len);
    if (retval != CC_SUCCESS) {
        goto end;
    }
    if (strncmp((const char *)add_data, (const char*)ADD_DATA_RAW, strlen((const char*)ADD_DATA_RAW)) != 0) {
        retval = CC_FAIL;
        goto end;
    }
    *data_p = data;
    *data_len_p = data_len;
    retval = CC_SUCCESS;

end:
    if (add_data != NULL) { 
        memset(add_data, 0, add_len);
        free(add_data);
    }
    if (retval != CC_SUCCESS && data != NULL) {
        memset(data, 0, data_len);
        free(data);
    }
    return retval;
}

int set_ctx_key(SSL_CTX *ctx, const char *enc_key_file_name)
{
    BIO *in_bio = NULL;
    EVP_PKEY *pkey = NULL;
    char *raw_key = NULL;
    size_t raw_key_len = 0;
    BIO *key_bio = NULL;
    char *enc_key = NULL;
    int retval = CC_FAIL;
    int res = CC_FAIL;

    key_bio = BIO_new_file(enc_key_file_name, "r");
    if (key_bio == NULL) {
        goto end;
    };
    enc_key = (char *)malloc(MAX_ENC_KEY_LEN);
    if (enc_key == NULL) {
        goto end;
    }
    eapp_print("[set_ctx_key] Before BIO_read()\n");
    if (BIO_read(key_bio, enc_key, MAX_ENC_KEY_LEN) <= 0) {
        goto end;
    }
    // eapp_print("[set_ctx_key] sealed_data content in file:");
    // printHexsecGear((unsigned char *)enc_key, MAX_ENC_KEY_LEN);
    eapp_print("[set_ctx_key] Before unseal_enc_data()\n");
    res = unseal_enc_data(&raw_key, &raw_key_len, enc_key);
    if (res != CC_SUCCESS || raw_key_len == 0) {
        goto end;
    }
    eapp_print("[set_ctx_key] Before BIO_new_mem_buf()\n");
    in_bio = BIO_new_mem_buf(raw_key, raw_key_len);
    if (in_bio == NULL) {
        goto end;
    }
    eapp_print("[set_ctx_key] Before PEM_read_bio_PrivateKey()\n");
    pkey = PEM_read_bio_PrivateKey(in_bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        goto end;
    }
    eapp_print("[set_ctx_key] Before SSL_CTX_use_PrivateKey()\n");
    if (!SSL_CTX_use_PrivateKey(ctx, pkey)) {
        goto end;
    }
    retval = CC_SUCCESS;

end: 
    eapp_print("[set_ctx_key] end: res: %d\n", res);
    EVP_PKEY_free(pkey);
    BIO_free(in_bio);
    BIO_free(key_bio);
    if (enc_key != NULL) {
        free(enc_key);
    }
    if (raw_key != NULL) {
        memset(raw_key, 0, raw_key_len);
        free(raw_key);
    }
    return retval;
}

int start_enclave_tls(int client_fd,const char *cert, size_t cert_len, const char *enc_key, size_t enc_key_len,const char *report, size_t report_szie)
{
    char buf[BUF_SIZE] = {0};
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int res = 0;
    int retval = CC_FAIL;

    if (client_fd <= 0 || cert == NULL || cert_len == 0 || enc_key == NULL || enc_key_len == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = TLS_method();
    if (meth == NULL) {
        return CC_FAIL;
    }
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        return CC_FAIL;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        goto end;
    }
    //Set the encrypted key enc_key to the SSL context
    if (set_ctx_key(ctx, enc_key) != CC_SUCCESS){
        goto end;
    }
    //Check if the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        goto end;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto end;
    }
    SSL_set_fd(ssl, client_fd);
    if (SSL_set_cipher_list(ssl, "ECDHE-RSA-AES128-GCM-SHA256") != 1) {
        goto end;
    }
    //TLS handshake
    if (SSL_accept(ssl) <= 0) {
        goto end;
    }
    //send attest report
    eapp_print("print report:");
    printHexsecGear(report,REPORT_SIZE);
    if (SSL_write(ssl, report, REPORT_SIZE) <= 0)
    {
        goto end;
    }
    eapp_print("[start_enclave_tls] Before SSL_read()\n");
    //read "hello enclave!" from client
    res = SSL_read(ssl, buf, BUF_SIZE -1); 
    if (res <= 0) {
        goto end;
    }
    eapp_print("[start_enclave_tls] Before SSL_write()\n");
    if (SSL_write(ssl, buf, res) <= 0) {
        goto end;
    }
    retval = CC_SUCCESS;

end:
    eapp_print("[start_enclave_tls] In end\n");
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    memset(buf, 0, BUF_SIZE);
    return retval;
}
