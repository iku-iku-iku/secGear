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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"

#define BUF_LEN 1024
#define REPORT_SIZE 328
void printHexsecGear(unsigned char *c, int n)
{
    int m = n / 16;
    int left = n - m * 16;
    char buf[33] = {0};
    char num;
    int top, below;
    printf("n: %d, m: %d, left: %d\n", n, m, left);
    for(int j = 0; j < m; j++){
        for(int i = 0; i < 16; i++){
            num = *(c + j*16 + i);
            top = (num >> 4) & 0xF;
            below = num & 0xF;
            buf[2 * i] = (top < 10 ? '0'+top : 'a'+top-10);
            buf[2 * i + 1] = (below < 10 ? '0'+below : 'a'+below-10);
        }
        buf[32] = '\0';
        printf("%d - %d: %s\n", j*16, j*16+15, buf);
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
        printf("%d - %d: %s\n", m*16, m*16+left-1, buf);
    }
}

int main(int argc, const char *argv[])
{
    struct sockaddr_in client_addr;
    int fd = 0;
    const SSL_METHOD *meth = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char buf[BUF_LEN] = {0};   
    int ret = -1;
    char report[REPORT_SIZE] = {0};
    
    if (argc != 3) {
        printf("usage: %s port ca_file\n", argv[0]);
        return -1;
    }
    printf("[client] Before SSL_load_error_strings()\n");
    SSL_load_error_strings();
    printf("[client] Before SSLeay_add_ssl_algorithms()\n");
    SSLeay_add_ssl_algorithms();
    meth = TLS_method();
    if (meth == NULL) {
        return -1;
    }
    printf("[client] Before SSL_CTX_new()\n");
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        return -1;
    }
    printf("[client] Before SSL_CTX_set_verify()\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    printf("[client] Before SSL_CTX_load_verify_locations()\n");
    if (SSL_CTX_load_verify_locations(ctx, argv[2], NULL) <= 0) {
        goto end;
    }
    printf("[client] Create client socket()\n");
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(atoi(argv[1]));
    client_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        goto end;
    } 
    printf("[client] connect to server\n");
    ret = connect(fd, (struct sockaddr *)&client_addr, sizeof(client_addr));
    if (ret < 0) {
        goto end;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        goto end;
    }
    
    SSL_set_fd(ssl, fd);

    printf("[client] Before SSL_connect()\n");
    if (SSL_connect(ssl) <= 0) {
        goto end;
    }
    printf("[client] After SSL_connect()\n");
    //get report
     if (SSL_read(ssl, report, REPORT_SIZE) <= 0) {
        goto end;
    }
    printf("receive report:");
    printHexsecGear(report, REPORT_SIZE);

    if (SSL_write(ssl, "hello enclave!", sizeof("hello enclave!")) <= 0) {
        goto end;
    }

    printf("send data: %s\n", "hello enclave!");
    if (SSL_read(ssl, buf, BUF_LEN - 1) <= 0) {
        goto end;
    }
    printf("receive data: %s\n", buf);
    ret = 0;

end:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (fd > 0) {
        close(fd);
    }
    return ret;
}
