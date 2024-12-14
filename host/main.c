/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

// 텍스트 파일 이름 정의
#define CIPHERTEXT_FILE "ciphertext.txt" 		// 암호문 출력 파일
#define ENCRYPTED_KEY_FILE "encryptedkey.txt" 	// 암호화된 키 파일

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
    FILE *fin, *fout;		// 파일 입출력 포인터
    char *plaintext;		// 동적 할당 평문 버퍼
    size_t file_size;		// 입력된 평문 파일의 총 바이트

    // 커맨드 인자 확인
    if (argc != 3 || strcmp(argv[1], "-e") != 0) {
        printf("사용법: %s -e [평문 파일 이름]\n", argv[0]);
        return 1;
    }

	// TEE 컨텍스트 초기화
	res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InitializeContext 실패, 코드: 0x%x", res);

    // TA와 세션 열기
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_OpenSession 실패, 코드: 0x%x, 원인: 0x%x", res, err_origin);

	// 평문 파일 읽기
    fin = fopen(argv[2], "r");
    if (!fin) {
        perror("파일 열기 오류");
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    // 파일 크기 확인 및 메모리 할당
    fseek(fin, 0, SEEK_END);
    file_size = ftell(fin);
    rewind(fin);

    plaintext = malloc(file_size + 1);
    if (!plaintext) {
        perror("메모리 할당 오류");
        fclose(fin);
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

	fread(plaintext, 1, file_size, fin);
    plaintext[file_size] = '\0';
    fclose(fin);

	// 암호화 작업 설정
    char *ciphertext = malloc(file_size + 1);
    char *encrypted_key = malloc(file_size + 1);

    if (!ciphertext || !encrypted_key) {
        perror("메모리 할당 오류");
        free(plaintext);
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);
        return 1;
    }

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
    op.params[0].tmpref.buffer = plaintext;
    op.params[0].tmpref.size = file_size;
    op.params[1].tmpref.buffer = ciphertext;
    op.params[1].tmpref.size = file_size;
    op.params[2].tmpref.buffer = encrypted_key;
    op.params[2].tmpref.size = file_size;

	// 암호화 명령 실행
	printf("======================== Encryption ========================\n");
    res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
    if (res != TEEC_SUCCESS)
        errx(1, "TEEC_InvokeCommand 실패, 코드: 0x%x, 원인: 0x%x", res, err_origin);

    // 암호문 파일 쓰기
    fout = fopen(CIPHERTEXT_FILE, "w");
    if (!fout) {
        perror("암호문 파일 쓰기 오류");
    } else {
        fputs(ciphertext, fout);
        fclose(fout);
    }

    // 암호화된 키 파일 쓰기
    fout = fopen(ENCRYPTED_KEY_FILE, "w");
    if (!fout) {
        perror("암호화된 키 파일 쓰기 오류");
    } else {
        fputs(encrypted_key, fout);
        fclose(fout);
    }

	// res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
	// 			 &err_origin);
	// res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMEKEY_GET, &op,
	// 			 &err_origin);
	// res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMEKEY_ENC, &op,
	// 			 &err_origin);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
