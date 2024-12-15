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

int main(void)
{
	TEEC_Result res;						// OP-TEE 함수 호출 결과
	TEEC_Context ctx;						// OP-TEE 컨텍스트
	TEEC_Session sess;						// OP-TEE 세션
	TEEC_Operation op;						// OP-TEE 연산 구조체
	TEEC_UUID uuid = TA_TEEencrypt_UUID;	// TA의 UUID 설정
	uint32_t err_origin;					// 오류 원인

    /* 명령어 및 파일 인자 확인 */
    if (argc != 3) {
        fprintf(stderr, "사용법: %s -e [평문 파일]\n", argv[0]);
        return 1;
    }

    /* 암호화 명령어 옵션 확인 */
    if (strcmp(argv[1], "-e") != 0) {
        fprintf(stderr, "지원되지 않는 명령어입니다. 사용 가능한 옵션: -e\n");
        return 1;
    }

    /* OP-TEE 컨텍스트 초기화 */
	res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext 실패: 0x%x", res);
    }

    /* TA와 세션 열기 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&ctx);
        errx(1, "TEEC_OpenSession 실패: 0x%x, 원인: 0x%x", res, err_origin);
    }

    /* TEEC_Operation 구조체 초기화 */
	memset(&op, 0, sizeof(op));

	/* 파라미터 타입 설정 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 42;

    /* TA 명령어 호출 */
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMEKEY_GET, &op,
				 &err_origin);
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMEKEY_ENC, &op,
				 &err_origin);

    /* 세션 및 컨텍스트 종료 */
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
