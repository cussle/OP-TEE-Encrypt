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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>

/* TA의 루트 키 설정 */
#define ROOT_KEY 3

/*
 * TA가 생성될 때 호출되는 함수
 */
TEE_Result TA_CreateEntryPoint(void) {
	DMSG("has been called");
	return TEE_SUCCESS;
}

/*
 * TA가 파괴될 때 호출되는 함수
 */
void TA_DestroyEntryPoint(void) {
	DMSG("has been called");
}

/*
 * 새로운 세션이 열릴 때 호출되는 함수
 */
TEE_Result TA_OpenSessionEntryPoint(
	uint32_t param_types,
	TEE_Param __maybe_unused params[4],
	void __maybe_unused **sess_ctx
) {
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	DMSG("has been called");

    /* 파라미터 타입 검증 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

/*
 * 세션이 닫힐 때 호출되는 함수
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
	(void)&sess_ctx; /* Unused parameter */
}

/*
 * 시저 암호를 사용하여 평문을 암호화하는 함수
 * - param0: 평문 (입력, memref)
 * - param1: 암호문 (출력, memref)
 * - param2: 암호화된 키 (출력, value)
 */
static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4]) {
    /* 파라미터 타입 정의 */
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

	DMSG("has been called");

    /* 파라미터 타입 검증 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

    /* 입력 평문과 출력 암호문 버퍼*/
    char *plaintext = (char *)params[0].memref.buffer;
    size_t plaintext_size = params[0].memref.size;

    char *ciphertext = (char *)params[1].memref.buffer;
    size_t ciphertext_size = params[1].memref.size;

    /* 암호화된 키를 저장할 변수 */
    uint32_t encrypted_key;

    /* 랜덤 키 생성 */
    uint32_t rand_bytes;
    TEE_GenerateRandom(&rand_bytes, sizeof(rand_bytes));
    uint32_t rand_key = (rand_bytes % 25) + 1;  // 1~25 범위로 조정

    /* 시저 암호로 평문을 암호화 */
    for (size_t i = 0; i < plaintext_size; i++) {
        char c = plaintext[i];
        if ('a' <= c && c <= 'z') {
            ciphertext[i] = ((c - 'a') + rand_key) % 26 + 'a';
        }
        else if ('A' <= c && c <= 'Z') {
            ciphertext[i] = ((c - 'A') + rand_key) % 26 + 'A';
        }
        else {
            /* 알파벳이 아닌 문자 */
            ciphertext[i] = c;
        }
    }

    /* 암호화된 키 계산 - (랜덤 키 + 루트 키) % 26 */
    encrypted_key = (rand_key + ROOT_KEY) % 26;

    /* 암호문 버퍼 크기 확인 */
    if (ciphertext_size < plaintext_size) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    /* 암호화된 키를 param2에 저장 */
    params[2].value.a = encrypted_key;

    IMSG("암호화 완료: 랜덤 키 = %u, 암호화된 키 = %u", rand_key, encrypted_key);

    return TEE_SUCCESS;
}

/*
 * 시저 암호를 사용하여 암호문을 복호화하는 함수.
 * - param0: 암호문 (입력, memref)
 * - param1: 암호화된 키 (입력, value)
 * - param2: 복호화된 평문 (출력, memref)
 * - param3: 사용 안 함
 */
static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4]) {
    /* 예상되는 파라미터 타입 정의 */
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE
    );

    /* 파라미터 타입 검증 */
    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* 암호문과 암호화된 키 */
    char *ciphertext = (char *)params[0].memref.buffer;
    size_t ciphertext_size = params[0].memref.size;

    uint32_t encrypted_key = params[1].value.a;

    char *decrypted_plaintext = (char *)params[2].memref.buffer;
    size_t decrypted_size = params[2].memref.size;

    /* 암호화된 키로부터 원래의 랜덤 키 복호화 */
    uint32_t rand_key = (encrypted_key + 26 - ROOT_KEY) % 26;
    if (rand_key == 0) {
        rand_key = 26;
    }

    /* 시저 암호로 암호문을 복호화 */
    for (size_t i = 0; i < ciphertext_size; i++) {
        char c = ciphertext[i];
        if ('a' <= c && c <= 'z') {
            decrypted_plaintext[i] = ((c - 'a') + (26 - rand_key)) % 26 + 'a';
        }
        else if ('A' <= c && c <= 'Z') {
            decrypted_plaintext[i] = ((c - 'A') + (26 - rand_key)) % 26 + 'A';
        }
        else {
            /* 알파벳이 아닌 문자 */
            decrypted_plaintext[i] = c;
        }
    }

    /* 복호화된 평문 버퍼 크기 확인 */
    if (decrypted_size < ciphertext_size) {
        return TEE_ERROR_SHORT_BUFFER;
    }

    IMSG("복호화 완료: 복호화된 키 = %u", rand_key);

    return TEE_SUCCESS;
}

/*
 * TA가 호출될 때 실행되는 엔트리 포인트
 * - cmd_id에 따라 적절한 함수를 호출
 */
TEE_Result TA_InvokeCommandEntryPoint(
	void __maybe_unused *sess_ctx,
	uint32_t cmd_id,
	uint32_t param_types, TEE_Param params[4]
) {
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:  // 암호화 명령어 처리
		return enc_value(param_types, params);
    case TA_TEEencrypt_CMD_DEC_VALUE:  // 복호화 명령어 처리
        return dec_value(param_types, params);
	// case TA_TEEencrypt_CMD_RANDOMEKEY_GET:
	// 	return dec_value(param_types, params);
	// case TA_TEEencrypt_CMD_RANDOMEKEY_ENC:
	// 	return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
