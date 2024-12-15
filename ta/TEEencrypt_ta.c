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
	IMSG("Goodbye!\n");
}

/*
 * 시저 암호를 사용하여 평문을 암호화하는 함수
 */
static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4]) {
    /* 파라미터 타입 정의 */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	DMSG("has been called");

    /* 파라미터 타입 검증 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a++;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4]) {
    /* 파라미터 타입 정의 */
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_VALUE_INOUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	DMSG("has been called");

    /* 파라미터 타입 검증 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}
/*
 * TA가 호출될 때 실행되며, cmd_id에 따라 적절한 함수를 호출
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
	// case TA_TEEencrypt_CMD_DEC_VALUE:
	// 	return dec_value(param_types, params);
	// case TA_TEEencrypt_CMD_RANDOMEKEY_GET:
	// 	return dec_value(param_types, params);
	// case TA_TEEencrypt_CMD_RANDOMEKEY_ENC:
	// 	return dec_value(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
