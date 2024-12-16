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
#define ROOT_KEY 1

/* RSA 설정 */
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

/* RSA 세션 구조체 */
struct rsa_session {
    TEE_OperationHandle op_handle;    /* RSA operation */
    TEE_ObjectHandle key_handle;      /* Key handle */
};

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
	void __maybe_unused **session
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

	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;

	*session = (void *)sess;
	DMSG("\nSession %p: newly allocated\n", *session);

	return TEE_SUCCESS;
}

/*
 * 세션이 닫힐 때 호출되는 함수
 */
void TA_CloseSessionEntryPoint(void *session)
{
	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);
	sess = (struct rsa_session *)session;

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);
	TEE_Free(sess);
}

/* RSA 암호화 관련 함수 */
TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

/*
 * 시저 암호를 사용하여 평문을 암호화하는 함수
 * - param0: 평문 (입력, memref)
 * - param1: 암호문 (출력, memref)
 * - param2: 암호화된 키 (출력, value)
 * - param3: 사용 안 함
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
 * RSA 키 쌍 생성 함수
 */
TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

/*
 * RSA를 사용하여 평문을 암호화하는 함수
 * - param0: 평문 (입력, memref)
 * - param1: 암호문 (출력, memref)
 * - param2: 사용 안 함
 * - param3: 사용 안 함
 */
TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

/*
 * 시저 암호를 사용하여 암호문을 복호화하는 함수
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
	void *session,
	uint32_t cmd_id,
	uint32_t param_types,
    TEE_Param params[4]
) {
	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE:  // 암호화 명령어 처리
		return enc_value(param_types, params);
    case TA_TEEencrypt_CMD_DEC_VALUE:  // 복호화 명령어 처리
        return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RSA_GENKEYS:  // RSA 키 생성 명령어 처리
		return RSA_create_key_pair(session);
	case TA_TEEencrypt_CMD_RSA_ENCRYPT:  // RSA 암호화 명령어 처리
		return RSA_encrypt(session, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
