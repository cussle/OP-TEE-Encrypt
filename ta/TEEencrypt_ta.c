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

#include <tee_internal_api.h>				// OP-TEE 내부 API를 사용하기 위한 헤더 파일
#include <tee_internal_api_extensions.h>	// OP-TEE 확장 API를 사용하기 위한 헤더 파일
#include <TEEencrypt_ta.h>					// TA(Trusted Application)의 헤더 파일
#include <string.h>							// 문자열 관련 함수들을 사용하기 위한 헤더 파일

/* TA의 루트 키 설정 */
#define ROOT_KEY 1

/* RSA 설정 */
#define RSA_KEY_SIZE 1024						// RSA 암호화에 사용할 키의 크기
#define RSA_MAX_PLAIN_LEN_1024 86				// RSA 1024비트 키를 사용할 때 암호화할 수 있는 최대 평문의 길이를 86자로 제한
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)	// RSA 암호문의 길이(키 크기를 8로 나눈 값)

/* RSA 세션 구조체 */
struct rsa_session {
    TEE_OperationHandle op_handle;    /* RSA operation */
    TEE_ObjectHandle key_handle;      /* Key handle */
};

/*
 * TA가 생성될 때 호출되는 함수
 */
TEE_Result TA_CreateEntryPoint(void) {
	DMSG("has been called");  // 디버그 메시지 출력
	return TEE_SUCCESS;  // 초기화가 성공적으로 완료되었음을 반환
}

/*
 * TA가 파괴될 때 호출되는 함수
 */
void TA_DestroyEntryPoint(void) {
	DMSG("has been called");  // 디버그 메시지 출력
}

/*
 * 새로운 세션이 열릴 때 호출되는 함수
 */
TEE_Result TA_OpenSessionEntryPoint(
	uint32_t param_types,
	TEE_Param __maybe_unused params[4],
	void __maybe_unused **session
) {
	// 예상되는 파라미터 타입을 정의
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	DMSG("has been called");  // 디버그 메시지 출력

    /* 파라미터 타입 검증 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;  // 전달된 파라미터 타입이 예상과 다르면 오류 반환

	// RSA 세션 구조체를 위한 메모리 할당
	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);  // 메모리를 동적으로 할당
	if (!sess)
		return TEE_ERROR_OUT_OF_MEMORY;  // 메모리 할당에 실패하면 오류 반환

	// 세션 핸들을 초기화
	sess->key_handle = TEE_HANDLE_NULL;  // 키 핸들을 NULL로 설정
	sess->op_handle = TEE_HANDLE_NULL;  // 연산 핸들을 NULL로 설정

	*session = (void *)sess;  // 세션 포인터에 할당된 구조체의 주소 저장
	DMSG("\nSession %p: newly allocated\n", *session);  // 세션이 새로 할당되었음을 출력

	return TEE_SUCCESS;  // 성공적으로 세션을 열었음을 반환
}

/*
 * 세션이 닫힐 때 호출되는 함수
 */
void TA_CloseSessionEntryPoint(void *session)
{
	struct rsa_session *sess;

	/* Get ciphering context from session ID */
	DMSG("Session %p: release session", session);  // 세션 해제를 출력
	sess = (struct rsa_session *)session;  // 전달된 세션 포인터를 rsa_session 구조체 포인터로 변환

	/* Release the session resources
	   These tests are mandatories to avoid PANIC TA (TEE_HANDLE_NULL) */
	if (sess->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(sess->key_handle);  // 키 핸들을 해제
	if (sess->op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(sess->op_handle);  // 연산 핸들을 해제
	TEE_Free(sess);  // 세션 구조체 해제
}

/*
 * RSA 연산을 준비하는 함수
 * - handle: 연산 핸들을 저장할 포인터
 * - alg: 사용할 알고리즘 (예: RSA)
 * - mode: 연산 모드 (암호화/복호화)
 * - key: 사용할 키의 핸들
 */
TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key) {
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;

	// 키에 대한 정보
	ret = TEE_GetObjectInfo1(key, &key_info);  // 키 객체의 정보
	if (ret != TEE_SUCCESS) {
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, ret);  // 오류 메시지 출력
		return ret;  // 오류가 발생하면 해당 오류 코드 반환
	}

	// 연산 핸들 할당
	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);  // 지정된 알고리즘과 모드로 연산 할당
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);  // 오류 메시지 출력
		return ret;  // 오류가 발생하면 해당 오류 코드 반환
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	// 연산에 키를 설정
	ret = TEE_SetOperationKey(*handle, key);  // 할당된 연산 핸들에 키 설정
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);  // 오류 메시지 출력
		return ret;  // 오류가 발생하면 해당 오류 코드 반환
	}
    DMSG("\n========== Operation key already set. ==========\n");

	return ret;  // 성공적으로 준비되었음을 반환
}

/*
 * 파라미터 타입을 확인하는 함수
 * 예상되는 파라미터 타입과 실제 파라미터 타입을 비교합니다.
 */
TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,  // 입력 메모리 참조 (평문)
		TEE_PARAM_TYPE_MEMREF_OUTPUT,  // 출력 메모리 참조 (암호문)
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;  // 파라미터가 예상과 다르면 오류 반환
	return TEE_SUCCESS;  // 파라미터가 유효하면 성공을 반환
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

	DMSG("has been called");  // 함수가 호출되었음을 출력

    /* 파라미터 타입 검증 */
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;  // 파라미터가 예상과 다르면 오류 반환

    /* 입력 평문과 출력 암호문 버퍼*/
    char *plaintext = (char *)params[0].memref.buffer;  // 평문 데이터의 시작 주소
    size_t plaintext_size = params[0].memref.size;  // 평문 데이터의 크기

    char *ciphertext = (char *)params[1].memref.buffer;  // 암호문 데이터가 저장될 버퍼의 시작 주소
    size_t ciphertext_size = params[1].memref.size;  

    /* 암호화된 키를 저장할 변수 */
    uint32_t encrypted_key;

    /* 랜덤 키 생성 */
    uint32_t rand_bytes;
    TEE_GenerateRandom(&rand_bytes, sizeof(rand_bytes));  // 랜덤한 바이트를 생성하여 rand_bytes에 저장
    uint32_t rand_key = (rand_bytes % 25) + 1;  // 1~25 범위로 조정

    /* 시저 암호로 평문을 암호화 */
    for (size_t i = 0; i < plaintext_size; i++) {  // 평문의 모든 문자에 대해 반복
        char c = plaintext[i];  // 현재 문자
        if ('a' <= c && c <= 'z') {  // 소문자인 경우
            ciphertext[i] = ((c - 'a') + rand_key) % 26 + 'a';  // 시저 암호 적용: 문자를 rand_key만큼 이동시킴
        }
        else if ('A' <= c && c <= 'Z') {  // 대문자인 경우
            ciphertext[i] = ((c - 'A') + rand_key) % 26 + 'A';  // 시저 암호 적용: 문자를 rand_key만큼 이동시킴
        } else {
            /* 알파벳이 아닌 문자 */
            ciphertext[i] = c;
        }
    }

    /* 암호화된 키 계산 - (랜덤 키 + 루트 키) % 26 */
    encrypted_key = (rand_key + ROOT_KEY) % 26;

    /* 암호문 버퍼 크기 확인 */
    if (ciphertext_size < plaintext_size) {
        return TEE_ERROR_SHORT_BUFFER;  // 암호문 버퍼가 충분하지 않으면 오류 반환
    }

    /* 암호화된 키를 param2에 저장 */
    params[2].value.a = encrypted_key;

    IMSG("암호화 완료: 랜덤 키 = %u, 암호화된 키 = %u", rand_key, encrypted_key);

    return TEE_SUCCESS;  // 성공적으로 암호화되었음을 반환
}

/*
 * RSA 키 쌍 생성 함수
 * - session: 현재 세션 정보
 */
TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	// 임시 RSA 키 쌍 객체를 할당
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);  // 오류 메시지 출력
		return ret;// 오류가 발생하면 해당 오류 코드 반환
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	// RSA 키 생성
	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);  // RSA 키 쌍 생성
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);  // 오류 메시지 출력
		return ret;  // 오류가 발생하면 해당 오류 코드 반환
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;  // 성공적으로 키가 생성되었음을 반환
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
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;  // 사용할 RSA 알고리즘 설정
	struct rsa_session *sess = (struct rsa_session *)session;

	// 파라미터 타입 확인
	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;  // 파라미터가 예상과 다르면 오류 반환

	void *plain_txt = params[0].memref.buffer;  // 평문 데이터의 시작 주소
	size_t plain_len = params[0].memref.size;  // 평문 데이터의 크기
	void *cipher = params[1].memref.buffer;  // 암호문 데이터가 저장될 버퍼의 시작 주소
	size_t cipher_len = params[1].memref.size;  // 암호문 데이터의 크기

	// RSA 연산 준비
	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);  // RSA 암호화를 위한 연산 준비
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);  // 오류 메시지 출력
		goto err;  // 오류가 발생하면 err 라벨로 점프
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);  // 암호화할 데이터 출력
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0,
					plain_txt, plain_len, cipher, &cipher_len);  // RSA 암호화 수행	
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);  // 오류 메시지 출력
		goto err;  // 오류가 발생하면 err 라벨로 점프
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);  // 암호화된 데이터 출력
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);  // 연산 핸들 해제
	TEE_FreeOperation(sess->key_handle);  // 키 핸들 해제
	return ret;  // 오류 코드 반환
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
        return TEE_ERROR_BAD_PARAMETERS;  // 파라미터가 예상과 다르면 오류 반환

    /* 암호문과 암호화된 키 */
    char *ciphertext = (char *)params[0].memref.buffer;  // 암호문 데이터의 시작 주소
    size_t ciphertext_size = params[0].memref.size;  // 암호문 데이터의 크기

    uint32_t encrypted_key = params[1].value.a;  // 암호화된 키 값

    char *decrypted_plaintext = (char *)params[2].memref.buffer;  // 복호화된 평문 데이터가 저장될 버퍼의 시작 주소
    size_t decrypted_size = params[2].memref.size;  // 복호화된 평문 데이터의 크기

    /* 암호화된 키로부터 원래의 랜덤 키 복호화 */
    uint32_t rand_key = (encrypted_key + 26 - ROOT_KEY) % 26;
    if (rand_key == 0) {
        rand_key = 26;  // 랜덤 키가 0이면 26으로 설정
    }

    /* 시저 암호로 암호문을 복호화 */
    for (size_t i = 0; i < ciphertext_size; i++) {  // 암호문의 모든 문자에 대해 반복
        char c = ciphertext[i];  // 현재 문자
        if ('a' <= c && c <= 'z') {  // 소문자인 경우
            decrypted_plaintext[i] = ((c - 'a') + (26 - rand_key)) % 26 + 'a';  // 시저 복호화 적용: 문자를 rand_key만큼 왼쪽으로 이동시킴
        }
        else if ('A' <= c && c <= 'Z') {  // 대문자인 경우
            decrypted_plaintext[i] = ((c - 'A') + (26 - rand_key)) % 26 + 'A';  // 시저 복호화 적용: 문자를 rand_key만큼 왼쪽으로 이동시킴
        }
        else {
            /* 알파벳이 아닌 문자 */
            decrypted_plaintext[i] = c;
        }
    }

    /* 복호화된 평문 버퍼 크기 확인 */
    if (decrypted_size < ciphertext_size) {
        return TEE_ERROR_SHORT_BUFFER;  // 복호화된 평문 버퍼가 충분하지 않으면 오류 반환
    }

    IMSG("복호화 완료: 복호화된 키 = %u", rand_key);  // 복호화 완료 메시지 출력

    return TEE_SUCCESS;  // 성공적으로 복호화되었음을 반환
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
		return enc_value(param_types, params);  // enc_value 함수 호출
    case TA_TEEencrypt_CMD_DEC_VALUE:  // 복호화 명령어 처리
        return dec_value(param_types, params);  // dec_value 함수 호출
	case TA_TEEencrypt_CMD_RSA_GENKEYS:  // RSA 키 생성 명령어 처리
		return RSA_create_key_pair(session);  // RSA_create_key_pair 함수 호출
	case TA_TEEencrypt_CMD_RSA_ENCRYPT:  // RSA 암호화 명령어 처리
		return RSA_encrypt(session, param_types, params);  // RSA_encrypt 함수 호출
	default:
		return TEE_ERROR_BAD_PARAMETERS;  // 알 수 없는 명령어일 경우 오류 반환
	}
}
