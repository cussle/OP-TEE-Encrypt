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
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

/* RSA 설정 */
#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char *argv[]) {
	TEEC_Result res;						// OP-TEE 함수 호출 결과
	TEEC_Context ctx;						// OP-TEE 컨텍스트
	TEEC_Session sess;						// OP-TEE 세션
	TEEC_Operation op;						// OP-TEE 연산 구조체
	TEEC_UUID uuid = TA_TEEencrypt_UUID;	// TA의 UUID 설정
	uint32_t err_origin;					// 오류 원인

    /* 명령어 및 파일 인자 확인 */
    if (argc < 3) {
        fprintf(stderr, "사용법: %s -e [평문 파일] [Caesar|RSA] 또는 %s -d [암호문 파일] [암호화된 키 파일]\n", argv[0], argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-e") == 0) {  // 암호화 명령어 처리
		/* 옵션 확인 */
        if (argc != 4) {
            fprintf(stderr, "암호화 사용법: %s -e [평문 파일] [Caesar|RSA]\n", argv[0]);
            return 1;
        }

		char *input_filename = argv[2];						// 입력(평문 파일 이름)
        char *algorithm = argv[3];                          // 사용할 알고리즘 (Caesar 또는 RSA)
		
		if (strcmp(algorithm, "Caesar") == 0) {  // Caesar 암호화 처리
			char *ciphertext_filename = "ciphertext.txt";		// 출력(암호문 파일 이름)
			char *encryptedkey_filename = "encrypted_key.txt";	// 출력(암호화된 키 파일 이름)

			/* 평문 파일 열기 */
			FILE *fp = fopen(input_filename, "rb");  // 바이너리 모드로 파일 열기
			if (!fp) {
				perror("평문 파일 열기 실패");
				return 1;
			}

			/* 파일 크기 구하기 */
			fseek(fp, 0, SEEK_END);			// 파일 포인터를 끝으로 이동
			long file_size = ftell(fp);		// 파일 크기 측정
			rewind(fp);						// 파일 포인터를 처음으로 되돌림

			/* 파일 크기 유효성 검사 */
			if (file_size <= 0) {
				fprintf(stderr, "평문 파일 크기가 유효하지 않습니다.\n");
				fclose(fp);
				return 1;
			}

			/* 평문 데이터를 읽을 버퍼 할당 */
			char *plaintext = malloc(file_size);
			if (!plaintext) {
				perror("평문 버퍼 할당 실패");
				fclose(fp);
				return 1;
			}

			/* 파일에서 평문 읽기 */
			size_t read_size = fread(plaintext, 1, file_size, fp);
			if (read_size != file_size) {
				perror("평문 파일 읽기 실패");
				free(plaintext);
				fclose(fp);
				return 1;
			}
			fclose(fp);  // 파일 닫기

			/* 암호문을 저장할 버퍼 할당 */
			char *ciphertext = malloc(file_size);
			if (!ciphertext) {
				perror("암호문 버퍼 할당 실패");
				free(plaintext);
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

			/* 파라미터 타입 설정:
			param0: 평문 (입력, temp memref)
			param1: 암호문 (출력, temp memref)
			param2: 암호화된 키 (출력, value)
			param3: 사용 안 함
			*/
			op.paramTypes = TEEC_PARAM_TYPES(
				TEEC_MEMREF_TEMP_INPUT,
				TEEC_MEMREF_TEMP_OUTPUT,
				TEEC_VALUE_OUTPUT,
				TEEC_NONE
			);

			/* param0: 평문 버퍼 및 크기 설정 */
			op.params[0].tmpref.buffer = plaintext;
			op.params[0].tmpref.size = file_size;

			/* param1: 암호문을 저장할 버퍼 및 크기 설정 */
			op.params[1].tmpref.buffer = ciphertext;
			op.params[1].tmpref.size = file_size;

			/* param2: 암호화된 키를 저장할 value */
			/* param3: 사용 안 함 */

			/* TA 명령어 호출 */
			printf("========================Encryption (Caesar)========================\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);  // 암호화 명령어 호출
			if (res != TEEC_SUCCESS) {
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				errx(1, "TEEC_InvokeCommand 실패: 0x%x, 원인: 0x%x", res, err_origin);
			}

			/* 암호화된 키를 param2의 값으로 반환 */
			uint32_t encrypted_key = op.params[2].value.a;

			/* 세션 및 컨텍스트 종료 */
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			/* 암호문을 파일에 저장 */
			fp = fopen(ciphertext_filename, "wb");  // 쓰기 바이너리 모드로 파일 열기
			if (!fp) {
				perror("암호문 파일 생성 실패");
				free(plaintext);
				free(ciphertext);
				return 1;
			}
			size_t write_size = fwrite(ciphertext, 1, file_size, fp);
			if (write_size != file_size) {
				perror("암호문 파일 쓰기 실패");
				fclose(fp);
				free(plaintext);
				free(ciphertext);
				return 1;
			}
			fclose(fp);  // 파일 닫기

			/* 암호화된 키를 파일에 저장 */
			char encrypted_key_str[12];  // 키를 문자열로 저장할 공간
			snprintf(encrypted_key_str, sizeof(encrypted_key_str), "%u", encrypted_key);

			FILE *fp_key = fopen(encryptedkey_filename, "w");  // 암호화된 키 파일 열기 (쓰기 모드)
			if (!fp_key) {
				perror("암호화된 키 파일 생성 실패");
				free(plaintext);
				free(ciphertext);
				return 1;
			}
			size_t key_write_size = fwrite(encrypted_key_str, 1, strlen(encrypted_key_str), fp_key);
			if (key_write_size != strlen(encrypted_key_str)) {
				perror("암호화된 키 파일 쓰기 실패");
				fclose(fp_key);
				free(plaintext);
				free(ciphertext);
				return 1;
			}
			fclose(fp_key);  // 파일 닫기

			/* 암호화 완료 메시지 */
			printf("[Caesar 암호화 완료]\n암호문 파일: %s\n암호화된 키 파일: %s\n", ciphertext_filename, encryptedkey_filename);

			/* 할당된 메모리 해제 */
			free(plaintext);
			free(ciphertext);
		} if (strcmp(algorithm, "Caesar") == 0) {  // RSA 암호화 처리
			char *ciphertext_filename = "ciphertext_rsa.bin";  // 출력(암호문 파일 이름)
			char *encryptedkey_filename = "encrypted_key.txt";	// 출력(암호화된 키 파일 이름)

			/* 평문 파일 열기 */
			FILE *fp = fopen(input_filename, "rb");  // 바이너리 모드로 파일 열기
			if (!fp) {
				perror("평문 파일 열기 실패");
				return 1;
			}

			/* 파일 크기 구하기 */
			fseek(fp, 0, SEEK_END);			// 파일 포인터를 끝으로 이동
			long file_size = ftell(fp);		// 파일 크기 측정
			rewind(fp);						// 파일 포인터를 처음으로 되돌림

			/* 파일 크기 유효성 검사 */
			if (file_size <= 0) {
				fprintf(stderr, "평문 파일 크기가 유효하지 않습니다.\n");
				fclose(fp);
				return 1;
			}

			/* 평문 데이터를 읽을 버퍼 할당 */
			char *plaintext = malloc(file_size);
			if (!plaintext) {
				perror("평문 버퍼 할당 실패");
				fclose(fp);
				return 1;
			}

			/* 파일에서 평문 읽기 */
			size_t read_size = fread(plaintext, 1, file_size, fp);
			if (read_size != file_size) {
				perror("평문 파일 읽기 실패");
				free(plaintext);
				fclose(fp);
				return 1;
			}
			fclose(fp);  // 파일 닫기

			/* 암호문을 저장할 버퍼 할당 */
			char *ciphertext = malloc(RSA_CIPHER_LEN_1024);
			if (!ciphertext) {
				perror("암호문 버퍼 할당 실패");
				free(plaintext);
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

			/* 파라미터 타입 설정:
			param0: 평문 (입력, temp memref)
			param1: 암호문 (출력, temp memref)
			param2: 사용 안 함
			param3: 사용 안 함
			*/
			op.paramTypes = TEEC_PARAM_TYPES(
				TEEC_MEMREF_TEMP_INPUT,
				TEEC_MEMREF_TEMP_OUTPUT,
				TEEC_NONE,
				TEEC_NONE
			);

			/* param0: 평문 버퍼 및 크기 설정 */
			op.params[0].tmpref.buffer = plaintext;
			op.params[0].tmpref.size = file_size;

			/* param1: 암호문을 저장할 버퍼 및 크기 설정 */
			op.params[1].tmpref.buffer = ciphertext;
			op.params[1].tmpref.size = file_size;

			/* param2, param3: 사용 안 함 */

			/* TA 명령어 호출 (RSA 키 생성) */
			printf("========================Encryption (RSA)========================\n");
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, &op, &err_origin);  // 암호화 명령어 호출
			if (res != TEEC_SUCCESS) {
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				errx(1, "TEEC_InvokeCommand 실패(RSA_GENKEYS): 0x%x, 원인: 0x%x", res, err_origin);
			}

			/* TA 명령어 호출 (RSA 암호화) */
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENCRYPT, &op, &err_origin);  // 암호화 명령어 호출
			if (res != TEEC_SUCCESS) {
				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				errx(1, "TEEC_InvokeCommand 실패(RSA_ENCRYPT): 0x%x, 원인: 0x%x", res, err_origin);
			}

			/* 세션 및 컨텍스트 종료 */
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);

			/* 암호문을 파일에 저장 */
			fp = fopen(ciphertext_filename, "wb");  // 쓰기 바이너리 모드로 파일 열기
			if (!fp) {
				perror("암호문 파일 생성 실패");
				free(plaintext);
				free(ciphertext);
				return 1;
			}
			size_t write_size = fwrite(ciphertext, 1, file_size, fp);
			if (write_size != file_size) {
				perror("암호문 파일 쓰기 실패");
				fclose(fp);
				free(plaintext);
				free(ciphertext);
				return 1;
			}
			fclose(fp);  // 파일 닫기

			/* 암호화 완료 메시지 */
			printf("[RSA 암호화 완료]\n암호문 파일: %s\n암호화된 키 파일: %s\n", ciphertext_filename, encryptedkey_filename);

			/* 할당된 메모리 해제 */
			free(plaintext);
			free(ciphertext);
		} else {
            fprintf(stderr, "지원되지 않는 알고리즘입니다. 사용 가능한 알고리즘: Caesar, RSA\n");
            return 1;
        }
	} else if (strcmp(argv[1], "-d") == 0) {    // 복호화화 명령어 처리
		/* 옵션 확인 */
        if (argc != 4) {
            fprintf(stderr, "복호화 사용법: %s -d [암호문 파일] [암호화된 키 파일]\n", argv[0]);
            return 1;
        }

        char *ciphertext_filename = argv[2];			// 입력(암호문 파일 이름)
        char *encryptedkey_filename = argv[3];			// 입력(암호화된 키 파일 이름)
        char *decrypted_filename = "decrypted.txt";		// 출력(복호화된 평문 파일 이름)

        /* 암호문 파일 열기 */
        FILE *fp_cipher = fopen(ciphertext_filename, "rb");  // 바이너리 모드로 파일 열기
        if (!fp_cipher) {
            perror("암호문 파일 열기 실패");
            return 1;
        }

        /* 암호문 파일 크기 구하기 */
        fseek(fp_cipher, 0, SEEK_END);			// 파일 포인터를 끝으로 이동
        long cipher_size = ftell(fp_cipher);	// 파일 크기 측정
        rewind(fp_cipher);						// 파일 포인터를 처음으로 되돌림

        /* 파일 크기 유효성 검사 */
        if (cipher_size <= 0) {
            fprintf(stderr, "암호문 파일 크기가 유효하지 않습니다.\n");
            fclose(fp_cipher);
            return 1;
        }

        /* 암호문 데이터를 읽을 버퍼 할당 */
        char *ciphertext = malloc(cipher_size);
        if (!ciphertext) {
            perror("암호문 버퍼 할당 실패");
            fclose(fp_cipher);
            return 1;
        }

        /* 암호문 파일에서 데이터 읽기 */
        size_t read_cipher_size = fread(ciphertext, 1, cipher_size, fp_cipher);
        if (read_cipher_size != cipher_size) {
            perror("암호문 파일 읽기 실패");
            free(ciphertext);
            fclose(fp_cipher);
            return 1;
        }
        fclose(fp_cipher);  // 파일 닫기

        /* 암호화된 키 파일 열기 */
        FILE *fp_key = fopen(encryptedkey_filename, "r");  // 읽기 모드로 파일 열기
        if (!fp_key) {
            perror("암호화된 키 파일 열기 실패");
            free(ciphertext);
            return 1;
        }

        /* 암호화된 키 읽기 */
        char encrypted_key_str[12];  // 키를 문자열로 읽을 공간
        if (fgets(encrypted_key_str, sizeof(encrypted_key_str), fp_key) == NULL) {
            perror("암호화된 키 파일 읽기 실패");
            fclose(fp_key);
            free(ciphertext);
            return 1;
        }
        fclose(fp_key);  // 파일 닫기

        /* 암호화된 키를 정수로 변환 */
        uint32_t encrypted_key = atoi(encrypted_key_str);

        /* 복호화된 평문을 저장할 버퍼 할당 */
        char *decrypted_plaintext = malloc(cipher_size);
        if (!decrypted_plaintext) {
            perror("복호화된 평문 버퍼 할당 실패");
            free(ciphertext);
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

        /* 파라미터 타입 설정:
           param0: 암호문 (입력, temp memref)
           param1: 암호화된 키 (입력, value)
           param2: 복호화된 평문 (출력, temp memref)
           param3: 사용 안 함
        */
        op.paramTypes = TEEC_PARAM_TYPES(
            TEEC_MEMREF_TEMP_INPUT,
            TEEC_VALUE_INPUT,
            TEEC_MEMREF_TEMP_OUTPUT,
            TEEC_NONE
        );

        /* param0: 암호문 버퍼 및 크기 설정 */
        op.params[0].tmpref.buffer = ciphertext;
        op.params[0].tmpref.size = cipher_size;

        /* param1: 암호화된 키를 설정 */
        op.params[1].value.a = encrypted_key;

        /* param2: 복호화된 평문을 저장할 버퍼 및 크기 설정 */
        op.params[2].tmpref.buffer = decrypted_plaintext;
        op.params[2].tmpref.size = cipher_size;

		/* param3: 사용 안 함 */

        /* TA 명령어 호출 */
		printf("========================Decryption========================\n");
        res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);  // 복호화 명령어 호출
        if (res != TEEC_SUCCESS) {
            TEEC_CloseSession(&sess);
            TEEC_FinalizeContext(&ctx);
            errx(1, "TEEC_InvokeCommand 실패: 0x%x, 원인: 0x%x", res, err_origin);
        }

        /* 세션 및 컨텍스트 종료 */
        TEEC_CloseSession(&sess);
        TEEC_FinalizeContext(&ctx);

        /* 복호화된 평문을 파일에 저장 */
        FILE *fp_decrypted = fopen(decrypted_filename, "wb");  // 쓰기 바이너리 모드로 파일 열기
        if (!fp_decrypted) {
            perror("복호화된 평문 파일 생성 실패");
            free(ciphertext);
            free(decrypted_plaintext);
            return 1;
        }
        size_t write_decrypted_size = fwrite(decrypted_plaintext, 1, cipher_size, fp_decrypted);
        if (write_decrypted_size != cipher_size) {
            perror("복호화된 평문 파일 쓰기 실패");
            fclose(fp_decrypted);
            free(ciphertext);
            free(decrypted_plaintext);
            return 1;
        }
        fclose(fp_decrypted);  // 파일 닫기

        /* 복호화 완료 메시지 */
        printf("[복호화 완료]\n복호화된 평문 파일: %s\n", decrypted_filename);

        /* 할당된 메모리 해제 */
        free(ciphertext);
        free(decrypted_plaintext);
	} else {
        fprintf(stderr, "지원되지 않는 명령어입니다. 사용 가능한 옵션: -e, -d\n");
        return 1;
    }

	return 0;
}
