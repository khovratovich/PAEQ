#define EXTRANONCE

#include "paeq-def.h"
#ifndef NO_SUPERCOP
#include "crypto_aead.h"
#endif

#include <stdio.h>
#include "stdint.h"
#include <cstring>
#include <stdlib.h>
#include "string.h"
#include "wmmintrin.h"
#if defined(_MSC_VER)
#include "intrin.h"
#else
#include <x86intrin.h>
#endif
#include "emmintrin.h"


int genKAT(unsigned long long plaintext_length, unsigned long long ad_length)
{
	if ((plaintext_length > (1 << 31)) || (ad_length> (1 << 31)))
		return 1;
	Init();   //For generating plaintext
	unsigned char *key = (unsigned char*)malloc(key_bytes);
	unsigned char *nonce = (unsigned char*)malloc(nonce_bytes);

	unsigned char *ciphertext;
	unsigned long long ciphertext_length;
	unsigned long long decrypted_length;

	unsigned char *plaintext = (unsigned char*)malloc((size_t)plaintext_length);
	unsigned char *plaintext_decrypted = (unsigned char*)malloc((size_t)plaintext_length);
	plaintext_length = (size_t)plaintext_length;
	if (plaintext == NULL || plaintext_decrypted == NULL)
		return 1;

	unsigned char *associated_data = (unsigned char*)malloc((size_t)ad_length);
	if (associated_data == NULL)
	{
		if (plaintext_length != 0)
		{

			free(plaintext);
			free(plaintext_decrypted);
		}
		return 1;
	}

	//Plaintext initialization
	unsigned char StateIn[64];
	memset(StateIn, 0, 64);
	unsigned char StateOut[64];
	int counter = (int)plaintext_length;
	unsigned char *dest_pointer = plaintext;
	while (counter>0)
	{
		FPerm(StateIn, StateOut);
		unsigned to_copy = (counter<64) ? counter : 64;
		memcpy(dest_pointer, StateOut, to_copy);
		dest_pointer += to_copy;
		(*((unsigned*)StateIn))++;
		counter -= to_copy;
	}

	//AD initialization
	counter = (int)
		ad_length;
	dest_pointer = associated_data;
	while (counter>0)
	{
		FPerm(StateIn, StateOut);
		unsigned to_copy = (counter<64) ? counter : 64;
		memcpy(dest_pointer, StateOut, to_copy);
		dest_pointer += to_copy;
		(*((unsigned*)StateIn))++;
		counter -= to_copy;
	}

	//Key setting
	FPerm(StateIn, StateOut);
	memcpy(key, StateOut, key_bytes);
	(*((unsigned*)StateIn))++;

	//Nonce setting
	FPerm(StateIn, StateOut);
	memcpy(nonce, StateOut, nonce_bytes);
	(*((unsigned*)StateIn))++;

	//Ciphertext memory allocation
	ciphertext = (unsigned char*)malloc((size_t)(plaintext_length + tag_bytes));
	if (ciphertext == NULL)
	{
		if (plaintext_length != 0)
		{
			free(plaintext);
			free(plaintext_decrypted);
		}
		if (ad_length != 0)
			free(associated_data);
		return 1;
	}

	//Writing input
	FILE *fp;
	fopen_s(&fp, "kat.log", "a+");
	fprintf(fp, "\n\n===================================  Encrypting plaintext (%llu bytes) and AD (%llu bytes)=============\n", plaintext_length,
		ad_length);
	fprintf(fp, "PLAINTEXT (%llu bytes):\n", plaintext_length);
	for (unsigned i = 0; i<plaintext_length; ++i)
	{
		fprintf(fp, "0x%.02x ", plaintext[i]);
		if (i % 20 == 19)
			fprintf(fp, "\n");
	}

	fprintf(fp, "\nASSOCIATED DATA  (%llu bytes):\n", ad_length);
	for (unsigned i = 0; i<ad_length; ++i)
	{
		fprintf(fp, "0x%.02x ", associated_data[i]);
		if (i % 20 == 19)
			fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
	fprintf(fp, "\nKEY  (%d bytes):\n", key_bytes);
	for (unsigned i = 0; i<key_bytes; ++i)
		fprintf(fp, "0x%.02x ", key[i]);
	fprintf(fp, "\n");


	//Encryption and decryption
#ifdef EXTRANONCE 	//ExtraNonce
	crypto_aead_encrypt_no_nonce(ciphertext, &ciphertext_length, plaintext, plaintext_length, associated_data, ad_length, NULL, nonce, key);

	int result = crypto_aead_decrypt(plaintext_decrypted, &decrypted_length, NULL, ciphertext, ciphertext_length, associated_data, ad_length, nonce, key);

#else	   	//Normal nonce
	crypto_aead_encrypt(ciphertext, &ciphertext_length, plaintext, plaintext_length, associated_data, ad_length, NULL, nonce, key);
	int result = crypto_aead_decrypt(plaintext_decrypted, &decrypted_length, NULL, ciphertext, ciphertext_length, associated_data, ad_length, nonce, key);

#endif

	if (decrypted_length != plaintext_length)
		printf("Plaintext length mismatch\n");

	//Writing outputs
	fprintf(fp, "\nNONCE  (%d bytes):\n", nonce_bytes);
	for (unsigned i = 0; i<nonce_bytes; ++i)
		fprintf(fp, "0x%.02x ", nonce[i]);
	fprintf(fp, ".\n");
	if (result != 0)
		printf("Decryption result: %d\n", result);


	fprintf(fp, "\nCIPHERTEXT (%llu bytes):\n", ciphertext_length);
	for (unsigned i = 0; i<ciphertext_length; ++i)
	{
		fprintf(fp, "0x%.02x ", ciphertext[i]);
		if (i % 20 == 19)
			fprintf(fp, "\n");
		if (i == ciphertext_length - tag_bytes - 1)
			fprintf(fp, " || ");
	}
	fprintf(fp, ".\n");

	fprintf(fp, "\nDECRYPTED PLAINTEXT  (%llu bytes):\n", decrypted_length);
	for (unsigned i = 0; i<decrypted_length; ++i)
	{
		fprintf(fp, "0x%.02x ", plaintext_decrypted[i]);
		if (i % 20 == 19)
			fprintf(fp, "\n");
	}
	fprintf(fp, ".\n");
	fclose(fp);


	free(ciphertext);
	if (plaintext_length != 0)
	{
		free(plaintext);
		free(plaintext_decrypted);
	}
	if (ad_length != 0)
		free(associated_data);
	return 0;



}


int benchmark(unsigned long long plaintext_length, unsigned long long ad_length)
{
	if ((plaintext_length >(1 << 31)) || (ad_length> (1 << 31)))
		return 1;
	Init();   //For generating plaintext
	unsigned char *key = (unsigned char*)malloc(key_bytes);
	unsigned char *nonce = (unsigned char*)malloc(nonce_bytes);

	unsigned char *ciphertext;
	unsigned long long ciphertext_length;
	unsigned long long decrypted_length;

	unsigned char *plaintext = (unsigned char*)malloc((size_t)plaintext_length);
	unsigned char *plaintext_decrypted = (unsigned char*)malloc((size_t)plaintext_length);
	plaintext_length = (size_t)plaintext_length;
	if (plaintext == NULL || plaintext_decrypted == NULL)
		return 1;

	unsigned char *associated_data = (unsigned char*)malloc((size_t)ad_length);
	if (associated_data == NULL)
	{
		free(plaintext);
		free(plaintext_decrypted);
		return 1;
	}

	//Plaintext initialization
	unsigned char StateIn[64];
	memset(StateIn, 0, 64);
	unsigned char StateOut[64];
	int counter = (int)plaintext_length;
	unsigned char *dest_pointer = plaintext;
	while (counter>0)
	{
		FPerm(StateIn, StateOut);
		unsigned to_copy = (counter<64) ? counter : 64;
		memcpy(dest_pointer, StateOut, to_copy);
		dest_pointer += to_copy;
		(*((unsigned*)StateIn))++;
		counter -= to_copy;
	}

	//AD initialization
	counter = (int)
		ad_length;
	dest_pointer = associated_data;
	while (counter>0)
	{
		FPerm(StateIn, StateOut);
		unsigned to_copy = (counter<64) ? counter : 64;
		memcpy(dest_pointer, StateOut, to_copy);
		dest_pointer += to_copy;
		(*((unsigned*)StateIn))++;
		counter -= to_copy;
	}

	//Key setting
	FPerm(StateIn, StateOut);
	memcpy(key, StateOut, key_bytes);
	(*((unsigned*)StateIn))++;

	//Nonce setting
	FPerm(StateIn, StateOut);
	memcpy(nonce, StateOut, nonce_bytes);
	(*((unsigned*)StateIn))++;

	//Ciphertext memory allocation
	ciphertext = (unsigned char*)malloc((size_t)(plaintext_length + tag_bytes));
	if (ciphertext == NULL)
	{
		free(plaintext);
		free(plaintext_decrypted);
		free(associated_data);
		return 1;
	}

	uint64_t start_time, mid_time, end_time;
	uint32_t start_ptr, mid_ptr, end_ptr;

	start_time = __rdtscp(&start_ptr);
#ifdef EXTRANONCE 	//ExtraNonce
	crypto_aead_encrypt_no_nonce(ciphertext, &ciphertext_length, plaintext, plaintext_length, associated_data, ad_length, NULL, nonce, key);
#else
	crypto_aead_encrypt(ciphertext, &ciphertext_length, plaintext, plaintext_length, associated_data, ad_length, NULL, nonce, key);
#endif
	mid_time = __rdtscp(&mid_ptr);
	float speed = (float)(mid_time - start_time) / (plaintext_length + ad_length);
	printf("PAEQ-128: %d bytes encrypted, %2.2f cpb\n", (uint32_t)(plaintext_length + ad_length), speed);
	mid_time = __rdtscp(&mid_ptr);
	int result = crypto_aead_decrypt(plaintext_decrypted, &decrypted_length, NULL, ciphertext, ciphertext_length, associated_data, ad_length, nonce, key);
	end_time = __rdtscp(&end_ptr);
	speed = (float)(end_time - mid_time) / (plaintext_length + ad_length);
	printf("PAEQ-128: %d bytes decrypted, %2.2f cpb\n", (uint32_t)(plaintext_length + ad_length), speed);

	if (decrypted_length != plaintext_length)
		printf("Plaintext length mismatch\n");
	if (result!=0)
		printf("Decryption result: %d\n", result);

	free(ciphertext);
	free(plaintext_decrypted);
	free(associated_data);
	return 0;
}



int main(int argc, char* argv[])
{
	remove("kat.log");
	for (unsigned p_length = 0; p_length < 400; p_length+=40)
	{
		printf("plaintext length %d\n", p_length);
		for (unsigned ad_length = 0; ad_length < 200; ad_length+=40)
			genKAT(p_length, ad_length);
	}
	/*for (unsigned i = 0; i < 10; ++i)
	benchmark_ctr(1000000);*/
	//benchmark(10000000, 0);
	return 0;
}

