#include "utils.h"

// http://www.martinbroadhurst.com/how-to-split-a-string-in-c.html
void Split(__in const std::string& str, __out std::vector<std::string>& cont)
{
	std::istringstream iss(str);
	std::copy(std::istream_iterator<std::string>(iss),
		std::istream_iterator<std::string>(),
		std::back_inserter(cont));
}

Md5Hash::Md5Hash()
{
	this->pbHashObject = nullptr;
	this->pbHash = nullptr;
	this->hHash = nullptr;
	this->phAlgorithm = nullptr;
	this->cbHash = 0;

	ULONG cbResult{};


	// The BCryptOpenAlgorithmProvider function loads and initializes a CNG provider.
	if (!NT_SUCCESS(this->Status = BCryptOpenAlgorithmProvider(
		&this->phAlgorithm,
		BCRYPT_MD5_ALGORITHM,
		nullptr,
		BCRYPT_HASH_REUSABLE_FLAG)))
	{
		wprintf(L"[!] Error 0x%lx BCryptOpenAlgorithmProvider\n", this->Status);
		return;
	}

	// HASH LENGTH
	if (!NT_SUCCESS(this->Status = BCryptGetProperty(
		this->phAlgorithm,
		BCRYPT_HASH_LENGTH,
		reinterpret_cast<PBYTE>(&this->cbHash),
		sizeof(DWORD),
		&cbResult,
		0)))
	{
		wprintf(L"[!] Error 0x%lx BCryptGetProperty\n", this->Status);
		return;
	}

	// The BCryptCreateHash function is called to create a md5_hash or Message Authentication Code (MAC) object.
	if (!NT_SUCCESS(this->Status = BCryptCreateHash(
		this->phAlgorithm,
		&this->hHash,
		nullptr,
		0,
		nullptr,
		0,
		BCRYPT_HASH_REUSABLE_FLAG)))
	{
		wprintf(L"[!] Error 0x%lx BCryptCreateHash\n", this->Status);
		return;
	}


	this->Status = STATUS_SUCCESS;
}

PWSTR Md5Hash::HashData(__in PUCHAR data, __in ULONG szData)
{
	this->Status = STATUS_UNSUCCESSFUL;
	PWSTR hashStr = nullptr;
	// The BCryptHashData function performs a one way md5_hash or Message Authentication Code (MAC) on a data buffer.
	if (!NT_SUCCESS(this->Status = BCryptHashData(
		this->hHash,
		data,
		szData,
		0)))
	{
		wprintf(L"[!] Error 0x%lx BCryptHashData\n", this->Status);
		return hashStr;
	}


	this->pbHash = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), 0, this->cbHash));
	if (nullptr == this->pbHash)
	{
		wprintf(L"[!] HeapAlloc failed\n");
		return hashStr;
	}


	// The BCryptFinishHash function retrieves the md5_hash or Message Authentication Code (MAC) value for the data accumulated from prior calls to BCryptHashData.
	if (!NT_SUCCESS(this->Status = BCryptFinishHash(
		this->hHash,
		this->pbHash,
		this->cbHash,
		0)))
	{
		wprintf(L"[!] Error 0x%lx BCryptFinishHash\n", this->Status);
		return hashStr;
	}

	const DWORD dwFlags = CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF;
	DWORD cchString{};
	// The CryptBinaryToString function converts an array of bytes into a formatted string.
	if (CryptBinaryToString(this->pbHash, this->cbHash, dwFlags, nullptr, &cchString))
	{
		hashStr = static_cast<PWSTR>(HeapAlloc(GetProcessHeap(), 0, cchString * sizeof(WCHAR)));
		if (hashStr)
		{
			if (CryptBinaryToString(this->pbHash, this->cbHash, dwFlags, hashStr, &cchString))
			{
				return hashStr;
			}
		}
	}

	HeapFree(GetProcessHeap(), 0, this->pbHash);
	return hashStr;
}

Md5Hash::~Md5Hash()
{
	if (this->phAlgorithm)
	{
		BCryptCloseAlgorithmProvider(this->phAlgorithm, 0);
	}
	if (this->pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, this->pbHashObject);
	}
	if (this->pbHash)
	{
		HeapFree(GetProcessHeap(), 0, this->pbHash);
	}
	if (this->hHash)
	{
		BCryptDestroyHash(this->hHash);
	}
}