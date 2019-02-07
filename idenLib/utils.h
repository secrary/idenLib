#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <cstdio>
#include <string>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <Zydis/Zydis.h>

#include "disassamble.h"
#include "parseArchive.h"

namespace fs = std::filesystem;

#pragma comment(lib, "bcrypt")
#pragma comment(lib, "crypt32")

#pragma comment(lib, "Zydis")
#pragma comment(lib, "Zycore")

#define NT_SUCCESS(_)				(((NTSTATUS)(_)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL			((NTSTATUS)0xC0000001L)

#define MIN_FUNC_SIZE 0x20
#define MAX_FUNC_SIZE 0x100

inline fs::path symExPath{ "SymEx" };
inline fs::path pdbDirName{ "symbols" };

void Split(__in const std::string& str, __out std::vector<std::string>& cont);

class Md5Hash
{
	BCRYPT_ALG_HANDLE phAlgorithm;
	PBYTE pbHashObject;
	PBYTE pbHash;
	BCRYPT_HASH_HANDLE hHash;
	DWORD cbHash;

public:
	NTSTATUS Status;
	Md5Hash();
	PWSTR HashData(__in PUCHAR data, __in ULONG szData);

	~Md5Hash();
};

typedef struct _USER_CONTEXT
{
	UINT64 FHandle;
	Md5Hash* pHash;
	std::unordered_map<std::wstring, std::wstring> UniqHashFuncName;
	bool Dirty;
} USER_CONTEXT, *PUSER_CONTEXT;