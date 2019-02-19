#pragma once

#include "utils.h"

_Success_(return)
bool ProcessMainSignature(const fs::path& pePath);

typedef struct _MAIN_SIG_INFO
{
	std::unordered_map<std::string, std::string> MainSignatures;
	bool Dirty;
	std::string EntryName;
	std::string opcodes_index;
	DWORD_PTR baseAddress;
	DWORD_PTR mainVA;
} MAIN_SIG_INFO, *P_MAIN_SIG_INFO;
