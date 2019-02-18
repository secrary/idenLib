#pragma once

#include "utils.h"

_Success_(return)
bool ProcessMainSignature(const fs::path& pePath, char* entryName);

typedef struct _MAIN_SIG_INFO
{
	std::unordered_map<std::string, std::string> MainSignatures;
	bool Dirty;
	char* EntryName;
	INT64 baseAddress;
	INT64 mainVA;
} MAIN_SIG_INFO, *P_MAIN_SIG_INFO;