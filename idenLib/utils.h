#pragma once

#include <Windows.h>
#include <cstdio>
#include <string>
#include <fstream>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <unordered_map>
#include <vector>
#include <filesystem>


#include "disassamble.h"
#include "parseArchive.h"
#include "compression.h"

#include "Zydis/Zydis.h"

#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

namespace fs = std::filesystem;

#define NT_SUCCESS(_)				(((NTSTATUS)(_)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL			((NTSTATUS)0xC0000001L)

#define MIN_FUNC_SIZE 0x20
#define MAX_FUNC_SIZE 0x100

#ifdef _WIN64
#define ZYDIS_ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_64
#define ZYDIS_MODE ZYDIS_MACHINE_MODE_LONG_64
#define SIG_EXT L".sig64"
#else
#define ZYDIS_ADDRESS_WIDTH ZYDIS_ADDRESS_WIDTH_32
#define ZYDIS_MODE ZYDIS_MACHINE_MODE_LEGACY_32
#define SIG_EXT L".sig"
#endif


inline fs::path symExPath{"SymEx"};
inline fs::path pdbDirName{"symbols"};


void Split(__in const std::string& str, __out std::vector<std::string>& cont);

typedef struct _USER_CONTEXT
{
	std::unordered_map<std::string, std::string> funcSignature;
	bool Dirty;
} USER_CONTEXT, *PUSER_CONTEXT;
