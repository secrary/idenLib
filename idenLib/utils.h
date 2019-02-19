#pragma once

#include <Windows.h>
#include <dia2.h>

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
#include "pdb.h"

#include "Zydis/Zydis.h"

#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

namespace fs = std::filesystem;

#define NT_SUCCESS(_)				(((NTSTATUS)(_)) >= 0)
#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL			((NTSTATUS)0xC0000001L)

#define MIN_FUNC_SIZE 0x20
#define MAX_FUNC_SIZE 0x100

inline auto entryPointSignatures = L"EntryPointSignatures.sig";
inline auto sigExt = L".sig";
inline auto subFolder = L"x86";
inline auto zydisMode = ZYDIS_MACHINE_MODE_LEGACY_32;
inline auto zydisWidth = ZYDIS_ADDRESS_WIDTH_32;

inline fs::path symExPath{"SymEx"};
inline fs::path pdbDirName{"symbols"};

void Split(__in const std::string& str, __out std::vector<std::string>& cont);

typedef struct _USER_CONTEXT
{
	std::unordered_map<std::string, std::string> funcSignature;
	bool Dirty;
} USER_CONTEXT, *PUSER_CONTEXT;

enum
{
	Arch86 = 0x14C,
	Arch64 = 0x8664
};
