#pragma once

#include "utils.h"
#include "zstd.h"

namespace fs = std::filesystem;

#pragma comment(lib, "libzstd_static")

#define DEFAULT_COMPRESS_LEVEL 3

bool CompressFile(fs::path& sigPathTmp, const fs::path& sigPath);

bool DecompressFile(fs::path & sigPath, PBYTE &decompressedData);