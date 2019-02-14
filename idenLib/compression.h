#pragma once

#include "utils.h"


namespace fs = std::filesystem;

#define DEFAULT_COMPRESS_LEVEL 3

bool CompressFile(fs::path& sigPathTmp, const fs::path& sigPath);

bool DecompressFile(fs::path& sigPath, PBYTE& decompressedData);
