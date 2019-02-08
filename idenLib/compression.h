#pragma once

#include "utils.h"
#include "zstd.h"

namespace fs = std::filesystem;

#pragma comment(lib, "libzstd_static")

#define DEFAULT_COMPRESS_LEVEL 3

bool compressFile(fs::path& sigPathTmp, fs::path sigPath);