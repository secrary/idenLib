#include "compression.h"

bool compressFile(fs::path & sigPathTmp, fs::path sigPath)
{
	FILE* hFile = nullptr;
	fopen_s(&hFile, sigPathTmp.string().c_str(), "rb");
	if (!hFile) {
		fprintf(stderr, "[idenLib] failed to open: %s \n", sigPathTmp.string().c_str());
		return false;
	}

	// file size
	fseek(hFile, 0L, SEEK_END);
	auto fSize = ftell(hFile);
	rewind(hFile);
	// read file
	auto fBuff = new BYTE[fSize];
	fread(fBuff, 1, fSize, hFile);
	// alloc for compressed data
	auto cBufSize = ZSTD_compressBound(fSize);
	auto cBuff = new BYTE[fSize];
	// compress data
	auto cSize = ZSTD_compress(cBuff, cBufSize, fBuff, fSize, DEFAULT_COMPRESS_LEVEL);
	if (ZSTD_isError(cSize)) {
		fprintf(stderr, "[idenLib] error compressing: %s \n", ZSTD_getErrorName(cSize));
		return false;
	}
	fclose(hFile);

	fopen_s(&hFile, sigPath.string().c_str(), "wb");
	if (!hFile) {
		fprintf(stderr, "[idenLib] failed to open: %s \n", sigPath.string().c_str());
		return false;
	}
	fwrite(cBuff, 1, cSize, hFile);
	fclose(hFile);

	return true;
}
