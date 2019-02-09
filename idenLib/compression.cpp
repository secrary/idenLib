#include "compression.h"

bool CompressFile(fs::path& sigPathTmp, const fs::path& sigPath)
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
	const auto fBuff = new BYTE[fSize];
	fread(fBuff, 1, fSize, hFile);
	// alloc for compressed data
	const auto cBufSize = ZSTD_compressBound(fSize);
	const auto cBuff = new BYTE[fSize];
	// compress data
	const auto cSize = ZSTD_compress(cBuff, cBufSize, fBuff, fSize, DEFAULT_COMPRESS_LEVEL);
	if (ZSTD_isError(cSize)) {
		fprintf(stderr, "[idenLib] error compressing: %s \n", ZSTD_getErrorName(cSize));
		return false;
	}
	fclose(hFile);

	if (fs::exists(sigPath))
	{
		fs::remove(sigPath);
	}
	fopen_s(&hFile, sigPath.string().c_str(), "wb");
	if (!hFile) {
		fprintf(stderr, "[idenLib] failed to open: %s \n", sigPath.string().c_str());
		return false;
	}
	fwrite(cBuff, 1, cSize, hFile);

	delete[] cBuff;
	delete[] fBuff;
	fclose(hFile);

	return true;
}

_Success_(return)
bool DecompressFile(fs::path & sigPath, PBYTE &decompressedData)
{
	FILE *hFile;
	auto err = fopen_s(&hFile, sigPath.string().c_str(), "rb");
	if(err)
	{
		wprintf(L"[idenLib] failed to open the file: %s\n", sigPath.c_str());
		return false;
	}
	// compressed size
	fseek(hFile, 0L, SEEK_END);
	const auto cSize = ftell(hFile);
	rewind(hFile);
	// read data
	const auto cBuff = new BYTE[cSize];
	if (!cBuff)
	{
		return false;
	}
	fread(cBuff, 1, cSize, hFile);
	// decompressed size
	const SIZE_T rSize = ZSTD_findDecompressedSize(cBuff, cSize);
	if (rSize == ZSTD_CONTENTSIZE_ERROR) {
		fprintf(stderr, "[idenLib] %s : it was not compressed by zstd.\n", sigPath.string().c_str());
		delete[] cBuff;
		return false;
	}
	else if (rSize == ZSTD_CONTENTSIZE_UNKNOWN) {
		fprintf(stderr,
			"[idenLib] %s : original size unknown. Use streaming decompression instead.\n", sigPath.string().c_str());
		delete[] cBuff;
		return false;
	}
	decompressedData = new BYTE[rSize + 1]{ 0 }; // +1 for 0x00
	if (!decompressedData)
	{
		return false;
	}
	SIZE_T const dSize = ZSTD_decompress(decompressedData, rSize, cBuff, cSize);

	if (dSize != rSize) {
		fprintf(stderr, "[idenLib] error decoding %s : %s \n", sigPath.string().c_str(), ZSTD_getErrorName(dSize));
		return false;
	}

	fclose(hFile);
	delete[] cBuff;
	return true;
}
