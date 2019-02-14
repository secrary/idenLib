#pragma once

#include "utils.h"

namespace fs = std::filesystem;

#define EVEN_BYTE_ALIGN(x)	(((x) & 1) ? (x) + 1 : (x))


class Lib
{
	bool isLib = false;
	SIZE_T MemberSeekBase = IMAGE_ARCHIVE_START_SIZE;
	SIZE_T MemberSize = 0;
	void MemberHeader(__in IMAGE_ARCHIVE_MEMBER_HEADER& archiveMemberHdr);
	void DisasmObjCode(__in IMAGE_FILE_HEADER& imageFileHdr, __in byte* currentObjectStart, LPVOID pUserContext);
public:
	byte* FileContent = nullptr;
	FILE* hFile = nullptr;
	SIZE_T FileLength = 0;
	Lib() = delete;
	Lib(const fs::path& libPath);
	_Success_(return)
	bool GetSignature(LPVOID pUserContext);

	~Lib();
};
