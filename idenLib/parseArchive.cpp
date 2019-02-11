#include "parseArchive.h"

Lib::Lib(const fs::path& libPath)
{
	if (_wfopen_s(&this->hFile, libPath.c_str(), L"rb") || !this->hFile) // Zero if successful;
		return;
	// get file length
	fseek(this->hFile, 0, SEEK_END);
	this->FileLength = ftell(this->hFile);
	rewind(this->hFile);
	// file content
	this->FileContent = static_cast<byte*>(malloc(this->FileLength));
	if (!this->FileContent)
		return;
	fread(this->FileContent, this->FileLength, 1, this->hFile);
	rewind(this->hFile);
	// Is it right type?
	if (this->FileContent && memcmp(this->FileContent, IMAGE_ARCHIVE_START, IMAGE_ARCHIVE_START_SIZE) == 0)
		this->IsRightType = true;
}

void Lib::MemberHeader(__in IMAGE_ARCHIVE_MEMBER_HEADER& archiveMemberHdr)
{
	const LONG seek = EVEN_BYTE_ALIGN(this->MemberSeekBase + this->MemberSize);
	fseek(this->hFile, seek, SEEK_SET);
	fread(&archiveMemberHdr, sizeof(IMAGE_ARCHIVE_MEMBER_HEADER), 1, this->hFile);
	this->MemberSeekBase = seek + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER);
	this->MemberSize = strtol(reinterpret_cast<char*>(archiveMemberHdr.Size), nullptr, 10);
}

DWORD Reverse(const DWORD value)
{
	return (value & 0x000000FF) << 24 | (value & 0x0000FF00) << 8 | (value & 0x00FF0000) >> 8 | (value & 0xFF000000) >>
		24;
}

_Success_(return)

bool Lib::GetSignature(LPVOID pUserContext)
{
	if (!this->IsRightType)
		return false;
	IMAGE_ARCHIVE_MEMBER_HEADER imArcMemHdr{};
	MemberHeader(imArcMemHdr);
	if (memcmp(imArcMemHdr.Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16) != 0)
	{
		return false;
	}
	// number of public symbols in linker member
	DWORD numberOfPublicSymbols{};
	fread(&numberOfPublicSymbols, sizeof(DWORD), 1, this->hFile);
	numberOfPublicSymbols = Reverse(numberOfPublicSymbols);

	// symbols offsets - skip
	fseek(this->hFile, sizeof(DWORD) * numberOfPublicSymbols, SEEK_CUR);
	// size of the linker member string table - skip
	auto stringTable = IMAGE_ARCHIVE_START_SIZE + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER) +
		(this->MemberSize - ftell(this->hFile));
	fseek(this->hFile, stringTable, SEEK_CUR);

	auto newMember = EVEN_BYTE_ALIGN(this->MemberSeekBase + this->MemberSize);
	fseek(this->hFile, newMember, SEEK_SET);

	IMAGE_ARCHIVE_MEMBER_HEADER imArcMemHdrPos{};
	fread(&imArcMemHdrPos, sizeof(IMAGE_ARCHIVE_MEMBER_HEADER), 1, this->hFile);
	if (!memcmp(imArcMemHdrPos.Name, IMAGE_ARCHIVE_LINKER_MEMBER, 16))
	{
		// second link member - skip
		MemberHeader(imArcMemHdr);
		DWORD cMemberOffsets{};
		fread(&cMemberOffsets, sizeof(DWORD), 1, this->hFile);
		fseek(this->hFile, sizeof(DWORD) * cMemberOffsets, SEEK_CUR);

		// new index table - skip
		fread(&numberOfPublicSymbols, sizeof(DWORD), 1, this->hFile);
		fseek(this->hFile, sizeof(WORD) * numberOfPublicSymbols, SEEK_CUR);
		// string table - skip
		stringTable = MemberSize - (ftell(this->hFile) - (newMember + sizeof(IMAGE_ARCHIVE_MEMBER_HEADER)));
		fseek(this->hFile, stringTable, SEEK_CUR);
	}


	newMember = EVEN_BYTE_ALIGN(this->MemberSeekBase + this->MemberSize);
	fseek(this->hFile, newMember, SEEK_SET);
	fread(&imArcMemHdrPos, sizeof(IMAGE_ARCHIVE_MEMBER_HEADER), 1, this->hFile);
	if (!memcmp(imArcMemHdrPos.Name, IMAGE_ARCHIVE_LONGNAMES_MEMBER, 16))
	{
		MemberHeader(imArcMemHdr);
		// strings - skip
		fseek(this->hFile, this->MemberSize, SEEK_CUR);
	}

	// iterate objects
	do
	{
		IMAGE_ARCHIVE_MEMBER_HEADER archiveMemberHdr{};
		MemberHeader(archiveMemberHdr);

		const auto currentObjectStart = this->FileContent + ftell(this->hFile);
		IMAGE_FILE_HEADER imageFileHdr{};
		fread(&imageFileHdr, sizeof(IMAGE_FILE_HEADER), 1, this->hFile);
		if (!imageFileHdr.Machine) // should we check?
			continue;
		DisasmObjCode(imageFileHdr, currentObjectStart, pUserContext);
	} while (this->MemberSeekBase + this->MemberSize + 1 < this->FileLength);


	return true;
}

Lib::~Lib()
{
	if (FileContent)
		free(FileContent);
	if (hFile)
		fclose(hFile);
}

void Lib::DisasmObjCode(__in IMAGE_FILE_HEADER& imageFileHdr, __in byte* currentObjectStart, LPVOID pUserContext) const
{
	const auto userContext = static_cast<PUSER_CONTEXT>(pUserContext);
	auto saveLoc = ftell(this->hFile);
	fseek(this->hFile, this->MemberSeekBase +
		imageFileHdr.PointerToSymbolTable, SEEK_SET);
	if (!imageFileHdr.NumberOfSymbols)
		return;
	const auto symbols = static_cast<PIMAGE_SYMBOL>(malloc(imageFileHdr.NumberOfSymbols * sizeof(IMAGE_SYMBOL)));
	if (!symbols)
		return;
	fread(symbols, imageFileHdr.NumberOfSymbols, sizeof(IMAGE_SYMBOL), this->hFile);
	fseek(this->hFile, saveLoc, SEEK_SET);

	const auto startOfSectionHeaders = this->MemberSeekBase + sizeof(IMAGE_FILE_HEADER) + imageFileHdr.
		SizeOfOptionalHeader;
	const DWORD cbSections = imageFileHdr.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
	if (!cbSections)
		return;
	const auto sectionHeaders = static_cast<PIMAGE_SECTION_HEADER>(malloc(cbSections));
	if (!sectionHeaders)
		return;
	fseek(this->hFile, startOfSectionHeaders, SEEK_SET); // set after optional header
	fread(sectionHeaders, sizeof(IMAGE_SECTION_HEADER), imageFileHdr.NumberOfSections, this->hFile);

	const auto stringTable = reinterpret_cast<char*>(imageFileHdr.PointerToSymbolTable + currentObjectStart +
		imageFileHdr.NumberOfSymbols *
		sizeof(IMAGE_SYMBOL));
	for (size_t i = 1; i <= imageFileHdr.NumberOfSections; i++) // since IMAGE_SYMBOL counts from 1 (not 0)
	{
		const auto imageSectionHeader = sectionHeaders[i - 1];
		const auto cbVirtual = imageSectionHeader.SizeOfRawData;

		if (imageSectionHeader.PointerToRawData != 0 && cbVirtual != 0 && (
			imageSectionHeader.Characteristics & IMAGE_SCN_CNT_CODE))
		{
			// disassemble code
			const auto numberOfSymbols = imageFileHdr.NumberOfSymbols;
			for (size_t j = 0; j < numberOfSymbols; ++j)
			{
				if (size_t(symbols[j].SectionNumber) == i &&
					(symbols[j].StorageClass == IMAGE_SYM_CLASS_EXTERNAL ||
						symbols[j].StorageClass == IMAGE_SYM_CLASS_STATIC ||
						symbols[j].StorageClass == IMAGE_SYM_CLASS_LABEL) && ISFCN(symbols[j].Type)
					) // current section and function
				{
					const auto fnName = symbols[j].N.Name.Short
						? reinterpret_cast<char*>(symbols[j].N.ShortName)
						: (stringTable + symbols[j].N.Name.Long);

					std::string sName{ fnName };

					//if (sName.find("ZydisDecoderInit") != std::string::npos) { // test func
					//	printf("%s\n", sName.c_str());
					//}

					const auto code = currentObjectStart + imageSectionHeader.PointerToRawData + symbols[j].Value;
					auto codeSize = imageSectionHeader.SizeOfRawData - symbols[j].Value;
					if (codeSize < MIN_FUNC_SIZE)
						continue;
					if (codeSize > MAX_FUNC_SIZE)
					{
						codeSize = MAX_FUNC_SIZE;
					}

					PCHAR opcodesBuf = nullptr;

					if (GetOpcodeBuf(code, static_cast<SIZE_T>(codeSize), opcodesBuf) && opcodesBuf)
					{

						std::string cOpcodes{ opcodesBuf };

						userContext->funcSignature[cOpcodes] = sName;
						userContext->Dirty = true;

						free(opcodesBuf);
					}
				}
			}
		}
	}

	free(symbols);
	free(sectionHeaders);
}