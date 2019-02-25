#include "pdb.h"

bool LoadDataFromPdb(const wchar_t* szFilename, IDiaDataSource** ppSource, IDiaSession** ppSession,
                     IDiaSymbol** ppGlobal);
bool GetMainSignature(__in IDiaSymbol* pGlobal, MAIN_SIG_INFO& mainInfo);
void GetMainRva(__in IDiaSymbol* pSymbol, MAIN_SIG_INFO& mainInfo);
void FindCallerSignature(__in IDiaSymbol* pSymbol, MAIN_SIG_INFO& mainInfo);
void GetCallerOpcodes(__in PBYTE funcVa, __in SIZE_T length, MAIN_SIG_INFO& mainInfo);

_Success_(return)

bool ProcessMainSignature(const fs::path& pePath)
{
	auto loadAddress = reinterpret_cast<DWORD_PTR>(LoadLibraryEx(pePath.c_str(), nullptr,
	                                                             LOAD_LIBRARY_AS_IMAGE_RESOURCE));
	if (INVALID_HANDLE_VALUE == reinterpret_cast<HANDLE>(loadAddress))
	{
		printf("Failed to map....");
		return false;
	}
	// if PE is DLL, LOAD_LIBRARY_AS_IMAGE_RESOURCE flag increases baseAddress by 2
	MEMORY_BASIC_INFORMATION info{};
	if (!VirtualQuery(reinterpret_cast<LPCVOID>(loadAddress), &info, sizeof(info)))
	{
		printf("[!] VirtualQuery failed\n");
		return false;
	}
	loadAddress = reinterpret_cast<UINT64>(info.AllocationBase);

	const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(loadAddress);
	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(loadAddress + dosHeader->e_lfanew);
	const auto isx64 = ntHeader->FileHeader.Machine == Arch64;

	MAIN_SIG_INFO mainInfo;
	mainInfo.Dirty = false;
	mainInfo.baseAddress = loadAddress;

	if (isx64)
	{
		entryPointSignatures = L"EntryPointSignatures.sig64";
		subFolder = L"x64";
		zydisMode = ZYDIS_MACHINE_MODE_LONG_64;
		zydisWidth = ZYDIS_ADDRESS_WIDTH_64;
		auto ntHeaderCurrent = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntHeader);
		mainInfo.EntryAddress = static_cast<DWORD_PTR>(ntHeaderCurrent->OptionalHeader.AddressOfEntryPoint);
	}
	else
	{
		entryPointSignatures = L"EntryPointSignatures.sig";
		subFolder = L"x86";
		zydisMode = ZYDIS_MACHINE_MODE_LEGACY_32;
		zydisWidth = ZYDIS_ADDRESS_WIDTH_32;
		auto ntHeaderCurrent = reinterpret_cast<PIMAGE_NT_HEADERS32>(ntHeader);
		mainInfo.EntryAddress = static_cast<DWORD_PTR>(ntHeaderCurrent->OptionalHeader.AddressOfEntryPoint);
	}

	IDiaDataSource* g_pDiaDataSource;
	IDiaSession* g_pDiaSession;
	IDiaSymbol* g_pGlobalSymbol;

	if (!LoadDataFromPdb(pePath.c_str(), &g_pDiaDataSource, &g_pDiaSession, &g_pGlobalSymbol))
	{
		printf("LoadDataFromPdb failed\n");
		return false;
	}

	if (!GetMainSignature(g_pGlobalSymbol, mainInfo))
	{
		//fwprintf(stderr, L"[idenLib - FAILED] GetMainSignature failed\n");
		return false;
	}

	if (!mainInfo.Dirty)
	{
		fwprintf(stderr, L"[idenLib - INFO] Can not generate a signature: %s\n", pePath.c_str());
		return true;
	}

	fs::path mainSigPath = symExPath;
	mainSigPath += L"\\";
	mainSigPath += subFolder;
	if (!exists(mainSigPath))
	{
		create_directories(mainSigPath);
	}
	mainSigPath += L"\\";
	mainSigPath += entryPointSignatures;

	std::unordered_map<std::string, std::string> mainSigs;

	if (exists(mainSigPath))
	{
		PBYTE decompressedData{};
		if (!DecompressFile(mainSigPath, decompressedData) || !decompressedData)
		{
			fwprintf_s(stderr, L"[idenLib - FAILED] failed to decompress the file: %s\n", mainSigPath.c_str());
			return false;
		}
		const char seps[] = "\n";
		char* next_token = nullptr;
		char* line = strtok_s(reinterpret_cast<char*>(decompressedData), seps, &next_token);
		while (line != nullptr)
		{
			std::vector<std::string> vec{};
			Split(line, vec);
			if (vec.size() != 2)
			{
				fwprintf(stderr, L"[idenLib - FAILED] SIG file contains a malformed data, SIG path: %s\n",
				         mainSigPath.c_str());
				return false;
			}
			// vec[0] opcode
			// vec[1] name
			mainSigs[vec[0]] = vec[1];

			line = strtok_s(nullptr, seps, &next_token);
		}


		delete[] decompressedData;
	}
	mainSigs[mainInfo.opcodes_index] = mainInfo.EntryName;

	fs::path sigPathTmp = mainSigPath;
	sigPathTmp += L".tmp";
	if (exists(sigPathTmp))
	{
		fs::remove(sigPathTmp);
	}

	FILE* hFile = nullptr;
	fopen_s(&hFile, sigPathTmp.string().c_str(), "wb");
	if (!hFile)
	{
		fwprintf(stderr, L"[idenLib - FAILED] failed to create sig file: %s\n", mainSigPath.c_str());
		return false;
	}
	for (const auto& n : mainSigs)
	{
		const auto bothSize = n.first.size() + n.second.size() + 3; // space + \n + 0x00
		const auto opcodesName = new CHAR[bothSize];
		sprintf_s(opcodesName, bothSize, "%s %s\n", n.first.c_str(), n.second.c_str());
		fwrite(opcodesName, bothSize - 1, 1, hFile); // -1 without 0x00
	}
	fclose(hFile);

	if (CompressFile(sigPathTmp, mainSigPath))
	{
		wprintf(L"[idenLib] Created SIG file: %s based on %s\n", mainSigPath.c_str(), pePath.c_str());
	}
	else
	{
		fwprintf(stderr, L"[idenLib - FAILED] compression failed\n");
	}
	if (exists(sigPathTmp))
		fs::remove(sigPathTmp);


	if (exists(mainSigPath) && is_empty(mainSigPath))
	{
		DeleteFile(mainSigPath.c_str());
	}


	return true;
}

bool LoadDataFromPdb(
	const wchar_t* szFilename,
	IDiaDataSource** ppSource,
	IDiaSession** ppSession,
	IDiaSymbol** ppGlobal)
{
	TCHAR wszExt[MAX_PATH]{};

	// Obtain access to the provider
	auto hr = CoCreateInstance(__uuidof(DiaSource),
	                           nullptr,
	                           CLSCTX_INPROC_SERVER,
	                           __uuidof(IDiaDataSource),
	                           reinterpret_cast<void **>(ppSource));

	if (FAILED(hr))
	{
		fwprintf(stderr, L"[idenLib - Failed] CoCreateInstance failed - HRESULT = %08X\n", hr);

		return false;
	}

	_wsplitpath_s(szFilename, nullptr, 0, nullptr, 0, nullptr, 0, wszExt, MAX_PATH);

	if (!_wcsicmp(wszExt, L".pdb"))
	{
		// Open and prepare a program database (.pdb) file as a debug data source

		hr = (*ppSource)->loadDataFromPdb(szFilename);

		if (FAILED(hr))
		{
			fwprintf(stderr, L"[idenLib - FAILED] loadDataFromPdb failed - HRESULT = %08X\n", hr);

			return false;
		}
	}

	else
	{
		// Open and prepare the debug data associated with the .exe/.dll file
		hr = (*ppSource)->loadDataForExe(szFilename, nullptr, nullptr);
		if (hr != S_OK)
		{
			wprintf(L"loadDataForExe failed - HRESULT = %x\n", hr);
			return false;
		}
	}

	// Open a session for querying symbols

	hr = (*ppSource)->openSession(ppSession);

	if (FAILED(hr))
	{
		fwprintf(stderr, L"[idenLib - FAILED] openSession failed - HRESULT = %08X\n", hr);

		return false;
	}

	// Retrieve a reference to the global scope

	hr = (*ppSession)->get_globalScope(ppGlobal);

	if (hr != S_OK)
	{
		fwprintf(stderr, L"[idenLib - FAILED] get_globalScope failed\n");

		return false;
	}

	return true;
}

bool GetMainSignature(__in IDiaSymbol* pGlobal, MAIN_SIG_INFO& mainInfo)
{
	IDiaEnumSymbols* pEnumSymbols;
	IDiaSymbol* pSymbol;
	ULONG celt = 0;


	// find RVA of a main function
	mainInfo.mainVA = 0;
	if (SUCCEEDED(pGlobal->findChildren(SymTagFunction, nullptr, nsNone, &pEnumSymbols)))
	{
		while (!mainInfo.mainVA && SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1))
		{
			GetMainRva(pSymbol, mainInfo);

			pSymbol->Release();
		}

		pEnumSymbols->Release();
	}

	else
	{
		fwprintf(stderr, L"[IdenLib - FAILED] findChildren(SymTagFunction, ...) failed \n");

		return false;
	}

	// find a function which calls main
	if (!mainInfo.mainVA)
	{
		fwprintf(stderr, L"[IdenLib - FAILED] failed to find main RVA\n");
		return false;
	}

	if (SUCCEEDED(pGlobal->findChildren(SymTagFunction, nullptr, nsNone, &pEnumSymbols)))
	{
		while (!mainInfo.Dirty && SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1))
		{
			FindCallerSignature(pSymbol, mainInfo);

			pSymbol->Release();
		}

		pEnumSymbols->Release();
	}


	return mainInfo.Dirty;
}

void FindCallerSignature(__in IDiaSymbol* pSymbol, MAIN_SIG_INFO& mainInfo)
{
	DWORD dwRva{};
	ULONGLONG length{};

	if (!pSymbol)
		return;

	DWORD dwSymTag{};
	if (pSymbol->get_symTag(&dwSymTag) != S_OK)
	{
		return;
	}

	auto isFunc = FALSE;
	pSymbol->get_function(&isFunc);
	if (!isFunc && dwSymTag != SymTagFunction)
		return;

	if (pSymbol->get_length(&length) != S_OK)
	{
		return;
	}

	if (pSymbol->get_relativeVirtualAddress(&dwRva) != S_OK)
	{
		dwRva = 0xFFFFFFFF;
	}

	// 444444...44_123 main
	// opcodes_mainInstrCount mainName
	GetCallerOpcodes(reinterpret_cast<PBYTE>(mainInfo.baseAddress + dwRva), length, mainInfo);
}

void GetCallerOpcodes(__in PBYTE funcVa, __in SIZE_T length, MAIN_SIG_INFO& mainInfo)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, zydisMode, zydisWidth);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;
	auto detected = false;

	size_t callInstr = 0;
	while (		ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, length - offset,
		&instruction)))
	{
		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			auto& callOperand = instruction.operands[0];
			ZyanU64 callVa{};
			auto instr = reinterpret_cast<ZyanU64>(funcVa) + offset;
			if (callOperand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && callOperand.imm.is_relative &&				ZYAN_SUCCESS(
ZydisCalcAbsoluteAddress(&instruction, &callOperand, instr, &callVa)))
			{
				if (callVa == mainInfo.mainVA)
				{
					detected = true;
					callInstr = offset;
					break;
				}
			}
		}
		offset += instruction.length;
	}

	if (!detected)
	{
		return;
	}

	offset = 0;
	auto cSize = length * 2;
	if (cSize < 3) // CHAR opcode[3];
	{
		return;
	}
	auto opcodesBuf = static_cast<PCHAR>(malloc(cSize)); // // we need to resize the buffer
	if (!opcodesBuf)
	{
		return;
	}
	SIZE_T counter = 0;
	const auto maxLength = length > MAX_FUNC_SIZE ? MAX_FUNC_SIZE : length;
	while (		ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, maxLength - offset,
		&instruction)))
	{
		CHAR opcode[3];
		sprintf_s(opcode, "%02x", instruction.opcode);

		memcpy_s(opcodesBuf + counter, cSize - counter, opcode, sizeof(opcode));
		counter += 2;

		offset += instruction.length;
	}
	auto tmpPtr = static_cast<PCHAR>(realloc(opcodesBuf, counter + 1)); // +1 for 0x00
	if (!tmpPtr)
		return;
	opcodesBuf = tmpPtr;


	mainInfo.Dirty = true;
	// Two ways to index a main function location
	std::string mainOpcodes{opcodesBuf};
	mainOpcodes += "_" + std::to_string(callInstr); // _123 => call "main" offset = func + 123
	signed long distanceFromEntry = reinterpret_cast<DWORD_PTR>(funcVa) + callInstr - (mainInfo.EntryAddress + mainInfo.
		baseAddress);
	mainOpcodes += "!" + std::to_string(distanceFromEntry); // !567 => call "main" offset = EP + 567
	mainInfo.opcodes_index = mainOpcodes;


	free(opcodesBuf);
}

void GetMainRva(__in IDiaSymbol* pSymbol, MAIN_SIG_INFO& mainInfo)
{
	DWORD dwRva{};

	if (!pSymbol)
		return;

	DWORD dwSymTag{};
	if (pSymbol->get_symTag(&dwSymTag) != S_OK)
	{
		return;
	}

	auto isFunc = FALSE;
	pSymbol->get_function(&isFunc);
	if (!isFunc && dwSymTag != SymTagFunction)
		return;

	if (pSymbol->get_relativeVirtualAddress(&dwRva) != S_OK)
	{
		dwRva = 0xFFFFFFFF;
	}

	BSTR bstrName;
	if (pSymbol->get_name(&bstrName) == S_OK)
	{
		const std::wstring name{bstrName};

		// mainCRTStartup(or wmainCRTStartup) 			An application that uses / SUBSYSTEM:CONSOLE; calls main(or wmain)
		// WinMainCRTStartup(or wWinMainCRTStartup) 	An application that uses / SUBSYSTEM:WINDOWS; calls WinMain(or wWinMain), which must be defined to use __stdcall
		// _DllMainCRTStartup 							A DLL; calls DllMain if it exists, which must be defined to use __stdcall

		// main wmain WinMain or wWinMain
		if (name == L"main" || name == L"wmain" || name == L"WinMain" || name == L"wWinMain")
		{
			mainInfo.mainVA = dwRva + mainInfo.baseAddress;
			mainInfo.EntryName = std::string{name.begin(), name.end()};
		}

		SysFreeString(bstrName);
	}
}
