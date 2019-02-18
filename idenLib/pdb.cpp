#include "pdb.h"

bool LoadDataFromPdb(const wchar_t* szFilename, IDiaDataSource** ppSource, IDiaSession** ppSession, IDiaSymbol** ppGlobal);
bool GetMainSignature(__in IDiaSymbol* pGlobal, MAIN_SIG_INFO& mainInfo);
void GetMainRva(__in IDiaSymbol* pSymbol, MAIN_SIG_INFO& mainInfo);
void FindCallerSignature(__in IDiaSymbol* pSymbol, MAIN_SIG_INFO& mainInfo);
bool GetCallerOpcodes(__in PBYTE funcVa, __in SIZE_T length, MAIN_SIG_INFO& mainInfo);

bool ProcessMainSignature(const fs::path& pePath, char* entryName)
{
	auto loadAddress = reinterpret_cast<DWORD_PTR>(LoadLibraryEx(pePath.c_str(), nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE));
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
	mainInfo.EntryName = entryName;
	mainInfo.baseAddress = loadAddress;

	if (isx64)
	{
		entryPointSignatures = L"EntryPointSignatures.sig64";
		subFolder = L"x64";
		zydisMode = ZYDIS_MACHINE_MODE_LONG_64;
		zydisWidth = ZYDIS_ADDRESS_WIDTH_64;

	}else
	{
		entryPointSignatures = L"EntryPointSignatures.sig";
		subFolder = L"x86";
		zydisMode = ZYDIS_MACHINE_MODE_LEGACY_32;
		zydisWidth = ZYDIS_ADDRESS_WIDTH_32;
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
		fwprintf(stderr, L"[idenLib - FAILED] GetMainSignature failed\n");
		return false;
	}


	return true;
}

bool LoadDataFromPdb(
	const wchar_t* szFilename,
	IDiaDataSource** ppSource,
	IDiaSession** ppSession,
	IDiaSymbol** ppGlobal)
{
	TCHAR wszExt[MAX_PATH];

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
		if (hr != S_OK) {
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

bool GetMainSignature(IDiaSymbol * pGlobal, MAIN_SIG_INFO& mainInfo)
{
	IDiaEnumSymbols* pEnumSymbols;
	IDiaSymbol* pSymbol;
	ULONG celt = 0;


	// find RVA of a main function
	mainInfo.mainVA = 0;
	if (SUCCEEDED(pGlobal->findChildren(SymTagFunction, NULL, nsNone, &pEnumSymbols)))
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
	// instruction.mnemonic == ZYDIS_MNEMONIC_CALL
	if (SUCCEEDED(pGlobal->findChildren(SymTagFunction, NULL, nsNone, &pEnumSymbols)))
	{
		while (!mainInfo.Dirty && SUCCEEDED(pEnumSymbols->Next(1, &pSymbol, &celt)) && (celt == 1))
		{
			FindCallerSignature(pSymbol, mainInfo);

			pSymbol->Release();
		}

		pEnumSymbols->Release();
	}


	return true;
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
	if (GetCallerOpcodes(PBYTE(mainInfo.baseAddress + dwRva), length, mainInfo) && mainInfo.Dirty)
	{
		printf("Xxx\n");
	}

}

bool GetCallerOpcodes(__in PBYTE funcVa, __in SIZE_T length, MAIN_SIG_INFO & mainInfo)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, zydisMode, zydisWidth);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;

	auto cSize = length * 2;
	auto opcodesBuf = static_cast<PCHAR>(malloc(cSize)); // // we need to resize the buffer
	if (!opcodesBuf)
	{
		return false;
	}
	SIZE_T counter = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, length - offset,
		&instruction)))
	{

		if (instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			auto callRVA = instruction.operands[0];
			ZyanU64 callVa;
			if (callRVA.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && callRVA.imm.is_relative && ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &callRVA, callRVA.imm.value.u, &callVa)))
			{
				printf("%llx", callVa);
			}
		}

		CHAR opcode[3];
		sprintf_s(opcode, "%02x", instruction.opcode);

		memcpy_s(opcodesBuf + counter, cSize - counter, opcode, sizeof(opcode));
		counter += 2;

		offset += instruction.length;
	}
	auto tmpPtr = static_cast<PCHAR>(realloc(opcodesBuf, counter + 1)); // +1 for 0x00
	if (!tmpPtr)
		return false;
	opcodesBuf = tmpPtr;



	return counter != 0;
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
		const std::wstring name{ bstrName };

		// mainCRTStartup(or wmainCRTStartup) 			An application that uses / SUBSYSTEM:CONSOLE; calls main(or wmain)
		// WinMainCRTStartup(or wWinMainCRTStartup) 	An application that uses / SUBSYSTEM:WINDOWS; calls WinMain(or wWinMain), which must be defined to use __stdcall
		// _DllMainCRTStartup 							A DLL; calls DllMain if it exists, which must be defined to use __stdcall

		// main wmain WinMain or wWinMain
		if (name == L"main" || name == L"wmain" || name == L"WinMain" || name == L"wWinMain")
		{
			mainInfo.mainVA = dwRva + mainInfo.baseAddress;
		}

		SysFreeString(bstrName);
	}

}
