#include "disassamble.h"

_Success_(return)
bool GetOpcodeBuf(__in PBYTE funcVa, __in SIZE_T length, __out PCHAR& opcodesBuf, __in bool countBranches, __out size_t& cBranches)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, zydisMode, zydisWidth);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;

	if (countBranches)
	{
		cBranches = 0;
	}

	auto cSize = length * 2;
	opcodesBuf = static_cast<PCHAR>(malloc(cSize)); // // we need to resize the buffer
	if (!opcodesBuf)
	{
		return false;
	}
	SIZE_T counter = 0;
	while (		ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, length - offset,
		&instruction)))
	{
		CHAR opcode[3];
		sprintf_s(opcode, "%02x", instruction.opcode);

		memcpy_s(opcodesBuf + counter, cSize - counter, opcode, sizeof(opcode));
		counter += 2;

		if (countBranches)
		{
			if (instruction.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
				cBranches++;
			}
		}

		offset += instruction.length;
	}
	auto tmpPtr = static_cast<PCHAR>(realloc(opcodesBuf, counter + 1)); // +1 for 0x00
	if (!tmpPtr)
		return false;
	opcodesBuf = tmpPtr;

	return counter != 0;
}
