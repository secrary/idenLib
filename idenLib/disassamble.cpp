#include "disassamble.h"

_Success_(return)
bool GetOpcodeBuf(__in PBYTE funcVa, __in SIZE_T length, __out PCHAR& opcodesBuf)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, ZYDIS_MODE, ZYDIS_ADDRESS_WIDTH);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;

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

		offset += instruction.length;
	}
	auto tmpPtr = static_cast<PCHAR>(realloc(opcodesBuf, counter + 1)); // +1 for 0x00
	if (!tmpPtr)
		return false;
	opcodesBuf = tmpPtr;

	return counter != 0;
}
