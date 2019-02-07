#include "disassamble.h"

_Success_(return)
bool GetOpcodeBuf(__in PBYTE funcVa, __in SIZE_T length, __out PUCHAR& opcodeBuf, __out ULONG& sizeOfBuf)
{
	ZydisDecoder decoder;

	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;

	opcodeBuf = static_cast<PBYTE>(malloc(length)); // // we need to resize the buffer
	if (!opcodeBuf)
	{
		return false;
	}
	size_t counter = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, funcVa + offset, length - offset,
		&instruction)))
	{
		opcodeBuf[counter++] = instruction.opcode;

		offset += instruction.length;
	}
	opcodeBuf = static_cast<PBYTE>(realloc(opcodeBuf, counter));
	sizeOfBuf = counter;

	return counter != 0;
}
