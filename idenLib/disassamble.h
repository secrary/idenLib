#pragma once

#include "utils.h"

_Success_(return)
bool GetOpcodeBuf(__in PBYTE funcVa, __in SIZE_T length, __out PCHAR& opcodesBuf, __in bool countBranches,
                  __out size_t& cBranches);
