#pragma once
#ifndef YADENGINE_H
#define YADENGINE_H

#include "Header.h"
#include "Opcodes.h"
#define MAX_MEMORY_SIZE 512000

class YADEngine
{
public:

	HANDLE hLoadedFile;
	BYTE* ptrMemBase;
	Opcodes* opcodes;

	YADEngine();
	~YADEngine();

	bool writeVirtualMemoryDword(DWORD address, DWORD value);
	bool writeVirtualMemoryWord(DWORD address, WORD value);
	bool writeVirtualMemoryByte(DWORD address, BYTE value);

	DWORD readVirtualMemoryDword(DWORD address);
	WORD readVirtualMemoryWord(DWORD address);
	BYTE readVirtualMemoryByte(DWORD address);

	DWORD Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt);
	int loadExecutable(char* lpFileName, DWORD* lpEntryPoint);

	bool createStack(DWORD desiredStackMaxSize);
	bool stackPush(DWORD value);
	bool stackPop(DWORD* value);

	bool fetchInstruction(OpcodeDefinition* nextOpcode, BOOLEAN* isDoubleLenOpcode);
	bool executeStep();
};

#endif