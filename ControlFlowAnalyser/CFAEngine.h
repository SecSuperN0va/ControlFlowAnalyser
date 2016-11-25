#pragma once
#include "Header.h"
#define MAX_MEMORY_SIZE 512000

class CFAEngine
{
public:

	HANDLE hLoadedFile;
	BYTE* ptrMemBase;

	CFAEngine();
	~CFAEngine();

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

	bool fetchInstruction(BYTE* nextOpcode, BOOLEAN* isDoubleLenOpcode);
	bool executeStep();
};

