#pragma once
#include "Header.h"
class Registers
{
public:
	static DWORD* eax;
	static DWORD* ebx;
	static DWORD* ecx;
	static DWORD* edx;

	static DWORD* esi;
	static DWORD* edi;

	static DWORD* esp;
	static DWORD* ebp;

	static DWORD* EBP_MAX;

	static DWORD* eip;

	Registers();
	~Registers();

	static bool SetEip(_In_ DWORD newInstructionPtr);
	static bool IncrementEip();
	static bool IncrementEipBy(_In_ int nBytes);
	static bool GetRegisterContentByte(_In_ DWORD* reg, _Out_ BYTE* val);
	static bool GetRegisterContentWord(_In_ DWORD* reg, _Out_ WORD* val);
	static bool GetRegisterContentDword(_In_ DWORD* reg, _Out_ DWORD* val);

};

