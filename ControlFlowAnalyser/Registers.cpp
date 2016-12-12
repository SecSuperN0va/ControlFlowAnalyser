#include "Registers.h"

DWORD* Registers::eax = NULL;
DWORD* Registers::ebx = NULL;
DWORD* Registers::ecx = NULL;
DWORD* Registers::edx = NULL;

DWORD* Registers::esi = NULL;
DWORD* Registers::edi = NULL;

DWORD* Registers::esp = NULL;
DWORD* Registers::ebp = NULL;

DWORD* Registers::EBP_MAX = NULL;


DWORD* Registers::eip = NULL;


Registers::Registers()
{
}


Registers::~Registers()
{
}

bool Registers::SetEip(DWORD newInstructionPtr){
	Registers::eip = (DWORD*)newInstructionPtr;
	return true;
}

bool Registers::IncrementEip(){
	Registers::eip = (DWORD*)((BYTE*)Registers::eip + 1);
	return true;
}

bool Registers::IncrementEipBy(int nBytes){
	while (nBytes){
		Registers::IncrementEip();
		nBytes--;
	}
	return true;
}

bool Registers::GetRegisterContentByte(DWORD* reg, BYTE* val){
	*val = (BYTE)*reg;
	return true;
}

bool Registers::GetRegisterContentWord(DWORD* reg, WORD* val){
	*val = (WORD)*reg;
	return true;
}

bool Registers::GetRegisterContentDword(DWORD* reg, DWORD* val){
	*val = (DWORD)*reg;
	return true;
}

