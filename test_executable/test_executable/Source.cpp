#include <stdio.h>

int main(){
	__asm{
		mov eax, 0x1
		mov ebx, 0x2
		mov ecx, 0x3
		mov edx, 0x4
		add eax, 0x5
	};
}