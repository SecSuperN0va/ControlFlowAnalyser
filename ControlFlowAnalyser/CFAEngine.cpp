#include "CFAEngine.h"
#include "Registers.h"

CFAEngine::CFAEngine()
{
	ptrMemBase = (BYTE*)malloc(MAX_MEMORY_SIZE * sizeof(BYTE));
	if (ptrMemBase == NULL){
		cout << "Failed to allocate virtual memory space!\n";
	}
	else {
		cout << MAX_MEMORY_SIZE << " bytes of virtual memory allocated\n";
		memset(ptrMemBase, 0xCC, MAX_MEMORY_SIZE);
		cout << "Virtual memory allocation filled with interupts\n";
	}
}

CFAEngine::~CFAEngine()
{
}

bool CFAEngine::writeVirtualMemoryDword(DWORD address, DWORD value){
	DWORD* realAddress;
	if (address >= MAX_MEMORY_SIZE){
		cerr << "Requested memory write address invalid\n";
		return false;
	}

	cout << "Writing DWORD: " << hex << value << " to virtual address: " << hex << address << endl;
	realAddress = (DWORD*)(address + ptrMemBase);
	*realAddress = value;
	if (*realAddress == value){
		//cout << "Written DWORD: " << hex << *realAddress << " to physical address: " << hex << realAddress << endl;
		return true;
	}
	return false;
}

bool CFAEngine::writeVirtualMemoryWord(DWORD address, WORD value){
	WORD* realAddress;
	if (address >= MAX_MEMORY_SIZE){
		cerr << "Requested memory write address invalid\n";
		return false;
	}

	cout << "Writing WORD: " << hex << value << " to virtual address: " << hex << address << endl;
	realAddress = (WORD*)(address + ptrMemBase);
	*realAddress = value;
	if (*realAddress == value){
		//cout << "Written WORD: " << hex << *realAddress << " to physical address: " << hex << realAddress << endl;
		return true;
	}
	return false;
}

bool CFAEngine::writeVirtualMemoryByte(DWORD address, BYTE value){
	BYTE* realAddress;
	if (address >= MAX_MEMORY_SIZE){
		cerr << "Requested memory write address invalid\n";
		return false;
	}

	cout << "Writing BYTE: " << hex << value << " to virtual address: " << hex << address << endl;
	realAddress = (BYTE*)(address + ptrMemBase);
	*realAddress = value;
	if (*realAddress == value){
		//cout << "Written BYTE: " << hex << *realAddress << " to physical address: " << hex << realAddress << endl;
		return true;
	}
	return false;
}

DWORD CFAEngine::readVirtualMemoryDword(DWORD address){
	if (address >= MAX_MEMORY_SIZE){
		cerr << "Requested DWORD memory read address invalid\n";
		return false;
	}
	DWORD* realAddress = (DWORD*)(ptrMemBase + address);
	return *realAddress;
}

WORD CFAEngine::readVirtualMemoryWord(DWORD address){
	if (address >= MAX_MEMORY_SIZE){
		cerr << "Requested WORD memory read address invalid\n";
		return false;
	}
	WORD* realAddress = (WORD*)(ptrMemBase + address);
	return *realAddress;
}

BYTE CFAEngine::readVirtualMemoryByte(DWORD address){
	if (address >= MAX_MEMORY_SIZE){
		cerr << "Requested BYTE memory read address invalid\n";
		return false;
	}
	BYTE* realAddress = (BYTE*)(ptrMemBase + address);
	return *realAddress;
}

DWORD CFAEngine::Rva2Offset(DWORD rva, PIMAGE_SECTION_HEADER psh, PIMAGE_NT_HEADERS pnt)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSeh;
	if (rva == 0)
	{
		return (rva);
	}
	pSeh = psh;
	for (i = 0; i < pnt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSeh->VirtualAddress && rva < pSeh->VirtualAddress +
			pSeh->Misc.VirtualSize)
		{
			break;
		}
		pSeh++;
	}
	return (rva - pSeh->VirtualAddress + pSeh->PointerToRawData);
}

int CFAEngine::loadExecutable(char* lpFileName, DWORD* lpEntryPoint){
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	PVOID image, mem, base;
	DWORD i, read, nSizeOfFile;

	cout << "Loading executable into memory: " << lpFileName << endl;
	hLoadedFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (hLoadedFile == INVALID_HANDLE_VALUE)
	{
		printf("\nError: Unable to open the executable. CreateFile failed with error %d\n", GetLastError());
		return 0;
	}

	nSizeOfFile = GetFileSize(hLoadedFile, NULL);

	image = VirtualAlloc(NULL, nSizeOfFile, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the executable file

	if (!ReadFile(hLoadedFile, image, nSizeOfFile, &read, NULL)) // Read the executable file from disk
	{
		printf("\nError: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());
		return 0;
	}

	CloseHandle(hLoadedFile); // Close the file handle

	pIDH = (PIMAGE_DOS_HEADER)image;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		printf("\nError: Invalid executable format.\n");
		return 0;
	}
	
	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew); // Get the address of the IMAGE_NT_HEADERS

	printf("\nAllocating memory in child process.\n");

	mem = VirtualAlloc((PVOID)pINH->OptionalHeader.ImageBase, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the executable image

	if (!mem)
	{
		mem = VirtualAlloc(NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allow it to pick its own address
	}

	if ((DWORD)mem != pINH->OptionalHeader.ImageBase)
	{
		printf("\nProper base could not be reserved.\n");

		return 0;
	}

	printf("\nMemory allocated. Address: %#X\n", mem);


	printf("\nResolving Imports\n");


	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
	{
		PIMAGE_SECTION_HEADER pSech = IMAGE_FIRST_SECTION(pINH);

		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)image + Rva2Offset(pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSech, pINH));
		LPSTR libname;
		size_t i = 0;
		// Walk until you reached an empty IMAGE_IMPORT_DESCRIPTOR
		while (pImportDescriptor->Name != NULL)
		{
			printf("Library Name   :");
			//Get the name of each DLL
			libname = (PCHAR)((DWORD_PTR)image + Rva2Offset(pImportDescriptor->Name, pSech, pINH));
			printf("%s\n", libname);

			HMODULE libhandle = GetModuleHandleA(libname);
			if (!libhandle)
				libhandle = LoadLibraryA(libname);

			PIMAGE_THUNK_DATA nameRef = (PIMAGE_THUNK_DATA)((DWORD_PTR)image + Rva2Offset(pImportDescriptor->Characteristics, pSech, pINH));
			PIMAGE_THUNK_DATA symbolRef = (PIMAGE_THUNK_DATA)((DWORD_PTR)image + Rva2Offset(pImportDescriptor->FirstThunk, pSech, pINH));
			for (; nameRef->u1.AddressOfData; nameRef++, symbolRef++)
			{
				if (nameRef->u1.AddressOfData & 0x80000000)
				{
					symbolRef->u1.AddressOfData = (DWORD)GetProcAddress(libhandle, (LPCSTR)MAKEINTRESOURCE(nameRef->u1.AddressOfData));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)image + Rva2Offset(nameRef->u1.AddressOfData, pSech, pINH));
					symbolRef->u1.AddressOfData = (DWORD)GetProcAddress(libhandle, (LPCSTR)&thunkData->Name);
				}
			}
			pImportDescriptor++; //advance to next IMAGE_IMPORT_DESCRIPTOR
			i++;

		}
	}

	printf("\nWriting executable image into child process.\n");

	memcpy(mem, image, pINH->OptionalHeader.SizeOfHeaders); // Write the header of the executable

	for (i = 0; i < pINH->FileHeader.NumberOfSections; i++)
	{
		pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)image + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i*sizeof(IMAGE_SECTION_HEADER)));
		memcpy((PVOID)((LPBYTE)mem + pISH->VirtualAddress), (PVOID)((LPBYTE)image + pISH->PointerToRawData), pISH->SizeOfRawData); //Write the remaining sections
	}

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size && (pINH->OptionalHeader.ImageBase != (DWORD)mem))
	{
		printf("\nBase relocation.\n");

		DWORD i, num_items;
		DWORD_PTR diff;
		IMAGE_BASE_RELOCATION* r;
		IMAGE_BASE_RELOCATION* r_end;
		WORD* reloc_item;

		diff = (DWORD)mem - pINH->OptionalHeader.ImageBase; //Difference between memory allocated and the executable's required base.
		r = (IMAGE_BASE_RELOCATION*)((DWORD)mem + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress); //The address of the first I_B_R struct 
		r_end = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)r + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)); //The addr of the last

		for (; r < r_end; r = (IMAGE_BASE_RELOCATION*)((DWORD_PTR)r + r->SizeOfBlock))
		{
			reloc_item = (WORD*)(r + 1);
			num_items = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (i = 0; i < num_items; ++i, ++reloc_item)
			{
				switch (*reloc_item >> 12)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*(DWORD_PTR*)((DWORD)mem + r->VirtualAddress + (*reloc_item & 0xFFF)) += diff;
					break;
				default:
					return 0;
				}
			}
		}
	}

	DWORD entrypoint = (DWORD)((LPBYTE)mem + pINH->OptionalHeader.AddressOfEntryPoint);

	printf("\nNew entry point: %#X\n", entrypoint);

	VirtualFree(image, 0, MEM_RELEASE); // Free the allocated memory

	*lpEntryPoint = entrypoint;
	return 1;
}

bool CFAEngine::createStack(DWORD desiredStackMaxSize){
	if (!desiredStackMaxSize){
		cout << "Setting default stack max size\n";
		desiredStackMaxSize = 1024;
	}

	Registers::EBP_MAX = (DWORD*)malloc(desiredStackMaxSize * sizeof(BYTE));
	Registers::ebp = Registers::EBP_MAX;
	Registers::esp = Registers::ebp;

	return true;
}

bool CFAEngine::stackPush(DWORD value){
	*Registers::esp = value;
	Registers::esp = (DWORD*)((DWORD*)Registers::esp + 1);
	return true;
}

bool CFAEngine::stackPop(DWORD* value){
	if (Registers::esp < Registers::ebp + 1){
		cout << "Attempting to pop past base of stack frame!!!\n";
		return false;
	}
	*value = *Registers::esp;
	Registers::esp = (DWORD*)((DWORD*)Registers::esp - 1);
	return true;
}

//see this: http://www.c-jump.com/CIS77/CPU/x86/lecture.html
bool CFAEngine::fetchInstruction(BYTE* nextOpcode, BOOLEAN* isDoubleLenOpcode){
	cout << " -+- FETCHING INSTRUCTION -+-\n";
	if (Registers::eip == NULL){
		return false;
	}
	
	BYTE opcodeByte;
	BYTE ins;
	BYTE sz;
	BYTE dir;
	BYTE ModRegRMByte;
	BYTE mod;
	BYTE reg;
	BYTE RM;
	BOOLEAN hasImmediateConstant = false;
	BOOLEAN twoByteOpcode = false;

	/*
		Extract opcode byte
	*/
	Registers::GetRegisterContentByte(Registers::eip, &opcodeByte);
	Registers::IncrementEipBy(1);

	if (opcodeByte == 0x0F){
		twoByteOpcode = true;
		cout << "TWO BYTE OPCODE IDENTIFIED!\n";
		Registers::IncrementEipBy(1);
	} else if (opcodeByte & 0x80){
		hasImmediateConstant = true;
		cout << "Instruction has immediate constant\n";
	}

	ins = opcodeByte & 0xFC;
	sz = opcodeByte & 0x01;
	dir = (opcodeByte & 0x02) >> 1;

	cout << "\tINSTRUCTION:\t" << int(ins) << endl;
	cout << "\tOPCODE SIZE:\t" << int(sz) << endl;
	cout << "\tDIRECTION:\t" << int(dir) << endl;
	
	if (sz){
		cout << "\t(32)/16 bit operands selected!\n";
	} else {
		cout << "\t8-bit operands selected!\n";
	}

	if (dir){
		cout << "\tOperating on register (from R/M)\n";
	} else {
		cout << "\tOperating on R/M (from register)\n";
	}

	/*if (hasImmediateConstant){

	} else {*/
		/*
		Extract MOD-REG-R/M Byte
		*/
		Registers::GetRegisterContentByte(Registers::eip, &ModRegRMByte);
		mod = (ModRegRMByte & 0xC0) >> 6; // XX......
		reg = (ModRegRMByte & 0x38) >> 3; // ..XXX...
		RM = ModRegRMByte & 0x07;         // .....XXX

		cout << "\tMOD:\t" << int(mod) << endl;
		cout << "\tREG:\t" << int(reg) << endl;
		cout << "\tR/M:\t" << int(RM) << endl;

		switch (mod){
		case 0x00:
			cout << "Register indirect addressing mode (or SIB with no displacement)\n";
			break;
		case 0x01:
			cout << "One-byte signed displacement follows addressing mode byte\n";
			break;
		case 0x02:
			cout << "Four-byte signed displacement follows addressing mode byte\n";
			break;
		case 0x03:
			cout << "Register addressing mode\n";
			break;
		default:
			cerr << "Invalid MOD code... wtf?!?!\n";
			break;
		}

		cout << "REGISTER: ";

		switch (reg){
		case 0x00:
			cout << "EAX";
			break;
		case 0x01:
			cout << "ECX";
			break;
		case 0x02:
			cout << "EDX";
			break;
		case 0x03:
			cout << "EBX";
			break;
		case 0x04:
			cout << "ESP";
			break;
		case 0x05:
			cout << "EBP";
			break;
		case 0x06:
			cout << "ESI";
			break;
		case 0x07:
			cout << "EDI";
			break;
		default:
			break;
		}

		cout << endl;

		cout << "MOD R/M: ";

		switch (RM){
		case 0x00:
			cout << "EAX";
			break;
		case 0x01:
			cout << "ECX";
			break;
		case 0x02:
			cout << "EDX";
			break;
		case 0x03:
			cout << "EBX";
			break;
		case 0x04:
			cout << "ESP";
			break;
		case 0x05:
			cout << "EBP";
			break;
		case 0x06:
			cout << "ESI";
			break;
		case 0x07:
			cout << "EDI";
			break;
		default:
			break;
		}

		cout << endl;
	//}

	*nextOpcode = opcodeByte;
	*isDoubleLenOpcode = twoByteOpcode;
	return true;
}

bool CFAEngine::executeStep(){
	BYTE opcode;
	BOOLEAN isDoubleLenOpcode = false;
	DWORD operand;
	DWORD offset;
	BYTE destination;

	DWORD* CURRENT_OPCODE_POINTER = Registers::eip;
	DWORD* CURRENT_OPERAND_POINTER = (DWORD*)((BYTE*)CURRENT_OPCODE_POINTER + sizeof(opcode));

	if (!fetchInstruction(&opcode, &isDoubleLenOpcode)){
		cout << "Fetch failed!" << endl;
		return false;
	}

	if (!isDoubleLenOpcode){
		cout << "Single byte opcode\n";
		switch (opcode)	{
		case 0x55:
			cout << "PUSH EBP\n";
			stackPush((DWORD)Registers::ebp);
			break;
		case 0x5D:
			cout << "POP EBP\n";
			stackPop(Registers::ebp);
			break;
		case 0x83:
			cout << "ADD ";
			destination = (BYTE)*CURRENT_OPERAND_POINTER;
			operand = (DWORD)*((BYTE*)CURRENT_OPERAND_POINTER + 1);
			cout << "DST: " << destination << " | OPD: " << int(operand);
			break;
		case 0x8B:
			cout << "MOV EBP, ";

			break;
		case 0xc3:
			cout << "RET\n";
			break;
		case 0xE8:
			cout << "CALL\n";
			Registers::GetRegisterContentDword(Registers::eip, &offset);
			stackPush((DWORD)(Registers::eip) + sizeof(DWORD));
			Registers::SetEip((DWORD)((BYTE*)Registers::eip + 4 + offset)); // Set eip to offset (start of function)
			break;
		case 0xE9:
			cout << "JMP\n";
			//Action the jump
			Registers::GetRegisterContentDword(Registers::eip, &offset);
			Registers::SetEip((DWORD)((BYTE*)Registers::eip + 4 + offset));
			break;
		case 0xCC:
			cout << "INTERUPT!\n";
			return false;
		default:
			cout << "Unknown opcode: 0x" << opcode << endl;
			break;
		}
	} else {
		cout << "Double byte opcode\n";
		switch (opcode){
		case 0x5C:
			cout << "Double length 5C opcode\n";
			break;
		default:
			cout << "Invalid double length opcode!\n";
			break;
		}
	}
	
	return true;
}

