#pragma once
#include "Header.h"

class OpcodeDefinition
{
public:
	CHAR* mnemonic;
	BYTE opcode;
	BOOLEAN SingleByteInstruction;
	BOOLEAN TwoByteOpcode;
	BOOLEAN InstructionPrefixBytePresent;
	BOOLEAN AddressSizePrefixBytePresent;
	BOOLEAN OperandSizePrefixBytePresent;
	BOOLEAN SegmentOverrideBytePresent;
	BOOLEAN ModRMBytePresent;
	BOOLEAN SIBBytePresent;
	BOOLEAN DisplacementPresent;
	BOOLEAN ImmediatePresent;
	DWORD* Source;
	DWORD* Destination;

	OpcodeDefinition(CHAR* mnemonic,
		BYTE opcode, 
		BOOLEAN SingleByteInstruction,
		BOOLEAN isTwoByteOpcode, 
		BOOLEAN hasInstructionPrefixByte, 
		BOOLEAN hasAddressSizePrefixByte, 
		BOOLEAN hasOperandSizePrefixByte, 
		BOOLEAN hasSegmentOverrideByte, 
		BOOLEAN hasModRMByte, 
		BOOLEAN hasSIBByte, 
		BOOLEAN hasDisplacement, 
		BOOLEAN hasImmediate);

	~OpcodeDefinition();

	BYTE getOpcode();
	BOOLEAN isSingleByteInstruction();
	BOOLEAN getMnemonic(char* lpMnemonic, int maxMnemonicLen);
	BOOLEAN isTwoByteOpcode();
	BOOLEAN hasInstructionPrefixByte();
	BOOLEAN hasAddressSizePrefixByte();
	BOOLEAN hasOperandSizePrefixByte();
	BOOLEAN hasSegmentOverrideBytePresent();
	BOOLEAN hasModRMByte();
	BOOLEAN hasSIDBytePresent();
	BOOLEAN hasDisplacement();
	BOOLEAN hasImmediate();
	BOOLEAN SetSource(DWORD* sourceAddress);
	BOOLEAN SetDestination(DWORD* sourceAddress);

};

class Opcodes
{
public:
	
	OpcodeDefinition* opcodeList[256];

	Opcodes();
	~Opcodes();

	OpcodeDefinition** GetOpcodeList();

	BOOLEAN GetOpcode(BYTE opcodeByte, OpcodeDefinition* opDef);
};

