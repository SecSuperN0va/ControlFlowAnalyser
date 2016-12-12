#include "Opcodes.h"


OpcodeDefinition::OpcodeDefinition(CHAR* mnemonic, BYTE opcode, BOOLEAN SingleByteInstruction, BOOLEAN isTwoByteOpcode, BOOLEAN hasInstructionPrefixByte, BOOLEAN hasAddressSizePrefixByte, BOOLEAN hasOperandSizePrefixByte, BOOLEAN hasSegmentOverrideByte, BOOLEAN hasModRMByte, BOOLEAN hasSIBByte, BOOLEAN hasDisplacement, BOOLEAN hasImmediate)
{
	this->opcode = opcode;
	this->mnemonic = mnemonic;
	this->SingleByteInstruction = SingleByteInstruction;
	this->TwoByteOpcode = isTwoByteOpcode;
	this->InstructionPrefixBytePresent = hasInstructionPrefixByte;
	this->AddressSizePrefixBytePresent = hasAddressSizePrefixByte;
	this->OperandSizePrefixBytePresent = hasOperandSizePrefixByte;
	this->SegmentOverrideBytePresent = hasSegmentOverrideByte;
	this->ModRMBytePresent = hasModRMByte;
	this->SIBBytePresent = hasSIBByte;
	this->DisplacementPresent = hasDisplacement;
	this->ImmediatePresent = hasImmediate;
	this->Source = NULL;
	this->Destination = NULL;
}


OpcodeDefinition::~OpcodeDefinition()
{
}

BOOLEAN OpcodeDefinition::getMnemonic(char* lpMnemonic, int maxMnemonicLen){
	int i = 0;

	for (i = 0; this->mnemonic[i]; i++) {}

	if (i > maxMnemonicLen) {
		return false;
	}
	strncpy(lpMnemonic, this->mnemonic, i);
	return true;
}

BYTE OpcodeDefinition::getOpcode() {
	return this->opcode;
}

BOOLEAN OpcodeDefinition::isSingleByteInstruction() {
	return this->SingleByteInstruction;
}

BOOLEAN OpcodeDefinition::isTwoByteOpcode() {
	return this->TwoByteOpcode;
}

BOOLEAN OpcodeDefinition::hasInstructionPrefixByte() {
	return this->InstructionPrefixBytePresent;
}

BOOLEAN OpcodeDefinition::hasAddressSizePrefixByte() {
	return this->AddressSizePrefixBytePresent;
}

BOOLEAN OpcodeDefinition::hasOperandSizePrefixByte() {
	return this->OperandSizePrefixBytePresent;
}

BOOLEAN OpcodeDefinition::hasSegmentOverrideBytePresent() {
	return this->SegmentOverrideBytePresent;
}

BOOLEAN OpcodeDefinition::hasModRMByte() {
	return this->ModRMBytePresent;
}

BOOLEAN OpcodeDefinition::hasSIDBytePresent() {
	return this->SIBBytePresent;
}

BOOLEAN OpcodeDefinition::hasDisplacement() {
	return this->DisplacementPresent;
}

BOOLEAN OpcodeDefinition::hasImmediate() {
	return this->ImmediatePresent;
}

BOOLEAN OpcodeDefinition::SetSource(DWORD* sourceAddress) {
	this->Source = sourceAddress;
	return true;
}

BOOLEAN OpcodeDefinition::SetDestination(DWORD* destinationAddress) {
	this->Destination = destinationAddress;
	return true;
}

Opcodes::Opcodes() {
	this->opcodeList[0x00] = new OpcodeDefinition("ADD", 0x00, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x01] = new OpcodeDefinition("ADD", 0x01, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x02] = new OpcodeDefinition("ADD", 0x02, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x03] = new OpcodeDefinition("ADD", 0x03, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x04] = new OpcodeDefinition("ADD", 0x04, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x05] = new OpcodeDefinition("ADD", 0x05, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x06] = new OpcodeDefinition("PUSH", 0x06, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x07] = new OpcodeDefinition("POP", 0x07, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x08] = new OpcodeDefinition("OR", 0x08, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x09] = new OpcodeDefinition("OR", 0x09, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x0A] = new OpcodeDefinition("OR", 0x0A, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x0B] = new OpcodeDefinition("OR", 0x0B, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x0C] = new OpcodeDefinition("OR", 0x0C, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x0D] = new OpcodeDefinition("OR", 0x0D, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x0E] = new OpcodeDefinition("PUSH", 0x0E, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x0F] = new OpcodeDefinition("", 0x0F, false, false, false, false, false, false, false, false, false, false); // TWO BYTE OPCODE

	////////////////////////////////////////////////////////

	this->opcodeList[0x10] = new OpcodeDefinition("ADC", 0x10, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x11] = new OpcodeDefinition("ADC", 0x11, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x12] = new OpcodeDefinition("ADC", 0x12, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x13] = new OpcodeDefinition("ADC", 0x13, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x14] = new OpcodeDefinition("ADC", 0x14, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x15] = new OpcodeDefinition("ADC", 0x15, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x16] = new OpcodeDefinition("PUSH", 0x16,true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x17] = new OpcodeDefinition("POP", 0x17,true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x18] = new OpcodeDefinition("SBB", 0x18, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x19] = new OpcodeDefinition("SBB", 0x19, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x1A] = new OpcodeDefinition("SBB", 0x1A, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x1B] = new OpcodeDefinition("SBB", 0x1B, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x1C] = new OpcodeDefinition("SBB", 0x1C, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x1D] = new OpcodeDefinition("SBB", 0x1D, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x1E] = new OpcodeDefinition("PUSH", 0x1E, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x1F] = new OpcodeDefinition("POP", 0x1F, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x20] = new OpcodeDefinition("AND", 0x20, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x21] = new OpcodeDefinition("AND", 0x21, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x22] = new OpcodeDefinition("AND", 0x22, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x23] = new OpcodeDefinition("AND", 0x23, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x24] = new OpcodeDefinition("AND", 0x24, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x25] = new OpcodeDefinition("AND", 0x25, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x26] = new OpcodeDefinition("ES:", 0X26, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x27] = new OpcodeDefinition("DAA", 0x27, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x28] = new OpcodeDefinition("SUB", 0x28, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x29] = new OpcodeDefinition("SUB", 0x29, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x2A] = new OpcodeDefinition("SUB", 0x2A, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x2B] = new OpcodeDefinition("SUB", 0x2B, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x2C] = new OpcodeDefinition("SUB", 0x2C, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x2D] = new OpcodeDefinition("SUB", 0x2D, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x2E] = new OpcodeDefinition("CS:", 0x2E, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x2F] = new OpcodeDefinition("DAS", 0x2F, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x30] = new OpcodeDefinition("XOR", 0x30, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x31] = new OpcodeDefinition("XOR", 0x31, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x32] = new OpcodeDefinition("XOR", 0x32, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x33] = new OpcodeDefinition("XOR", 0x33, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x34] = new OpcodeDefinition("XOR", 0x34, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x35] = new OpcodeDefinition("XOR", 0x35, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x36] = new OpcodeDefinition("SS:", 0X36, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x37] = new OpcodeDefinition("AAA", 0x37, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x38] = new OpcodeDefinition("CMP", 0x38, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x39] = new OpcodeDefinition("CMP", 0x39, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x3A] = new OpcodeDefinition("CMP", 0x3A, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x3B] = new OpcodeDefinition("CMP", 0x3B, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x3C] = new OpcodeDefinition("CMP", 0x3C, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x3D] = new OpcodeDefinition("CMP", 0x3D, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x3E] = new OpcodeDefinition("DS:", 0x3E, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x3F] = new OpcodeDefinition("AAS", 0x3F, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x40] = new OpcodeDefinition("INC", 0x40, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x41] = new OpcodeDefinition("INC", 0x41, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x42] = new OpcodeDefinition("INC", 0x42, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x43] = new OpcodeDefinition("INC", 0x43, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x44] = new OpcodeDefinition("INC", 0x44, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x45] = new OpcodeDefinition("INC", 0x45, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x46] = new OpcodeDefinition("INC", 0X46, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x47] = new OpcodeDefinition("INC", 0x47, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x48] = new OpcodeDefinition("DEC", 0x48, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x49] = new OpcodeDefinition("DEC", 0x49, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x4A] = new OpcodeDefinition("DEC", 0x4A, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x4B] = new OpcodeDefinition("DEC", 0x4B, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x4C] = new OpcodeDefinition("DEC", 0x4C, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x4D] = new OpcodeDefinition("DEC", 0x4D, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x4E] = new OpcodeDefinition("DEC", 0x4E, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x4F] = new OpcodeDefinition("DEC", 0x4F, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x50] = new OpcodeDefinition("PUSH", 0x50, true, false, false, false, false, false, false, false, false, false); // EAX
	this->opcodeList[0x51] = new OpcodeDefinition("PUSH", 0x51, true, false, false, false, false, false, false, false, false, false); // ECX
	this->opcodeList[0x52] = new OpcodeDefinition("PUSH", 0x52, true, false, false, false, false, false, false, false, false, false); // EDX
	this->opcodeList[0x53] = new OpcodeDefinition("PUSH", 0x53, true, false, false, false, false, false, false, false, false, false); // EBX
	this->opcodeList[0x54] = new OpcodeDefinition("PUSH", 0x54, true, false, false, false, false, false, false, false, false, false); // ESP
	this->opcodeList[0x55] = new OpcodeDefinition("PUSH", 0x55, true, false, false, false, false, false, false, false, false, false); // EBP
	this->opcodeList[0x56] = new OpcodeDefinition("PUSH", 0X56, true, false, false, false, false, false, false, false, false, false); // ESI
	this->opcodeList[0x57] = new OpcodeDefinition("PUSH", 0x57, true, false, false, false, false, false, false, false, false, false); // EDI

	this->opcodeList[0x58] = new OpcodeDefinition("POP", 0x58, true, false, false, false, false, false, false, false, false, false); // EAX
	this->opcodeList[0x59] = new OpcodeDefinition("POP", 0x59, true, false, false, false, false, false, false, false, false, false); // ECX
	this->opcodeList[0x5A] = new OpcodeDefinition("POP", 0x5A, true, false, false, false, false, false, false, false, false, false); // EDX
	this->opcodeList[0x5B] = new OpcodeDefinition("POP", 0x5B, true, false, false, false, false, false, false, false, false, false); // EBX 
	this->opcodeList[0x5C] = new OpcodeDefinition("POP", 0x5C, true, false, false, false, false, false, false, false, false, false); // ESP
	this->opcodeList[0x5D] = new OpcodeDefinition("POP", 0x5D, true, false, false, false, false, false, false, false, false, false); // EBP
	this->opcodeList[0x5E] = new OpcodeDefinition("POP", 0x5E, true, false, false, false, false, false, false, false, false, false); // ESI
	this->opcodeList[0x5F] = new OpcodeDefinition("POP", 0x5F, true, false, false, false, false, false, false, false, false, false); // EDI

	////////////////////////////////////////////////////////

	this->opcodeList[0x60] = new OpcodeDefinition("PUSHA", 0x60, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x61] = new OpcodeDefinition("POPA", 0x61, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x62] = new OpcodeDefinition("BOUND", 0x62, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x63] = new OpcodeDefinition("ARPL", 0x63, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x64] = new OpcodeDefinition("FS:", 0x64, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x65] = new OpcodeDefinition("GS:", 0x65, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x66] = new OpcodeDefinition("OPSIZE:", 0x66, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x67] = new OpcodeDefinition("ADSIZE:", 0x67, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x68] = new OpcodeDefinition("PUSH", 0x68, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x69] = new OpcodeDefinition("IMUL", 0x69, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x6A] = new OpcodeDefinition("PUSH", 0x6A, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x6B] = new OpcodeDefinition("IMUL", 0x6B, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x6C] = new OpcodeDefinition("INSB", 0x6C, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x6D] = new OpcodeDefinition("INSW", 0x6D, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x6E] = new OpcodeDefinition("OUTSB", 0x6E, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x6F] = new OpcodeDefinition("OUTSW", 0x6F, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x70] = new OpcodeDefinition("JO", 0x70, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x71] = new OpcodeDefinition("JNO", 0x71, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x72] = new OpcodeDefinition("JB", 0x72, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x73] = new OpcodeDefinition("JNB", 0x73, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x74] = new OpcodeDefinition("JZ", 0x74, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x75] = new OpcodeDefinition("JNZ", 0x75, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x76] = new OpcodeDefinition("JBE", 0x76, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x77] = new OpcodeDefinition("JA", 0x77, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x78] = new OpcodeDefinition("JS", 0x78, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x79] = new OpcodeDefinition("JNS", 0x79, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x7A] = new OpcodeDefinition("JP", 0x7A, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x7B] = new OpcodeDefinition("JNP", 0x7B, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x7C] = new OpcodeDefinition("JL", 0x7C, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x7D] = new OpcodeDefinition("JNL", 0x7D, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x7E] = new OpcodeDefinition("JLE", 0x7E, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x7F] = new OpcodeDefinition("JNLE", 0x7F, false, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x80] = new OpcodeDefinition("ADD", 0x80, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x81] = new OpcodeDefinition("ADD", 0x81, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x82] = new OpcodeDefinition("SUB", 0x82, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x83] = new OpcodeDefinition("SUB", 0x83, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x84] = new OpcodeDefinition("TEST", 0x84, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x85] = new OpcodeDefinition("TEST", 0x85, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x86] = new OpcodeDefinition("XCHG", 0x86, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x87] = new OpcodeDefinition("XCHG", 0x87, false, false, false, false, false, false, true, false, false, false);

	this->opcodeList[0x88] = new OpcodeDefinition("MOV", 0x88, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x89] = new OpcodeDefinition("MOV", 0x89, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x8A] = new OpcodeDefinition("MOV", 0x8A, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x8B] = new OpcodeDefinition("MOV", 0x8B, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x8C] = new OpcodeDefinition("MOV", 0x8C, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x8D] = new OpcodeDefinition("LEA", 0x8D, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x8E] = new OpcodeDefinition("MOV", 0x8E, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0x8F] = new OpcodeDefinition("POP", 0x8F, false, false, false, false, false, false, true, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0x90] = new OpcodeDefinition("NOP", 0x90, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x91] = new OpcodeDefinition("XCHG", 0x91, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x92] = new OpcodeDefinition("XCHG", 0x92, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x93] = new OpcodeDefinition("XCHG", 0x93, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x94] = new OpcodeDefinition("XCHG", 0x94, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x95] = new OpcodeDefinition("XCHG", 0x95, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x96] = new OpcodeDefinition("XCHG", 0x96, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x97] = new OpcodeDefinition("XCHG", 0x97, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0x98] = new OpcodeDefinition("CBW", 0x98, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x99] = new OpcodeDefinition("CWD", 0x99, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x9A] = new OpcodeDefinition("CALL", 0x9A, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x9B] = new OpcodeDefinition("WAIT", 0x9B, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x9C] = new OpcodeDefinition("PUSHF", 0x9C, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x9D] = new OpcodeDefinition("POPF", 0x9D, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x9E] = new OpcodeDefinition("SAHF", 0x9E, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0x9F] = new OpcodeDefinition("LAHF", 0x9F, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0xA0] = new OpcodeDefinition("MOV", 0xA0, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA1] = new OpcodeDefinition("MOV", 0xA1, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA2] = new OpcodeDefinition("MOV", 0xA2, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA3] = new OpcodeDefinition("MOV", 0xA3, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA4] = new OpcodeDefinition("MOVSB", 0xA4, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA5] = new OpcodeDefinition("MOVSW", 0xA5, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA6] = new OpcodeDefinition("CMPSB", 0xA6, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA7] = new OpcodeDefinition("CMPSW", 0xA7, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0xA8] = new OpcodeDefinition("TEST", 0xA8, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xA9] = new OpcodeDefinition("TEST", 0xA9, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xAA] = new OpcodeDefinition("STOSB", 0xAA, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xAB] = new OpcodeDefinition("STOSW", 0xAB, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xAC] = new OpcodeDefinition("LODSB", 0xAC, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xAD] = new OpcodeDefinition("LODSW", 0xAD, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xAE] = new OpcodeDefinition("SCASB", 0xAE, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xAF] = new OpcodeDefinition("SCASW", 0xAF, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0xB0] = new OpcodeDefinition("MOV", 0xB0, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB1] = new OpcodeDefinition("MOV", 0xB1, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB2] = new OpcodeDefinition("MOV", 0xB2, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB3] = new OpcodeDefinition("MOV", 0xB3, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB4] = new OpcodeDefinition("MOV", 0xB4, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB5] = new OpcodeDefinition("MOV", 0xB5, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB6] = new OpcodeDefinition("MOV", 0xB6, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB7] = new OpcodeDefinition("MOV", 0xB7, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0xB8] = new OpcodeDefinition("MOV", 0xB8, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xB9] = new OpcodeDefinition("MOV", 0xB9, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xBA] = new OpcodeDefinition("MOV", 0xBA, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xBB] = new OpcodeDefinition("MOV", 0xBB, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xBC] = new OpcodeDefinition("MOV", 0xBC, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xBD] = new OpcodeDefinition("MOV", 0xBD, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xBE] = new OpcodeDefinition("MOV", 0xBE, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xBF] = new OpcodeDefinition("MOV", 0xBF, false, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0xC0] = new OpcodeDefinition("£2", 0xC0, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xC1] = new OpcodeDefinition("£2", 0xC1, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xC2] = new OpcodeDefinition("RETN", 0xC2, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xC3] = new OpcodeDefinition("RETN", 0xC3, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xC4] = new OpcodeDefinition("LES", 0xC4, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xC5] = new OpcodeDefinition("LDS", 0xC5, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xC6] = new OpcodeDefinition("MOV", 0xC6, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xC7] = new OpcodeDefinition("MOV", 0xC7, false, false, false, false, false, false, true, false, false, false);

	this->opcodeList[0xC8] = new OpcodeDefinition("ENTER", 0xC8, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xC9] = new OpcodeDefinition("LEAVE", 0xC9, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xCA] = new OpcodeDefinition("RETF", 0xCA, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xCB] = new OpcodeDefinition("RETF", 0xCB, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xCC] = new OpcodeDefinition("INT3", 0xCC, true,  false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xCD] = new OpcodeDefinition("INT", 0xCD, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xCE] = new OpcodeDefinition("INTO", 0xCE, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xCF] = new OpcodeDefinition("IRET", 0xCF, false, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0xD0] = new OpcodeDefinition("£2", 0xD0, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xD1] = new OpcodeDefinition("£2", 0xD1, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xD2] = new OpcodeDefinition("£2", 0xD2, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xD3] = new OpcodeDefinition("£2", 0xD3, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xD4] = new OpcodeDefinition("AAM", 0xD4, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xD5] = new OpcodeDefinition("AAD", 0xD5, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xD6] = new OpcodeDefinition("SALC", 0xD6, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xD7] = new OpcodeDefinition("XLAT", 0xD7, true, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0xD8] = new OpcodeDefinition("ESC", 0xD8, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xD9] = new OpcodeDefinition("ESC", 0xD9, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xDA] = new OpcodeDefinition("ESC", 0xDA, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xDB] = new OpcodeDefinition("ESC", 0xDB, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xDC] = new OpcodeDefinition("ESC", 0xDC, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xDD] = new OpcodeDefinition("ESC", 0xDD, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xDE] = new OpcodeDefinition("ESC", 0xDE, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xDF] = new OpcodeDefinition("ESC", 0xDF, false, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0xE0] = new OpcodeDefinition("LOOPNZ", 0xE0, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE1] = new OpcodeDefinition("LOOPZ", 0xE1, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE2] = new OpcodeDefinition("LOOP", 0xE2, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE3] = new OpcodeDefinition("JCXZ", 0xE3, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE4] = new OpcodeDefinition("IN", 0xE4, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE5] = new OpcodeDefinition("IN", 0xE5, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE6] = new OpcodeDefinition("OUT", 0xE6, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE7] = new OpcodeDefinition("OUT", 0xE7, false, false, false, false, false, false, false, false, false, false);

	this->opcodeList[0xE8] = new OpcodeDefinition("CALL", 0xE8, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xE9] = new OpcodeDefinition("JMP", 0xE9, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xEA] = new OpcodeDefinition("JMP", 0xEA, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xEB] = new OpcodeDefinition("JMP", 0xEB, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xEC] = new OpcodeDefinition("IN", 0xEC, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xED] = new OpcodeDefinition("IN", 0xED, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xEE] = new OpcodeDefinition("OUT", 0xEE, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xEF] = new OpcodeDefinition("OUT", 0xEF, true, false, false, false, false, false, false, false, false, false);

	////////////////////////////////////////////////////////

	this->opcodeList[0xF0] = new OpcodeDefinition("LOCK:", 0xF0, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF1] = new OpcodeDefinition("INT1", 0xF1, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF2] = new OpcodeDefinition("REPNE:", 0xF2, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF3] = new OpcodeDefinition("REP:", 0xF3, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF4] = new OpcodeDefinition("HLT", 0xF4, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF5] = new OpcodeDefinition("CMC", 0xF5, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF6] = new OpcodeDefinition("£3", 0xF6, false, false, false, false, false, false, true, false, false, false);
	this->opcodeList[0xF7] = new OpcodeDefinition("£3", 0xF7, false, false, false, false, false, false, true, false, false, false);

	this->opcodeList[0xF8] = new OpcodeDefinition("CLC", 0xF8, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xF9] = new OpcodeDefinition("STC", 0xF9, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xFA] = new OpcodeDefinition("CLI", 0xFA, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xFB] = new OpcodeDefinition("STI", 0xFB, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xFC] = new OpcodeDefinition("CLD", 0xFC, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xFD] = new OpcodeDefinition("STD", 0xFD, true, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xFE] = new OpcodeDefinition("£4", 0xFE, false, false, false, false, false, false, false, false, false, false);
	this->opcodeList[0xFF] = new OpcodeDefinition("£5", 0xFF, false, false, false, false, false, false, false, false, false, false);
}

Opcodes::~Opcodes() {

}

OpcodeDefinition **Opcodes::GetOpcodeList() {
	return this->opcodeList;
}

BOOLEAN Opcodes::GetOpcode(BYTE opcodeByte, OpcodeDefinition* opDef) {
	
	OpcodeDefinition* requestedOpcode = this->opcodeList[opcodeByte];

	opDef->opcode = requestedOpcode->opcode;
	opDef->mnemonic = requestedOpcode->mnemonic;
	opDef->SingleByteInstruction = requestedOpcode->SingleByteInstruction;
	opDef->TwoByteOpcode = requestedOpcode->TwoByteOpcode;
	opDef->InstructionPrefixBytePresent = requestedOpcode->InstructionPrefixBytePresent;
	opDef->AddressSizePrefixBytePresent = requestedOpcode->AddressSizePrefixBytePresent;
	opDef->OperandSizePrefixBytePresent = requestedOpcode->OperandSizePrefixBytePresent;
	opDef->SegmentOverrideBytePresent = requestedOpcode->SegmentOverrideBytePresent;
	opDef->ModRMBytePresent = requestedOpcode->ModRMBytePresent;
	opDef->SIBBytePresent = requestedOpcode->SIBBytePresent;
	opDef->DisplacementPresent = requestedOpcode->DisplacementPresent;
	opDef->ImmediatePresent = requestedOpcode->ImmediatePresent;
	opDef->Source = requestedOpcode->Source;
	opDef->Destination = requestedOpcode->Destination;
	
	return true;
}
