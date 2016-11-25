#include "Header.h"
#include "CFAEngine.h"
#include "Registers.h"


int main(int argc, char* argv[]) {
	CFALogging::logInfoMessage("=== Welcome to The Control Flow Analyser (CFA) ===");

	if (argc != 2)
	{
		CFALogging::logWarnMessage("\nNot Enough Arguments\n");
		return 1;
	}

	CFALogging::logInfoMessage("Opening the executable.");

	CFAEngine* engine = new CFAEngine();
	DWORD entrypoint = NULL;
	engine->loadExecutable(argv[1], &entrypoint);
	engine->createStack(0);
	Registers::eip = (DWORD*)entrypoint;

	if (!entrypoint){
		cout << "Failed to identify executable entry point! Quitting!\n";
		return -1;
	}

	cout << "Identified entry point into loaded executable: 0x" << hex << entrypoint << endl;

	//engine->traverseFunction((void*)entrypoint);

	CFALogging::logInfoMessage("Executing...");

	while (engine->executeStep());

	CFALogging::logInfoMessage("=== The Control Flow Analyser is now terminating! ===");
	std::cin.get();
	return 0;
}