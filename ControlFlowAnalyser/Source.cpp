#include "Header.h"
#include "YADEngine.h"
#include "Registers.h"


int main(int argc, char* argv[]) {
	YADLogging::logInfoMessage("=== Welcome to The Control Flow Analyser (CFA) ===");

	if (argc != 2)
	{
		YADLogging::logWarnMessage("\nNot Enough Arguments\n");
		return 1;
	}

	YADLogging::logInfoMessage("Opening the executable.");

	YADEngine* engine = new YADEngine();
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

	YADLogging::logInfoMessage("Executing...");

	while (engine->executeStep());

	YADLogging::logInfoMessage("=== The Control Flow Analyser is now terminating! ===");
	std::cin.get();
	return 0;
}