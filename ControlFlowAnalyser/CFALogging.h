#pragma once
#include "Header.h"
#include <iostream>
#include <ctime>
#include <exception>

class UnknownLogLevelException
{
	virtual const char* what() const throw()
	{
		return "Could not find suitable tag for LogLevel";
	}
};

class FailedMemoryAllocationException
{
	virtual const char* what() const throw()
	{
		return "Failed to allocate desired memory";
	}
};

class CFALogging
{
public:
	static enum LogLevel {ERR, WARN, INFO, DEBUG};

	static void getCurrentTime(char** timeString);
	static void getLogTag(LogLevel level, char** lpLogTag);
	static void logMessage(LogLevel level, char* message);
	static void logDebugMessage(char* message);
	static void logInfoMessage(char* message);
	static void logWarnMessage(char* message);
	static void logErrorMessage(char* message);
};

