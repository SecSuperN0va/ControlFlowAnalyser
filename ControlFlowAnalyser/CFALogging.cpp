#include "CFALogging.h"

void CFALogging::getCurrentTime(char** time_string){
	time_t cur_time = time(0);
	struct tm * now = localtime(&cur_time);
	*time_string = (char*)malloc(80);
	if (!time_string){
		throw new FailedMemoryAllocationException();
	}
	memset(*time_string, 0, 80);
	strftime(*time_string, 80, "%Y-%m-%d %H:%M:%S", now);
	return;

}

void CFALogging::getLogTag(LogLevel level, char** lpLogTag){
	switch (level){
		case DEBUG:
			*lpLogTag = "[DBG]\0";
			break;
		case INFO:
			*lpLogTag = "[INF]\0";
			break;
		case WARN:
			*lpLogTag = "[WAR]\0";
			break;
		case ERR:
			*lpLogTag = "[ERR]\0";
			break;
		default:
			throw new UnknownLogLevelException();
			break;
	}
	return;
}


void CFALogging::logMessage(LogLevel level, char* message){
	char* timeString = NULL;
	char* logTag = NULL;

	getCurrentTime(&timeString);
	getLogTag(level, &logTag);

	std::cout << timeString << " " << logTag << " " << message << std::endl;
}

void CFALogging::logDebugMessage(char* message){
	logMessage(DEBUG, message);
}

void CFALogging::logInfoMessage(char* message){
	logMessage(INFO, message);
}

void CFALogging::logWarnMessage(char* message){
	logMessage(WARN, message);
}

void CFALogging::logErrorMessage(char* message){
	logMessage(ERR, message);
}

