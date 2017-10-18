#include "YADEngine.h"

void YADLogging::getCurrentTime(char** time_string){
	time_t cur_time = time(0);
	struct tm now;
	localtime_s(&now, &cur_time);
	*time_string = (char*)malloc(80);
	if (!time_string){
		throw new FailedMemoryAllocationException();
	}
	memset(*time_string, 0, 80);
	strftime(*time_string, 80, "%Y-%m-%d %H:%M:%S", &now);
	return;

}

void YADLogging::getLogTag(LogLevel level, char** lpLogTag){
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


void YADLogging::logMessage(LogLevel level, char* message){
	char* timeString = NULL;
	char* logTag = NULL;

	getCurrentTime(&timeString);
	getLogTag(level, &logTag);

	std::cout << timeString << " " << logTag << " " << message << std::endl;
}

void YADLogging::logDebugMessage(char* message){
	logMessage(DEBUG, message);
}

void YADLogging::logInfoMessage(char* message){
	logMessage(INFO, message);
}

void YADLogging::logWarnMessage(char* message){
	logMessage(WARN, message);
}

void YADLogging::logErrorMessage(char* message){
	logMessage(ERR, message);
}

