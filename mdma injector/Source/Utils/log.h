#pragma once

#include <stdio.h>
#include <chrono>
#include <ctime>

namespace logger {
	inline void print(const char* prefix, const char* format, ...) {
		auto now = std::chrono::system_clock::now();
		auto time = std::chrono::system_clock::to_time_t(now);
		auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
		
		tm local_time;
		localtime_s(&local_time, &time);
		
		printf("[%s][%02d:%02d:%02d] ", prefix, local_time.tm_hour, local_time.tm_min, local_time.tm_sec);
		
		va_list args;
		va_start(args, format);
		vprintf(format, args);
		va_end(args);
	}
}

#define log_info(format, ...) logger::print("+", format, __VA_ARGS__)
#define log_error(format, ...) logger::print("-", format, __VA_ARGS__)
#define log_status(format, ...) logger::print("*", format, __VA_ARGS__)

