#include "HaoLog.h"
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <cstdio>
#include <ratio>
using namespace hao_log;
using std::cout;
using std::endl;

int main()
{
	Init("C:/Workspace/Test/", "test", 150);
	SetLogLevel(LogLevel::INFO);

	int times{ 1000000 };
	
    
	auto begin = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < times; ++i)
	{
		LOG_INFO << "test string " << i << " end" << 3.14;
	}
	auto end = std::chrono::high_resolution_clock::now();
	cout << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count() << "ms" << endl;
	return 0;
}