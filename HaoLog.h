#define _CRT_SECURE_NO_WARNINGS
#ifndef _HAO_LOG_H_

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>
#include <string_view>
#include <atomic>
#include <vector>
#include <iostream>

namespace hao_log
{
	using std::unique_ptr;
	using std::string;
	using std::string_view;
	using std::atomic;
	using std::vector;
	using std::cerr;
	using std::endl;
	namespace
	{
		class File
		{
		public:
			explicit File(const char* filename)
				:fp_{ fopen(filename, "a+") }, written_bytes_{ 0 }, buffer_{ 0 }
			{
				//setvbuf(fp_, buffer_, _IOFBF, 64 * 1024);
			}
			size_t WrittenBytes() const
			{
				return written_bytes_;
			}
			void Append(const char* log_line, const size_t len)
			{
				size_t written{ 0 };
				while (written != len)
				{
					size_t remain = len - written;
					size_t n = fwrite(log_line + written, 1, remain, fp_);
					if (n != remain)
					{
						int err = ferror(fp_);
						if (err)
						{
							char err_str[256];
							#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
								strerror_s(err_str, 256, err);
							#else
								strerror_r(err, err_str, 256);
							#endif
							
							cerr << err_str << endl;
							break;
						}
					}
					written += n;
				}
				written_bytes_ += written;
			}
			void Flush()
			{
				fflush(fp_);
			}
			~File()
			{
				fclose(fp_);
			}
		private:
			FILE* fp_;
			size_t written_bytes_;
			char buffer_[64 * 1024];
		};
	}

	enum LogLevel : uint8_t { EMERG = 0, ALERT, CRIT, ERROR, WARN, NOTICE, INFO, DEBUG };
	class LogLine
	{
		public:
			LogLine(LogLevel level, const char* filename, uint32_t line, int cur_errno);
			~LogLine() = default;
			LogLine(LogLine&&) = default;
			LogLine& operator=(LogLine&&) = default;

			void ToFile(File& fp);

			LogLine& operator << (bool);
			LogLine& operator << (short);
			LogLine& operator << (unsigned short);
			LogLine& operator << (int);
			LogLine& operator << (unsigned int);
			LogLine& operator << (long);
			LogLine& operator << (unsigned long);
			LogLine& operator << (long long);
			LogLine& operator << (unsigned long long);
			LogLine& operator << (const void*);
			LogLine& operator << (float);
			LogLine& operator << (double);

			LogLine& operator << (char);
			LogLine& operator << (const unsigned char*);
			LogLine& operator << (const char*);
			LogLine& operator << (string_view sv);
			LogLine& operator << (const string& arg);

		private:
			template<typename T>
			void FormatInteger(T);
			void Append(const char* arg, size_t length);
			void GenerateTime();
			void NeedSize(size_t size);
			char* cur();
			static void InitSysErrorList();
		
		private:
			size_t used;
			size_t buf_size_;
			unique_ptr<char[]> heap_buf_;
			char stack_buf_[256 - 2*sizeof(size_t)-sizeof(decltype(heap_buf_))];
			
			
	};
	class Helper
	{
		public:
			void operator&(LogLine& log_line);
	};
	
	void Init(const string log_dir, const string file_name, uint32_t roll_size);
	void SetLogLevel(LogLevel level);
	LogLevel GetLogLevel();

	#define _LOG_LEVEL_(level, cur_errno)\
		(GetLogLevel()<level)?void(0):\
		Helper() & LogLine(level, __FILE__, __LINE__, cur_errno)

	#define LOG_EMERG  _LOG_LEVEL_(LogLevel::EMERG, errno)
	#define LOG_ALERT  _LOG_LEVEL_(LogLevel::ALERT, errno)
	#define LOG_CRIT   _LOG_LEVEL_(LogLevel::CRIT, errno)
	#define LOG_ERROR  _LOG_LEVEL_(LogLevel::ERROR, errno)
	#define LOG_WARN   _LOG_LEVEL_(LogLevel::WARN, 0)
	#define LOG_NOTICE _LOG_LEVEL_(LogLevel::NOTICE, 0)
	#define LOG_INFO   _LOG_LEVEL_(LogLevel::INFO, 0)
	#define LOG_DEBUG  _LOG_LEVEL_(LogLevel::DEBUG, 0)	
}
#endif // !_HAO_LOG_H_