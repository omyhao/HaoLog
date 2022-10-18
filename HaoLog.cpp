#include "HaoLog.h"

#include <cinttypes>

#include <queue>
#include <atomic>
#include <thread>
#include <fstream>
#include <vector>
#include <sstream>
#include <iostream>
#include <thread>
#include <fstream>
#include <chrono>
#include <mutex>

using std::cout;
using std::endl;
using std::queue;
using std::thread;
using std::atomic;
using std::vector;
using std::atomic_flag;
using std::make_unique;
using std::streamoff;
using std::ofstream;
using std::ostringstream;
using std::unique_lock;
using std::mutex;
using std::condition_variable;

namespace fs = std::filesystem;
using namespace hao_log;

// 系统错误个数
constexpr int kSysNerr{ 134 };
constexpr int kMaxNumericSize{ 48 };
// 系统错误信息
vector<string> kSysErrorList_;

string_view my_error(int err)
{
	if (err <= kSysNerr)
	{
		return kSysErrorList_[err].c_str();
	}
	else
	{
		return "unknow error";
	}
}

struct Tid
{
	Tid()
	{
		ostringstream ss;
		ss << std::this_thread::get_id();
		tid_string_ = ss.str();
	}
	string tid_string_;
};
static thread_local Tid tid;

constexpr const char* LogLevelString(int level)
{
	return &"[EMERG ]"     // system is unusable
			"[ALERT ]"     // action must be taken immediately
			"[CRIT  ]"     // critical conditions
			"[ERROR ]"     // error conditions
			"[WARN  ]"     // warning conditions
			"[NOTICE]"     // normal, but significant condition
			"[INFO  ]"     // informational message
			"[DEBUG ]"     // debug-level message
			[level * 8];
};

constexpr const char* digits2(size_t value) {
	// GCC generates slightly better code when value is pointer-size.
	return &"0001020304050607080910111213141516171819"
		"2021222324252627282930313233343536373839"
		"4041424344454647484950515253545556575859"
		"6061626364656667686970717273747576777879"
		"8081828384858687888990919293949596979899"[value * 2];
}

inline void format_time(char* buf, unsigned a, unsigned b, unsigned c, char sep)
{
	uint64_t timer_buffer = a | (b << 24) | (static_cast<uint64_t>(c) << 48);
	timer_buffer += (((timer_buffer * 205) >> 11) & 0x000f00000f00000f) * 6;
	timer_buffer = ((timer_buffer & 0x00f00000f00000f0) >> 4) | ((timer_buffer & 0x000f00000f00000f) << 8);
	auto u_sep = static_cast<uint64_t>(sep);
	timer_buffer |= 0x3030003030003030 | (u_sep << 16) | (u_sep << 40);

	std::memcpy(buf, &timer_buffer, 8);
}

class FileWriter
{
public:
	FileWriter(const string& log_dir, const string& filename, uint32_t roll_size_mb)
		:roll_size_{ 1024 * 1024 * roll_size_mb }, name_(log_dir + filename)
	{
		roll_file();
	}
	void write(LogLine& logline)
	{
		logline.ToFile(*file_);
		if (file_->WrittenBytes() > roll_size_)
		{
			roll_file();
		}
	}
	string GetTimestampString()
	{
		char time_str[30]{ '\0' };
		timespec now;
		timespec_get(&now, TIME_UTC);
		std::tm to_time;
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
		localtime_s(&to_time, &now.tv_sec);
#else
		localtime_r(&now.tv_sec, &to_time)；
#endif

			std::memcpy(time_str, digits2(static_cast<size_t>((1900 + to_time.tm_year) / 100)), 2);
		format_time(time_str + 2,
			static_cast<unsigned>(to_time.tm_year % 100),
			static_cast<unsigned>(to_time.tm_mon + 1),
			static_cast<unsigned>(to_time.tm_mday), '.');
		time_str[10] = '_';
		format_time(time_str + 11,
			static_cast<unsigned>(to_time.tm_hour),
			static_cast<unsigned>(to_time.tm_min),
			static_cast<unsigned>(to_time.tm_sec), '.');
		//time_str[19] = '.';
		auto usec = now.tv_nsec;
		char* usec_end = &time_str[29];
		for (int i{ 0 }; i < 5; ++i)
		{
			usec_end -= 2;
			std::memcpy(usec_end, digits2(static_cast<size_t>(usec % 100)), 2);
			usec /= 100;
		}
		time_str[19] = '.';
		time_str[29] = '\0';
		return time_str;
	}
private:
	void roll_file()
	{
		if (file_)
		{
			file_->Flush();
		}
		bytes_written_ = 0;
		string log_file_name = name_;
		log_file_name.append(".");
		log_file_name.append(GetTimestampString());
		log_file_name.append(".txt");
		file_.reset(new File(log_file_name.c_str()));
	}
private:
	streamoff bytes_written_ = 0;
	const uint32_t	roll_size_;
	const string name_;
	unique_ptr<File> file_;
};

void LogLine::InitSysErrorList()
{
	string temp;
	temp.reserve(128);
	for (int err = 0; err < kSysNerr; err++)
	{
		temp.push_back('[');
		char err_str[256]{ 0 };
		strerror_s(err_str, 256, err);
		temp.append(err_str);
		temp.push_back(']');
		//std::cout << temp << endl;
		kSysErrorList_.push_back(temp);
		temp.clear();
	}
}


LogLine::LogLine(LogLevel level, const char* filename, uint32_t line, int cur_errno)
	: used{ 0 }, buf_size_{ sizeof(stack_buf_) }, stack_buf_{0}
{
	GenerateTime();
	Append(tid.tid_string_.c_str(), tid.tid_string_.size());
	Append(LogLevelString(level), 8);
	*this << '[' << filename << ' ' << line << ']';
	
	if (cur_errno)
	{
		string_view sv = my_error(cur_errno);
		Append(sv.data(), sv.size());
		used += sv.size();
	}
}
static const int64_t kMicroSecondsPerSecond = 1000 * 1000;
thread_local time_t last_secend_;
// 2022-09-06 16:10:30
thread_local char time_str[19];
void LogLine::GenerateTime()
{
	timespec now;
	timespec_get(&now, TIME_UTC);
	if (now.tv_sec != last_secend_)
	{
		std::tm to_time;
		#if defined(WIN32) || defined(_WIN32) || defined(__WIN32) && !defined(__CYGWIN__)
				localtime_s(&to_time, &now.tv_sec);
		#else
				localtime_r(&to_time, &now.tv_sec)；
		#endif
		
		std::memcpy(time_str, digits2(static_cast<size_t>((1900 + to_time.tm_year) / 100)), 2);
		format_time(time_str + 2,
			static_cast<unsigned>(to_time.tm_year % 100),
			static_cast<unsigned>(to_time.tm_mon + 1),
			static_cast<unsigned>(to_time.tm_mday), '-');
		time_str[10] = ' ';
		format_time(time_str + 11,
			static_cast<unsigned>(to_time.tm_hour),
			static_cast<unsigned>(to_time.tm_min),
			static_cast<unsigned>(to_time.tm_sec), ':');
	}
	memcpy(stack_buf_, time_str, 19);
	//log_line_buffer_[19] = '.';
	auto usec = now.tv_nsec;
	char* usec_end = &stack_buf_[29];
	for (int i{ 0 }; i < 5; ++i)
	{
		usec_end -= 2;
		std::memcpy(usec_end, digits2(static_cast<size_t>(usec % 100)), 2);
		usec /= 100;
	}
	stack_buf_[19] = '.';
	stack_buf_[29] = ' ';
	used += 30;
}


void LogLine::ToFile(File& fp_)
{
	NeedSize(1);
	*cur() = '\n';
	used += 1;
	if (!heap_buf_)
	{
		//cout << stack_buf_;
		fp_.Append(stack_buf_, used);
	}
	else
	{
		//cout << heap_buf_;
		fp_.Append(heap_buf_.get(), used);
	}
}
char* LogLine::cur()
{
	return !heap_buf_ ? &stack_buf_[used] : &(heap_buf_.get())[used];
}

void LogLine::NeedSize(size_t acruired)
{
	size_t need = used + acruired;
	if (need <= buf_size_)
		return;
	if (!heap_buf_)
	{
		buf_size_ = std::max(static_cast<size_t>(512), need);
		heap_buf_.reset(new char[buf_size_]);
		std::memcpy(heap_buf_.get(), stack_buf_, used);
	}
	else
	{
		buf_size_ = std::max(static_cast<size_t>(2 * buf_size_), need);
		unique_ptr<char[]> new_buf(new char[buf_size_]);
		std::memcpy(new_buf.get(), heap_buf_.get(), buf_size_);
		heap_buf_.swap(new_buf);
	}
}

void LogLine::Append(const char* src, size_t len)
{
	NeedSize(len);
	std::memcpy(cur(), src, len);
	used += len;	
}

LogLine& LogLine::operator<<(bool num)
{
	if (num)
	{
		Append("true", 4);
	}
	else
	{
		Append("false", 5);
	}
	return *this;
}

template <typename INT>
constexpr int digits10() noexcept
{
	return std::numeric_limits<INT>::digits10;
}

struct result
{
	char* begin;
	char* end;
};
template<typename UINT>
result format_decimal(char* out, UINT value, int size)
{
	out += size;
	char* end = out;
	while (value >= 100)
	{
		out -= 2;
		// memcpy(dst, src, 2);
		memcpy(out, digits2(static_cast<size_t>(value % 100)), 2);
		value /= 100;
	}
	if (value < 10)
	{
		*--out = static_cast<char>('0' + value);
		return { out, end };
	}
	out -= 2;
	memcpy(out, digits2(static_cast<size_t>(value)), 2);
	return { out,end };
}

// +1 是为了存负号-
constexpr int buffer_size = std::numeric_limits<unsigned long long>::digits10 + 1;
template<typename T>
constexpr int num_bits()
{
	return std::numeric_limits<T>::digits;
}
template<bool B, typename T, typename F>
using conditional_t = typename std::conditional<B, T, F>::type;
template <typename T>
using uint32_or_64_t =
conditional_t < num_bits<T>() <= 32,
	uint32_t,
	conditional_t<num_bits<T>() < 64, uint64_t, uintmax_t > >;


template<typename T>
void LogLine::FormatInteger(T num)
{
	auto abs_value = static_cast<uint32_or_64_t<T>>(num);
	bool negative{ num < 0 };
	if (negative)
	{
		abs_value = 0 - abs_value;
	}
	char buffer[buffer_size];
	char* begin = format_decimal(buffer, num, buffer_size - 1).begin;
	if (negative)
	{
		*--begin = '-';
	}
	size_t size = buffer - begin + buffer_size - 1;
	NeedSize(size);
	Append(begin, size);
	
}

LogLine& LogLine::operator<<(short num)
{
	*this << static_cast<int>(num);
	return *this;
}
LogLine& LogLine::operator<<(unsigned short num)
{
	*this << static_cast<unsigned int>(num);
	return *this;
}
LogLine& LogLine::operator<<(int num)
{
	FormatInteger(num);
	return *this;
}
LogLine& LogLine::operator<<(unsigned int num)
{
	FormatInteger(num);
	return *this;
}
LogLine& LogLine::operator<<(long num)
{
	FormatInteger(num);
	return *this;
}
LogLine& LogLine::operator<<(unsigned long num)
{
	FormatInteger(num);
	return *this;
}
LogLine& LogLine::operator<<(long long num)
{
	FormatInteger(num);
	return *this;
}
LogLine& LogLine::operator<<(unsigned long long num)
{
	FormatInteger(num);
	return *this;
}

LogLine& LogLine::operator<<(const void* src)
{
	std::uintptr_t address = reinterpret_cast<uintptr_t>(src);
	NeedSize(kMaxNumericSize);
	int n = std::snprintf(cur(), kMaxNumericSize, "0x%" PRIXPTR, address);
	used += n;
	return *this;
}
LogLine& LogLine::operator<<(float num)
{
	*this << static_cast<double>(num);
	return *this;
}

LogLine& LogLine::operator<<(double num)
{
	NeedSize(kMaxNumericSize);
	int len = snprintf(cur(), kMaxNumericSize, "%.12g", num);
	used += len;
	return *this;
}

LogLine& LogLine::operator<<(char c)
{
	NeedSize(1);
	*cur() = c;
	used += 1;
	return *this;
}

LogLine& LogLine::operator<<(const unsigned char* str)
{
	return operator<<(reinterpret_cast<const char*>(str));
}

LogLine& LogLine::operator<<(const char* src)
{
	if (src)
	{
		auto size = std::strlen(src);
		Append(src, size);
	}
	else
	{
		Append("(null)", 6);
	}
	return *this;
}

LogLine& LogLine::operator<<(string_view sv)
{
	Append(sv.data(), sv.size());
	return *this;
}

LogLine& LogLine::operator<<(const std::string& s)
{
	Append(s.c_str(), s.size());
	return *this;
}

// 一个Buffer中保存着一个动态数组，可以容纳32768个LogLine
class Buffer
{
	public:
		struct Item
		{
			Item(LogLine&& log_line) :log_line_{ std::move(log_line) } {}
			LogLine log_line_;
		};
		// 一个Buffer里要存32768条日志
		// 日志以动态数组的形式malloc出来，保存一个数组指针
		static constexpr const size_t size = 32768;
		Buffer():buffer_((Item*)std::malloc(size*sizeof(Item)))
		{
			for (size_t i{ 0 }; i <= size; ++i)
			{
				write_state[i].store(0, std::memory_order_relaxed);
			}
			//static_assert(sizeof(Item) == 256, "Unexpected size != 256");
		}

		~Buffer()
		{
			uint32_t write_count = write_state[size].load();
			for (size_t i{ 0 }; i < write_count; ++i)
			{
				buffer_[i].~Item();
			}
			std::free(buffer_);
		}
		bool push(LogLine&& logline, const uint32_t write_index)
		{
			// 定位new
			new(&buffer_[write_index])Item(std::move(logline));
			write_state[write_index].store(1, std::memory_order_release);
			// 这里还可以优化，避免上下文切换
			return write_state[size].fetch_add(1, std::memory_order_acquire) + 1 == size;
		}
		bool try_pop(LogLine& logline, const uint32_t read_index)
		{
			if (write_state[read_index].load(std::memory_order_acquire))
			{
				Item& item = buffer_[read_index];
				logline = std::move(item.log_line_);
				return true;
			}
			return false;
		}
		Buffer(const Buffer&) = delete;
		Buffer& operator=(const Buffer&) = delete;
	private:
		Item* buffer_;
		// 状态数组，保存每一个元素是否被使用的状态，最后一个值表示buffer_数组中有多少个元素
		atomic<uint32_t> write_state[size + 1];

};
class SpinLock
{
public:
	SpinLock(atomic_flag& flag) :flag_{ flag }
	{
		while (flag_.test_and_set(std::memory_order_acquire));
	}
	~SpinLock()
	{
		flag_.clear(std::memory_order_release);
	}
private:
	atomic_flag& flag_;
};
class QueueBuffer
{
	public:
		QueueBuffer() :
			current_read_buffer_{ nullptr },
			write_index_{ 0 }, read_index_{ 0 },
			flag_{ATOMIC_FLAG_INIT}
		{
			set_next_write_buffer();
		}
		QueueBuffer(const QueueBuffer&) = delete;
		QueueBuffer& operator=(const QueueBuffer&) = delete;
		bool Empty() const
		{
			return buffers_.front().get() == nullptr;
		}
		void push(LogLine&& log_line)
		{
			uint32_t write_index = write_index_.fetch_add(1, std::memory_order_relaxed);
			if (write_index < Buffer::size)
			{
				if (current_write_buffer_.load(std::memory_order_acquire)->push(std::move(log_line), write_index))
				{
					set_next_write_buffer();
				}
			}
			else
			{
				while (write_index_.load(std::memory_order_acquire) >= Buffer::size)
					;
				push(std::move(log_line));
			}
		}
		bool try_pop(LogLine& logline)
		{
			if (current_read_buffer_ == nullptr)
			{
				current_read_buffer_ = get_next_read_buffer();
			}
			Buffer* read_buffer = current_read_buffer_;
			if (read_buffer == nullptr)
			{
				return false;
			}
			if (bool success = read_buffer->try_pop(logline, read_index_))
			{
				read_index_++;
				if (read_index_ == Buffer::size)
				{
					read_index_ = 0;
					current_read_buffer_ = nullptr;
					SpinLock lock(flag_);
					buffers_.pop();
				}
				return true;
			}
			return false;
		}
	private:
		void set_next_write_buffer()
		{
			unique_ptr<Buffer> next_write_buffer = make_unique<Buffer>();
			current_write_buffer_.store(next_write_buffer.get(), std::memory_order_release);
			SpinLock spinlock(flag_);
			buffers_.push(move(next_write_buffer));
			write_index_.store(0, std::memory_order_relaxed);
		}
		Buffer* get_next_read_buffer()
		{
			SpinLock lock(flag_);
			return buffers_.empty() ? nullptr : buffers_.front().get();
		}
	private:
		queue<unique_ptr<Buffer>>	buffers_;
		atomic<Buffer*>				current_write_buffer_;
		atomic<uint32_t>			write_index_;
		
		Buffer*						current_read_buffer_;
		uint32_t					read_index_;
		
		atomic_flag					flag_;
		
};

class Logger
{
	public:
		Logger(const string& log_dir, const string filename, uint32_t roll_size)
			:file_writer_(log_dir, filename, std::max(1u, roll_size))
		{
			running_ = true;
			logger_thread_ = std::thread(&Logger::thread_func, this);
		}
		~Logger()
		{
			running_ = false;
			logger_thread_.join();
		}
		void add(LogLine&& logline)
		{
			buffer_.push(std::move(logline));
			//sink_cond_.notify_one();
		}

		void thread_func()
		{
			LogLine single_line(LogLevel::INFO, nullptr, 0, 0);;
			/*while (running_)
			{
				unique_lock<mutex> lock{ sink_mutex_ };
				sink_cond_.wait(lock, [this] {
					return !buffer_.Empty() || !running_;
				});
				while (buffer_.try_pop(single_line))
				{
					file_writer_.write(single_line);
				}
			}	*/	
			while (running_)
			{
				if (buffer_.try_pop(single_line))
				{
					file_writer_.write(single_line);
				}
				else
				{
					std::this_thread::sleep_for(std::chrono::microseconds(100));
				}
			}
			while (buffer_.try_pop(single_line))
			{
				file_writer_.write(single_line);
			}
		}
	private:
		QueueBuffer		buffer_;
		FileWriter		file_writer_;
		thread			logger_thread_;
		atomic<bool>	running_;
		//mutex			sink_mutex_;
		//condition_variable	sink_cond_;
		
};

atomic<LogLevel> global_level;
unique_ptr<Logger> logger;
atomic<Logger*> logger_ptr;

void hao_log::Helper::operator&(LogLine& log_line)
{
	logger_ptr.load(std::memory_order_acquire)->add(std::move(log_line));
}

void hao_log::Init(const string log_dir, const string file_name, uint32_t roll_size)
{
	logger.reset(new Logger(log_dir, file_name, roll_size));
	logger_ptr.store(logger.get(), std::memory_order_seq_cst);
}

void hao_log::SetLogLevel(LogLevel level)
{
	global_level.store(level, std::memory_order_release);
}

LogLevel hao_log::GetLogLevel()
{
	return global_level.load(std::memory_order_acquire);
}