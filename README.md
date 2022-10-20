# HaoLog
基于C++17的高性能线程安全日志库
# 特性
- 高效的日期格式化
- 支持固定文件大小滚动
- 日志行使用少内容在栈、多内容在堆的形式
- 支持流式日志格式
- 使用pre-allocated memory来减少内存分配
- 日志行使用move进行消息存取

# 性能
1,000,000条日志，耗时403ms


# 可改进点
- 延迟格式化
- 优化无止尽
- Buffer中write_state[size+1]用来保存bufer使用的个数，在push的时候对其fetch_add，直接访问数组最后一个元素，会造成上下文的不断的切换，这里还可以想办法优化
- queue中的Buffer pop之后，考虑如何复用，避免内存的频繁申请
