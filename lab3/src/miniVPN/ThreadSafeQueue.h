#ifndef MINIVPN_THREADSAFEQUEUE_H
#define MINIVPN_THREADSAFEQUEUE_H

#include <queue>
#include <mutex>
#include "utils.h"
#include <cstring>
#include <condition_variable>

class ThreadSafeQueue {
public:
    // 构造函数
    ThreadSafeQueue() = default;

    // 销毁函数
    ~ThreadSafeQueue() = default;

    // 禁止拷贝和赋值操作
    ThreadSafeQueue(const ThreadSafeQueue&) = delete;
    ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

    /* 元素入队 */
    void push(const char * new_value, int len) {
        std::lock_guard<std::mutex> lock(m_mutex);
        char *new_value_copy = new char[len];
        memcpy(new_value_copy, new_value, len);
        m_queue.push(std::make_pair(new_value_copy, len));
        m_cond.notify_one();  // 唤醒一个等待者
    }


    /* 获取首个元素并弹出 */
    void try_front(char * dst, int &dst_len) {
        std::unique_lock<std::mutex> lock(m_mutex);
        while (m_queue.empty()) {  // 队列为空时等待
            m_cond.wait(lock);     // 等待条件变量通知
        }
        char *src = m_queue.front().first;
        int src_len = m_queue.front().second;
        memcpy(dst, src, src_len);
        dst_len = src_len;
        delete src;
        m_queue.pop();
    }

    /* 判断队列是否为空 */
    bool empty() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_queue.empty();
    }

private:
    std::queue<std::pair<char *, int>> m_queue;                  // 存储元素的队列
    mutable std::mutex m_mutex;             // 互斥锁，保护队列的访问
    std::condition_variable m_cond;         // 条件变量，用于等待队列有元素
};


#endif //MINIVPN_VPNCLIENT_H