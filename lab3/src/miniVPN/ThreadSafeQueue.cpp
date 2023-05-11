#include "ThreadSafeQueue.h"


template <typename T>
ThreadSafeQueue<T>::ThreadSafeQueue() {}

template <typename T>
ThreadSafeQueue<T>::~ThreadSafeQueue() {}

template <typename T>
void ThreadSafeQueue<T>::push(T new_value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.push(new_value);
    m_cond.notify_one();
}

template <typename T>
void ThreadSafeQueue<T>::pop() {
    std::unique_lock<std::mutex> lock(m_mutex);
    while (m_queue.empty()) {
        m_cond.wait(lock);
    }
    m_queue.pop();
}

template <typename T>
bool ThreadSafeQueue<T>::try_front(T& value) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_queue.empty()) {
        return false;
    }
    value = m_queue.front();
    return true;
}

template <typename T>
bool ThreadSafeQueue<T>::empty() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_queue.empty();
}