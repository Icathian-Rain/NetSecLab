#include"IPPool.h"


IPPool::IPPool(/* args */)
{
}

IPPool::~IPPool()
{
}

void IPPool::init_ip_pool(const std::string& virtual_ip_cidr) {
    this->pool.clear();
    for (int i = 1;; i++) {
        std::string ip;
        ip = get_ip_by_cidr(virtual_ip_cidr, i);
        if (ip.empty())
            break;
        this->pool.push_back(ip);
    }
}

std::string IPPool::alloc_IP_addr() {
    pthread_mutex_lock(&this->mutex);
    std::string ip;
    if (!this->pool.empty()) {
        ip = this->pool[0];
        this->pool.erase(this->pool.begin());
    }
    pthread_mutex_unlock(&this->mutex);
    return ip;
}

void IPPool::release_IP_addr(const std::string &ip) {
    pthread_mutex_lock(&this->mutex);
    this->pool.push_back(ip);
    pthread_mutex_unlock(&this->mutex);
}