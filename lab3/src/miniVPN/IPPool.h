#ifndef MINIVPN_IPPOOL_H
#define MINIVPN_IPPOOL_H
#include <vector>
#include <string>
#include "utils.h"




class IPPool
{
private:
    /* data */
    std::vector<std::string> pool;
    pthread_mutex_t mutex;


public:
    IPPool(/* args */);
    ~IPPool();
    void init_ip_pool(const std::string& virtual_ip_cidr);
    std::string alloc_IP_addr();
    void release_IP_addr(const std::string &ip);
};










#endif //MINIVPN_IPPOOL_H