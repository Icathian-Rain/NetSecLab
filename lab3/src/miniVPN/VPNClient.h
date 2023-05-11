//
// Created by seed on 5/8/23.
//

#ifndef MINIVPN_VPNCLIENT_H
#define MINIVPN_VPNCLIENT_H
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <utility>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring>
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iostream>
#include "utils.h"

class VPNClient {
private:
    // vpn服务器主机名
    std::string server_host;
    // vpn服务器端口号
    int server_port;
    // ca证书路径
    std::string ca_path;
    // 允许访问的IP地址段
    std::string allow_ip_cidr;
public:
    // 初始化
    VPNClient(std::string server_host, int server_port, std::string ca_path, std::string allow_ip_cidr);
    // 连接VPN服务器
    void connect();

};


#endif //MINIVPN_VPNCLIENT_H
