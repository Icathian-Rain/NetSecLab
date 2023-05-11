

#ifndef HUSTVPN_VPNSERVER_H
#define HUSTVPN_VPNSERVER_H

#include <string>
#include <cstring>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <pthread.h>
#include <shadow.h>

#include <iostream>
#include <sys/stat.h>
#include <dirent.h>
#include "utils.h"

class VPNServer {
public:
    VPNServer(std::string bind_ip, int bind_port, std::string ca_path, std::string cert_path, std::string key_path, std::string virtual_ip_cidr);
    void Listen();
    ~VPNServer();

private:
    // VPN服务器bind的IP地址
    std::string bind_ip;
    // VPN服务器bind的端口号
    int bind_port;
    // CA证书路径
    std::string ca_path;
    // 服务器证书路径
    std::string cert_path;
    // 服务器私钥路径
    std::string key_path;
    // 虚拟IP地址段 TUN
    std::string virtual_ip_cidr;

    int setupTcpServer();
    int setupTunDevice();
    void initIPPool();
    static void cleanPipes();
};


#endif //HUSTVPN_VPNSERVER_H