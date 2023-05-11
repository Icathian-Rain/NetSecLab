//
// Created by seed on 5/8/23.
//

#include "VPNClient.h"

/// @brief 证书验证回调函数
/// @param pre_verify_ok 
/// @param x509_ctx 
/// @return 返回1表示验证通过，0表示验证失败
int verifyCallback(int pre_verify_ok, X509_STORE_CTX *x509_ctx) {
    char buf[300];
    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("certificate subject= %s\n", buf);

    if (pre_verify_ok == 0) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("Verification failed: %s.\n",
               X509_verify_cert_error_string(err));
        return 0;  
    }
    printf("Verification passed.\n");
    return 1;  
}


/// @brief 设置TCP客户端
/// @param hostname 
/// @param port 
/// @return 返回套接字描述符
int setup_tcp_client(const std::string &hostname, int port) {
    struct sockaddr_in serverAddr{};

    // 由域名获取IP地址
    struct hostent *hp = gethostbyname(hostname.c_str());

    // 创建TCP套接字
    int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(sock_fd, "socket")

    // 填充服务端信息(IP, 端口号, 协议族)
    memset(&serverAddr, '\0', sizeof(serverAddr));
    memcpy(&(serverAddr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    //   server_addr.sin_addr.s_addr = inet_addr ("10.0.2.14");
    serverAddr.sin_port = htons(port);
    serverAddr.sin_family = AF_INET;

    // 与服务端建立连接
    int err = connect(sock_fd, (struct sockaddr *) &serverAddr, sizeof(serverAddr));
    CHK_ERR(err, "connect")
    printf("TCP connect! hostname IP:%s port:%d\n", inet_ntoa(serverAddr.sin_addr), port);
    return sock_fd;
}

/// @brief 用户名密码验证
/// @param ssl 
/// @return 1表示验证成功，0表示验证失败
int verify_client(SSL *ssl) {
    std::string username;
    char* passwd;
    char recvBuf[BUFFER_SIZE];
    SSL_read(ssl, recvBuf, BUFFER_SIZE);
    //username
    printf("%s\n", recvBuf);
    std::cin >> username;
    SSL_write(ssl, username.c_str(), static_cast<int>(strlen(username.c_str())) + 1);
    //passwd
    SSL_read(ssl, recvBuf, BUFFER_SIZE);
    printf("%s\n", recvBuf);
    passwd = getpass("");
    SSL_write(ssl, passwd, static_cast<int>(strlen(passwd)) + 1);
    //check
    SSL_read(ssl, recvBuf, BUFFER_SIZE);
    if (strcmp(recvBuf, "Client verify succeed") != 0) {
        printf("Client verify failed!\n");
        return 0;
    }
    printf("client verify succeed!\n");
    return 1;
}

/// @brief 设置TLS客户端
/// @param hostname 目的服务器的主机名
/// @param ca_path ca证书路径
/// @return SSL套接字
SSL *setup_tls_client(const std::string &hostname, const std::string &ca_path) {
    // 加载SSL库
    SSL_library_init();
    // 加载SSL错误信息
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    // 创建SSL上下文
    const SSL_METHOD *meth = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
    }
    // 指定证书验证回调函数
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verifyCallback);
    // 加载CA证书
    if (SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), nullptr) < 1) {
        printf("Error setting the verify locations. \n");
        exit(0);
    }
    // 创建SSL套接字
    SSL *ssl = SSL_new(ctx);
    // 设置套接字
    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
    // 设置主机名
    X509_VERIFY_PARAM_set1_host(vpm, hostname.c_str(), 0);
    SSL_CTX_free(ctx);
    return ssl;
}

/// @brief 获取虚拟IP
/// @param ssl SSL套接字
/// @return 虚拟IP
std::string recv_virtual_ip(SSL *ssl) {
    char buf[BUFFER_SIZE];
    // 接收虚拟IP
    SSL_read(ssl, buf, BUFFER_SIZE);
    // 打印虚拟IP
    printf("virtual ip: %s\n", buf);
    return buf;
}
/// @brief 创建TUN设备
/// @param virtual_ip 虚拟IP
/// @param allow_ip_cidr 目的IP子网
/// @return TUN套接字描述符
int create_tun_device(const std::string& virtual_ip, const std::string& allow_ip_cidr) {
    int tun_fd;
    struct ifreq ifr{};
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    //IFF_TUN:表示创建一个TUN设备
    //IFF_NO_PI:表示不包含包头信息

    //打开TUN设备
    tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd == -1) {
        printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    //注册设备工作模式
    int ret = ioctl(tun_fd, TUNSETIFF, &ifr);
    if (ret == -1) {
        printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    printf("Create a tun device :%s\n", ifr.ifr_name);
    //虚拟设备编号
    int tunId = static_cast<int>(strtol(ifr.ifr_name+3, nullptr, 10));
    char cmd[BUFFER_SIZE];
    //将虚拟IP绑定到TUN设备上
    int err;
    // ip addr add 192.168.53.5 dev tun0
    snprintf(cmd, BUFFER_SIZE, "ip addr add %s dev tun%d",virtual_ip.c_str(),tunId);
    err = system(cmd);
    if (err == -1) {
        printf("Set virtual ip failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    // ip link set tun0 up
    snprintf(cmd, BUFFER_SIZE, "ip link set tun%d up",tunId);
    err = system(cmd);
    if (err == -1) {
        printf("Set virtual ip failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    // 将发送给192.168.60.0/24的数据包交由TUN设备处理
    // ip route add 192.168.60.0/24 dev tun0
    snprintf(cmd, BUFFER_SIZE, "ip route add %s dev tun%d", allow_ip_cidr.c_str(), tunId);
    err = system(cmd);
    if (err == -1) {
        printf("Set route failed! (%d: %s)\n", errno, strerror(errno));
        return -1;
    }
    return tun_fd;
}


/// @brief 设置TCP客户端
/// @param server_host 服务器主机名
/// @param server_port 服务器端口
/// @param ca_path CA证书路径
/// @param allow_ip_cidr 目的IP子网
VPNClient::VPNClient(std::string server_host, int server_port, std::string ca_path, std::string allow_ip_cidr) {
    this->server_host = server_host;
    this->server_port = server_port;
    this->ca_path = ca_path;
    this->allow_ip_cidr = allow_ip_cidr;
}

/// @brief tun中读取数据，写入tls套接字
/// @param tun_fd tun套接字
/// @param ssl ssl套接字
void tunSelected(int tun_fd, SSL *ssl) {
    char buf[BUFFER_SIZE];
    int len;
    // 从tun设备读取数据
    len = static_cast<int>(read(tun_fd, buf, BUFFER_SIZE));
    buf[len] = '\0';
    // 将数据写入tls套接字
    SSL_write(ssl, buf, len);
}

/// @brief tls套接字中读取数据，写入tun设备
/// @param tun_fd tun套接字
/// @param ssl ssl套接字
void socketSelected(int tun_fd, SSL *ssl) {
    char buf[BUFFER_SIZE];
    int len;
    // 从tls套接字读取数据
    len = SSL_read(ssl, buf, BUFFER_SIZE);
    if (len == 0) {
        fprintf(stderr, "the ssl socket close!\n");
        return;
    }
    buf[len] = '\0';
    // 将数据写入tun设备
    long size = write(tun_fd, buf, len);
    if (size == -1) {
        printf("Write to tun device failed! (%d: %s)\n", errno, strerror(errno));
    }
}


/// @brief 连接VPN服务器
void VPNClient::connect() {
    // 初始化tls客户端
    SSL *ssl = setup_tls_client(this->server_host, this->ca_path);
    // 初始化tcp客户端
    int sock_fd = setup_tcp_client(this->server_host, this->server_port);
    // 将tcp套接字绑定到tls套接字
    SSL_set_fd(ssl, sock_fd);
    // 客户端与服务器建立连接
    int err = SSL_connect(ssl);
    if (err == -1) {
        ERR_print_errors_fp(stderr);
        return;
    }
    printf("TLS connect succeed!\n");
    // 服务器用户名密码验证
    if (!verify_client(ssl)) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }
    // 接收虚拟ip
    std::string virtual_ip = recv_virtual_ip(ssl);
    // 创建tun设备
    int tun_fd = create_tun_device(virtual_ip, this->allow_ip_cidr);
    // 开始转发数据
    while (true) {
        // 监听套接字
        // 判断是哪个套接字有数据
        fd_set read_fd;
        FD_ZERO(&read_fd);
        FD_SET(sock_fd, &read_fd);
        FD_SET(tun_fd, &read_fd);
        select(FD_SETSIZE, &read_fd, nullptr, nullptr, nullptr);
        // client -> tun -> SSL -> server
        // 从tun设备读取数据，写入tls套接字
        if (FD_ISSET(tun_fd, &read_fd)) {
            tunSelected(tun_fd, ssl);
        }
        // server -> SSL -> tun -> client
        // 从tls套接字读取数据，写入tun设备
        if (FD_ISSET(sock_fd, &read_fd)) {
            socketSelected(tun_fd, ssl);
        }
    }
}