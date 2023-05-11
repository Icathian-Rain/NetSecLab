#include "VPNServer.h"

IPPool IPpool;
std::unordered_map<std::string, ThreadSafeQueue *> IP2Queue;

/// @brief 创建tun设备
/// @param virtual_ip_cidr 虚拟ip地址子网
/// @return tun套接字
int create_tun_device(std::string virtual_ip_cidr) {
    auto ifr = (struct ifreq *) malloc(sizeof(ifreq));
    memset(ifr, 0, sizeof(ifreq));
    ifr->ifr_flags = IFF_TUN | IFF_NO_PI;
    // 创建tun设备
    int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd == -1) {
        fprintf(stderr, "error! open TUN failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }
    // 设置tun设备
    int ret = ioctl(tun_fd, TUNSETIFF, ifr);
    if (ret == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }
    //tun id
    int tunId = static_cast<int>(strtol(ifr->ifr_name + 3, nullptr, 10));  
    char cmd[BUFFER_SIZE];

    // ip addr add 192.168.50.1/24 dev tun0
    snprintf(cmd, BUFFER_SIZE, "ip addr add %s dev tun%d", IPpool.alloc_IP_addr().c_str(), tunId);
    int err = system(cmd);
    printf("%s\n", cmd);
    if (err == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    // ip link set tun0 up
    snprintf(cmd, BUFFER_SIZE, "ip link set tun%d up", tunId);
    err = system(cmd);
    printf("%s\n", cmd);
    if (err == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    // ip route add 192.168.50.0/24 dev tun0
    snprintf(cmd, BUFFER_SIZE, "ip route add %s dev tun%d", virtual_ip_cidr.c_str(), tunId);
    err = system(cmd);
    printf("%s\n", cmd);
    if (err == -1) {
        fprintf(stderr, "error! setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
        free(ifr);
        return -1;
    }

    free(ifr);
    return tun_fd;
}

/// @brief 设置TCP套接字
/// @param bind_ip 绑定的IP地址
/// @param bind_port 绑定的端口号
/// @return TCP套接字
int setup_tcp_server(std::string bind_ip, int bind_port) {
    // 允许地址重用
    auto sa_server = (struct sockaddr_in *) malloc(sizeof(sockaddr_in));
    int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket")
    int opt = 1;
    int set_err = setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    CHK_ERR(set_err, "setsockopt")
    memset(sa_server, '\0', sizeof(sockaddr_in));
    sa_server->sin_family = AF_INET;
    inet_aton(bind_ip.c_str(), &(sa_server->sin_addr));
    sa_server->sin_port = htons(bind_port);
    int err = bind(listen_sock, (struct sockaddr *) sa_server, sizeof(sockaddr_in));
    CHK_ERR(err, "bind")
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen")
    free(sa_server);
    return listen_sock;
}


/// @brief 设置SSL套接字
/// @param CA_PATH CA证书路径
/// @param CERT_PATH 证书路径
/// @param KEY_PATH 私钥路径
/// @return SSL套接字
SSL_CTX *server_ssl_init(const char *CA_PATH, const char *CERT_PATH, const char *KEY_PATH) {
    SSL_CTX *ctx;

    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL_CTX_load_verify_locations(ctx, CA_PATH, nullptr);// set default locations for trusted CA certificates

    // Step 2: Set up the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_PATH, SSL_FILETYPE_PEM) <=
        0) {//loads the certificate for use with Secure Sockets Layer (SSL) sessions using a specific context (CTX) structure.
        fprintf(stderr, "server cert use error!\n");
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_PATH, SSL_FILETYPE_PEM) <=
        0) {// loads the private key for use with Secure Sockets Layer (SSL) sessions using a specific context (CTX) structure.
        fprintf(stderr, "server key use error!\n");
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(
            ctx)) {// verifies that the private key agrees with the corresponding public key in the certificate associated with a specific context (CTX) structure.
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }
    return ctx;
}


/// @brief 监听TCP套接字
/// @param listen_sock 监听套接字
/// @return TCP套接字
int accept_tcp_client(int listen_sock) {
    auto clientAddr = (struct sockaddr_in *) malloc(sizeof(sockaddr_in));
    socklen_t clientAddrLen = sizeof(struct sockaddr_in);
    int client_sock = accept(listen_sock, (struct sockaddr *) clientAddr, &clientAddrLen);
    if (client_sock == -1) {
        fprintf(stderr, "error accept client!\n");
        return -1;
    }
    fprintf(stdout, "get a connect request! s.ip is %s s.port is %d\n", inet_ntoa(clientAddr->sin_addr),
            clientAddr->sin_port);
    return client_sock;
}

/// @brief 身份验证
/// @param ssl SSL套接字
/// @return 是否验证成功 1成功 0失败
int verify(SSL *ssl) {
    // username and password
    char user_message[] = "Please input username: ";
    SSL_write(ssl, user_message, static_cast<int>(strlen(user_message)) +
                                 1);// writes application data across a Secure Sockets Layer (SSL) session.
    char username[BUFFER_SIZE];
    SSL_read(ssl, username, BUFFER_SIZE);
    printf("username: %s try to login\n", username);
    char password_message[] = "Please input password: ";
    SSL_write(ssl, password_message, static_cast<int>(strlen(password_message)) + 1);
    char password[BUFFER_SIZE];
    SSL_read(ssl, password, BUFFER_SIZE);
    
    // check
    struct spwd *pw = getspnam(username);    //get account info from shadow file
    if (pw == nullptr) {// the user doesn't exist
        char no[] = "Client verify failed";
        SSL_write(ssl, no, static_cast<int>(strlen(no)) + 1);
        fprintf(stderr, "error! user doesn't exist\n");
        return -1;
    }
    char *enc_passwd = crypt(password, pw->sp_pwdp);
    if (strcmp(enc_passwd, pw->sp_pwdp) != 0) {
        char no[] = "Client verify failed";
        SSL_write(ssl, no, static_cast<int>(strlen(no)) + 1);
        fprintf(stderr, "error! password\n");
        return -1;
    }
    char yes[] = "Client verify succeed";
    SSL_write(ssl, yes, static_cast<int>(strlen(yes)) + 1);
    printf("username: %s successfully Login\n", username);
    return 0;
}

/// @brief 监听tun设备，将数据写入队列
/// @param _tun_fd tun设备文件描述符
void *listen_tun(void *_tun_fd) {
    int tun_fd = *((int *) _tun_fd);
    char buff[BUFFER_SIZE];
    while (true) {
        long len = read(tun_fd, buff, BUFFER_SIZE);
        if (len > 19 && buff[0] == 0x45) {
            auto ip_header = (struct iphdr *) buff;
            auto ip_addr = int_to_ip(ntohl(ip_header->daddr));
            if (IP2Queue.find(ip_addr) == IP2Queue.end())
            {
                printf("The ip address %s is not in the queue\n", ip_addr.c_str());
                continue;
            }
            IP2Queue[ip_addr]->push(buff, len);
        }
    }
}


// dest -> tun -> queue -> SSL -> client
/// @brief 从队列中读取数据并发送给客户端
/// @param param 参数 ip地址和SSL套接字
/// @return 空指针
void *listen_queue(void *param) {
    auto _param = (listen_queue_param *) param;
    std::string ip_addr = _param->ip_addr;
    if (IP2Queue.find(ip_addr) == IP2Queue.end()) {
        printf("The ip address %s is not in the queue\n", ip_addr.c_str());
        return nullptr;
    }
    ThreadSafeQueue *queue = IP2Queue[ip_addr];
    do {
        int len;
        char buff[BUFFER_SIZE];
        queue->try_front(buff, len);
        SSL_write(_param->ssl, buff, static_cast<int>(len));
    } while (1);
    return nullptr;
}

// client -> SSL -> tun -> dest
/// @brief 从SSL套接字中读取数据并交给tun设备转发
/// @param ssl SSL套接字
/// @param tun_fd tun设备文件描述符
void listen_sock(SSL *ssl, int tun_fd) {
    do {
        char buf[BUFFER_SIZE];
        int len;
        // 从tls套接字读取数据
        len = SSL_read(ssl, buf, BUFFER_SIZE);
        if (len == 0) {
            fprintf(stderr, "the ssl socket close!\n");
            break;
        }
        buf[len] = '\0';
        // 将数据写入tun设备
        long size = write(tun_fd, buf, len);
        if (size == -1) {
            printf("Write to tun device failed! (%d: %s)\n", errno, strerror(errno));
        }
    } while (1);
    
}



/// @brief 处理客户端连接
/// @param arg 参数 SSL套接字
/// @return 空指针
void *process_connection(void *arg) {
    // 获取线程参数
    socket_param _param = *(socket_param *) arg;

    // SSL init
    SSL_CTX *ctx = server_ssl_init(_param.ca_path, _param.cert_path, _param.key_path);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, _param.client_sock);

    int err = SSL_accept(ssl);
    if (err <= 0) {
        err = SSL_get_error(ssl, err);
        fprintf(stderr, "error! SSL_accept return fail error:%d!\n", err);
        perror("Error during SSL_accept");
        ERR_print_errors_fp(stderr);
    }
    fprintf(stdout, "SSL_accept success!\n");

    // verify client
    if (verify(ssl) != 0) {
        printf("Client verify failed.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(_param.client_sock);
        return nullptr;
    }

    // 获取虚拟IP
    std::string virtual_ip_with_cidr = IPpool.alloc_IP_addr();
    std::string virtual_ip = virtual_ip_with_cidr.substr(0, virtual_ip_with_cidr.find_last_of('/'));


    // 将虚拟IP发送给客户端
    SSL_write(ssl, virtual_ip_with_cidr.c_str(), static_cast<int>(virtual_ip_with_cidr.length()) + 1);


    if (IP2Queue.find(virtual_ip) != IP2Queue.end()) {
        printf("[The IP %s is occupied.Choose another one.]", virtual_ip.c_str());
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(_param.client_sock);
        return nullptr;
    }

    // 创建队列
    auto queue = new ThreadSafeQueue();
    IP2Queue.insert(std::pair<std::string, ThreadSafeQueue *>(virtual_ip, queue));

    // 创建线程，监听队列
    printf("Create thread to listen %s\"s queue\n", virtual_ip.c_str());
    auto lpp = new listen_queue_param();
    lpp->ssl = ssl;
    lpp->ip_addr = virtual_ip;
    pthread_t listen_pipe_thread;
    pthread_create(&listen_pipe_thread, nullptr, listen_queue, (void *) lpp);

    // 监听socket
    printf("Listen socket from %s\n", virtual_ip.c_str());
    listen_sock(ssl, _param.tun_fd);

    // 通讯结束，删除连接信息
    // 结束监听queue进程
    // 清除与虚拟IP相关的信息
    delete lpp;
    IP2Queue.erase(virtual_ip);
    delete queue;
    IPpool.release_IP_addr(virtual_ip_with_cidr);
    // 关闭SSL
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(_param.client_sock);
    
    printf("%s disconnect! \n", virtual_ip.c_str());
    // 结束该线程
    pthread_exit(nullptr);
}




VPNServer::VPNServer(std::string bind_ip, int bind_port, std::string ca_path, std::string cert_path,
                     std::string key_path, std::string virtual_ip_cidr) {
    this->bind_ip = std::move(bind_ip);
    this->bind_port = bind_port;
    this->ca_path = std::move(ca_path);
    this->cert_path = std::move(cert_path);
    this->key_path = std::move(key_path);
    this->virtual_ip_cidr = std::move(virtual_ip_cidr);
}

VPNServer::~VPNServer() = default;

void VPNServer::Listen() {
    // 初始化IP池
    IPpool.init_ip_pool(this->virtual_ip_cidr);
    // 创建监听socket
    int listen_sock = setup_tcp_server(this->bind_ip, this->bind_port);
    // 创建tun设备
    int tun_fd = create_tun_device(this->virtual_ip_cidr);
    // 创建监听tun设备的线程
    pthread_t listen_tun_thread;
    pthread_create(&listen_tun_thread, nullptr, listen_tun, (void *) &tun_fd);


    while (true) {
        // 接受客户端连接
        int client_sock = accept_tcp_client(listen_sock);
        if (client_sock == -1) {
            fprintf(stderr, "error! client_sock return fail!\n");
            continue;
        }
        auto client_arg = (socket_param*) malloc(sizeof(socket_param));
        client_arg->client_sock = client_sock;
        client_arg->ca_path = this->ca_path.c_str();
        client_arg->cert_path = this->cert_path.c_str();
        client_arg->key_path = this->key_path.c_str();
        client_arg->tun_fd = tun_fd;
        pthread_t tid;
        int ret = pthread_create(&tid, nullptr, process_connection, (void *) client_arg);
        if (ret != 0) {
            perror("pthread_create failed");
        }
    }
}

