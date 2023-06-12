#include "CLI11.hpp"
#include "VPNClient.h"
#include "VPNServer.h"
int main(int argc, char *argv[])
{
    CLI::App app{"MiniVPN"};
    std::string mode;
    // server参数
    std::string s_ip= "10.9.0.11";
    int s_port = 4433;
    std::string s_ca = "cert/ca.crt";
    std::string s_cert = "cert/fqhserver.crt";
    std::string s_key = "cert/fqhserver.key.unsecure";
    std::string s_cidr = "192.168.53.0/24";
    // client参数
    std::string c_domain = "fqhvpnserver.com";
    int c_port = 4433;
    std::string c_ca = "cert/ca.crt";
    std::string c_cidr = "192.168.60.0/24";

    app.add_option("-m,--mode", mode, "mode: server or client")->required();
    app.add_option("-i,--ip", s_ip, "server: bind ip, default: 10.9.0.11")->group("server");
    app.add_option("-p,--port", s_port, "server: bind port, default: 4433")->group("server");
    app.add_option("-c,--ca", s_ca, "server: ca file, default: cert/ca.crt")->group("server");
    app.add_option("-e,--cert", s_cert, "server: cert file, default: cert/fqhserver.crt")->group("server");
    app.add_option("-k,--key", s_key, "server: key file, default: cert/fqhserver.key.unsecure")->group("server");
    app.add_option("-n,--tun", s_cidr, "server: tun cidr, default: 192.168.53.0/24")->group("server");
    app.add_option("-d,--domain", c_domain, "client: server domain, default: fqhvpnserver.com")->group("client");
    app.add_option("-o,--cport", c_port, "client: server port, default: 4433")->group("client");
    app.add_option("-a,--cca", c_ca, "client: ca file, default: cert/ca.crt")->group("client");
    app.add_option("-r,--cidr", c_cidr, "client: destination ip cidr, default: 192.168.60.0/24")->group("client");


    CLI11_PARSE(app, argc, argv);

    if (mode == "server")
    {
        // VPNServer server("10.9.0.11", 4433, "cert/ca.crt", "cert/fqhserver.crt", "cert/fqhserver.key.unsecure",  "192.168.53.0/24");
        VPNServer server(s_ip, s_port, s_ca, s_cert, s_key, s_cidr);
        server.Listen();
    }
    else if (mode == "client")
    {
        // VPNClient client("fqhvpnserver.com", 4433, "cert/ca.crt", "192.168.60.0/24");
        VPNClient client(c_domain, c_port, c_ca, c_cidr);
        client.connect();
    }

}


