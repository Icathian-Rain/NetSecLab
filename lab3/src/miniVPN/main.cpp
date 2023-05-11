#include "VPNClient.h"
#include "VPNServer.h"
int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " <server|client> [args]" << std::endl;
        return 0;
    }
    std::string mode = std::string(argv[1]);
    if (mode == "server")
    {
        VPNServer server("10.9.0.11", 4433, "cert/ca.crt", "cert/fqhserver.crt", "cert/fqhserver.key.unsecure",  "192.168.53.0/24");
        server.Listen();
    }
    else if (mode == "client")
    {
        VPNClient client("fqhvpnserver.com", 4433, "cert/ca.crt", "192.168.60.0/24");
        client.connect();
    }

}


