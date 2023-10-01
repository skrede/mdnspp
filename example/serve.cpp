#include <mdnspp/service_server.h>

int main(int argc, char **argv)
{
    mdnspp::service_server s("audhumbla", "_mdnspp-service._udp.local.");
    s.serve({
                {"Odin", std::nullopt},
                {"Thor",  "Balder"}
            }
    );
}