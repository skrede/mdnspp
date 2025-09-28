#include <mdnspp/service_server.h>

int main(int, char **)
{
    mdnspp::service_server s("unique_service_name", "_mdnspp-service._udp.local.");
    s.serve({
            {"flag", std::nullopt},
            {"key", "value"}
        }
    );
}
