#include <mdnspp/service_server.h>

int main(int, char **)
{
    mdnspp::service_server s("preferably_unique_name", "_mdnspp-service._udp.local.");
    s.serve({
            {"flag", std::nullopt},
            {"key", "value"}
        }
    );
}
