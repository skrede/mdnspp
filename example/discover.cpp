#include <mdnspp/service_discovery.h>

int main(int, char **)
{
    mdnspp::service_discovery d;
    d.discover();
}
