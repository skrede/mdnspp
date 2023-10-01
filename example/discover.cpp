#include <mdnspp/service_discovery.h>

int main(int argc, char **argv)
{
    mdnspp::service_discovery d;
    d.discover();
}