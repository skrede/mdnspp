#include <mdnspp/querier.h>

int main(int argc, char **argv)
{
    mdnspp::querier d;
    d.inquire(
        {
            "audhumbla.local.",
            MDNS_RECORDTYPE_AAAA
        });

    d.inquire(
        {
            "audhumbla.local.",
            MDNS_RECORDTYPE_A
        });

    d.inquire(
        {
            "audhumbla._mdnspp-service._udp.local.",
            MDNS_RECORDTYPE_PTR
        });
}