#include <mdnspp/querier.h>

int main(int, char **)
{
    mdnspp::querier d;
    d.inquire(
        {
            "preferably_unique_name.local.",
            MDNS_RECORDTYPE_AAAA
        });

    d.inquire(
        {
            "preferably_unique_name.local.",
            MDNS_RECORDTYPE_A
        });

    d.inquire(
        {
            "preferably_unique_name._mdnspp-service._udp.local.",
            MDNS_RECORDTYPE_ANY
        });
}
