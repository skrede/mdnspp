#include <mdnspp/service_discovery.h>

int main(int, char **)
{
mdnspp::service_discovery d;
d.discover({
    [](const std::shared_ptr<mdnspp::record_t> &record)
    {
        return record->sender_address.starts_with("192.168.1.169");
    }
});
}
