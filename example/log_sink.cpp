#include <mdnspp/querier.h>

namespace mdnspp {

class example_sink : public log_sink
{
public:
    ~example_sink() override = default;

    void log(log_level level, const std::string &string) noexcept override
    {
        // print to stdout and omit the log level.
        std::cout << string << std::endl;
    }
};

}

int main(int argc, char **argv)
{
    mdnspp::querier d(std::make_shared<mdnspp::example_sink>());
    d.inquire(
        {
            "audhumbla._mdnspp-service._udp.local.",
            MDNS_RECORDTYPE_TXT
        });
}