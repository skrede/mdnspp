#include <mdnspp/querent.h>

class example_sink : public mdnspp::log_sink
{
public:
    ~example_sink() override = default;

    void log(mdnspp::log_level level, const std::string &string) noexcept override
    {
        // redirect the printouts e.g., to file, or wrap around another logger implementation.
    }
};

int main(int, char **)
{
    mdnspp::querent d(std::make_shared<example_sink>());
    d.query({
        "unique_service_name.local.",
        MDNS_RECORDTYPE_ANY
    });
}
