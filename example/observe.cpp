#include <mdnspp/observer.h>

int main(int, char **)
{
mdnspp::observer s;
s.set_log_level(mdnspp::log_level::trace);
s.observe();
}
