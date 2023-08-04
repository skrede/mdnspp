#include <mdnspp/service.h>

int main(int argc, char** argv)
{
    mdnspp::Service s;
    s.serve("mdnspp", "example", 27015);
}