#include <mdnspp/service.h>

int main(int argc, char** argv)
{
    mdnspp::service s;
    s.serve("mdnspp", "example", 27015);
}