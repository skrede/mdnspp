#include <mdnspp/service.h>

int main(int argc, char** argv)
{
    mdnspp::service s("mdnspp", "example", 27015);
    s.serve();
}