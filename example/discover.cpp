#include <mdnspp/discovery.h>

int main(int argc, char** argv)
{
    mdnspp::Discovery d;
    d.discover_async();
}