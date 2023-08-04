#include <mdnspp/query.h>

int main(int argc, char** argv)
{
    mdnspp::query d;
    mdnspp::query_t query;
    query.name = "fau shau";
    query.type = mdns_record_type::MDNS_RECORDTYPE_ANY;
    d.send(query);
}