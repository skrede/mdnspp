#include "mdnspp/impl/services.h"

void mdnspp::default_records(const service_t &service, mdnspp::records_t &records)
{
//    mdnspp::records_t records = {0};

    // Setup our mDNS records
    // PTR record reverse mapping "<_service-name>._tcp.local." to
    // "<hostname>.<_service-name>._tcp.local."
    records.record_ptr.name = service.service;
    records.record_ptr.type = MDNS_RECORDTYPE_PTR;
    records.record_ptr.data.ptr.name = service.service_instance;
    records.record_ptr.rclass = 0;
    records.record_ptr.ttl = 0;

    // SRV record mapping "<hostname>.<_service-name>._tcp.local." to
    // "<hostname>.local." with port. Set weight & priority to 0.
    records.record_srv.name = service.service_instance;
    records.record_srv.type = MDNS_RECORDTYPE_SRV;
    records.record_srv.data.srv.name = service.hostname_qualified;
    records.record_srv.data.srv.port = service.port;
    records.record_srv.data.srv.priority = 0;
    records.record_srv.data.srv.weight = 0;
    records.record_srv.rclass = 0;
    records.record_srv.ttl = 0;

    // A/AAAA records mapping "<hostname>.local." to IPv4/IPv6 addresses
    records.record_a.name = service.hostname_qualified;
    records.record_a.type = MDNS_RECORDTYPE_A;
    records.record_a.data.a.addr = service.address_ipv4;
    records.record_a.rclass = 0;
    records.record_a.ttl = 0;

    records.record_aaaa.name = service.hostname_qualified;
    records.record_aaaa.type = MDNS_RECORDTYPE_AAAA;
    records.record_aaaa.data.aaaa.addr = service.address_ipv6;
    records.record_aaaa.rclass = 0;
    records.record_aaaa.ttl = 0;

    // Add two test TXT records for our service instance name, will be coalesced into
    // one record with both key-value pair strings by the library
    records.txt_record[0].name = service.service_instance;
    records.txt_record[0].type = MDNS_RECORDTYPE_TXT;
    records.txt_record[0].data.txt.key = {
        MDNS_STRING_CONST("test")
    };
    records.txt_record[0].data.txt.value = {
        MDNS_STRING_CONST("1")
    };
    records.txt_record[0].rclass = 0;
    records.txt_record[0].ttl = 0;

    records.txt_record[1].name = service.service_instance;
    records.txt_record[1].type = MDNS_RECORDTYPE_TXT;
    records.txt_record[1].data.txt.key = {
        MDNS_STRING_CONST("other")
    };
    records.txt_record[1].data.txt.value = {
        MDNS_STRING_CONST("value")
    };
    records.txt_record[1].rclass = 0;
    records.txt_record[1].ttl = 0;
}
