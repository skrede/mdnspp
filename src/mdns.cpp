
#ifdef MDNS_FUZZING

#undef printf

// Fuzzing by piping random data into the recieve functions
static void
fuzz_mdns(void) {
#define MAX_FUZZ_SIZE 4096
#define MAX_PASSES (1024 * 1024 * 1024)

	static uint8_t fuzz_mdns_services_query[] = {
	    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, '_',
	    's',  'e',  'r',  'v',  'i',  'c',  'e',  's',  0x07, '_',  'd',  'n',  's',  '-',
	    's',  'd',  0x04, '_',  'u',  'd',  'p',  0x05, 'l',  'o',  'c',  'a',  'l',  0x00};

	uint8_t* buffer = malloc(MAX_FUZZ_SIZE);
	uint8_t* strbuffer = malloc(MAX_FUZZ_SIZE);
	for (int ipass = 0; ipass < MAX_PASSES; ++ipass) {
		size_t size = rand() % MAX_FUZZ_SIZE;
		for (size_t i = 0; i < size; ++i)
			buffer[i] = rand() & 0xFF;

		if (ipass % 4) {
			// Crafted fuzzing, make sure header is reasonable
			memcpy(buffer, fuzz_mdns_services_query, sizeof(fuzz_mdns_services_query));
			uint16_t* header = (uint16_t*)buffer;
			header[0] = 0;
			header[1] = htons(0x8400);
			for (int ival = 2; ival < 6; ++ival)
				header[ival] = rand() & 0xFF;
		}
		mdns_discovery_recv(0, (void*)buffer, size, query_callback, 0);

		mdns_socket_listen(0, (void*)buffer, size, service_callback, 0);

		if (ipass % 4) {
			// Crafted fuzzing, make sure header is reasonable (1 question claimed).
			// Earlier passes will have done completely random data
			uint16_t* header = (uint16_t*)buffer;
			header[2] = htons(1);
		}
		mdns_query_recv(0, (void*)buffer, size, query_callback, 0, 0);

		// Fuzzing by piping random data into the parse functions
		size_t offset = size ? (rand() % size) : 0;
		size_t length = size ? (rand() % (size - offset)) : 0;
		mdns_record_parse_ptr(buffer, size, offset, length, strbuffer, MAX_FUZZ_SIZE);

		offset = size ? (rand() % size) : 0;
		length = size ? (rand() % (size - offset)) : 0;
		mdns_record_parse_srv(buffer, size, offset, length, strbuffer, MAX_FUZZ_SIZE);

		struct sockaddr_in addr_ipv4;
		offset = size ? (rand() % size) : 0;
		length = size ? (rand() % (size - offset)) : 0;
		mdns_record_parse_a(buffer, size, offset, length, &addr_ipv4);

		struct sockaddr_in6 addr_ipv6;
		offset = size ? (rand() % size) : 0;
		length = size ? (rand() % (size - offset)) : 0;
		mdns_record_parse_aaaa(buffer, size, offset, length, &addr_ipv6);

		offset = size ? (rand() % size) : 0;
		length = size ? (rand() % (size - offset)) : 0;
		mdns_record_parse_txt(buffer, size, offset, length, (mdns_record_txt_t*)strbuffer,
		                      MAX_FUZZ_SIZE);

		if (ipass && !(ipass % 10000))
			printf("Completed fuzzing pass %d\n", ipass);
	}

	free(buffer);
	free(strbuffer);
}

#endif

int
main(int argc, const char* const* argv) {

    mdns_query_t query[16];
    size_t query_count = 0;
    int mode = 0;
    const char *service = "_test-mdns._tcp.local.";
    int service_port = 42424;

    for (int iarg = 0; iarg < argc; ++iarg) {
        if (strcmp(argv[iarg], "--discovery") == 0) {
            mode = 0;
        } else if (strcmp(argv[iarg], "--query") == 0) {

        } else if (strcmp(argv[iarg], "--service") == 0) {
            mode = 2;
            ++iarg;
            if (iarg < argc)
                service = argv[iarg];
        } else if (strcmp(argv[iarg], "--dump") == 0) {
            mode = 3;
        } else if (strcmp(argv[iarg], "--hostname") == 0) {
            ++iarg;
            if (iarg < argc)
                hostname = argv[iarg];
        } else if (strcmp(argv[iarg], "--port") == 0) {
            ++iarg;
            if (iarg < argc)
                service_port = atoi(argv[iarg]);
        }
    }

#ifdef MDNS_FUZZING
    fuzz_mdns();
#else
    int ret;
    if (mode == 0)
        ret = send_dns_sd();
    else if (mode == 1)
        ret = send_mdns_query(query, query_count);
    else if (mode == 2)
        ret = service_mdns(hostname, service, service_port);
    else if (mode == 3)
        ret = dump_mdns();
#endif


    return 0;
}