#ifndef HPP_GUARD_MDNSPP_DETAIL_PLATFORM_H
#define HPP_GUARD_MDNSPP_DETAIL_PLATFORM_H

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
// nfds_t is not provided by Windows headers
using nfds_t = unsigned long;
#else
#  include <arpa/inet.h>
#  include <sys/socket.h>
#  include <poll.h>
#endif

#endif
