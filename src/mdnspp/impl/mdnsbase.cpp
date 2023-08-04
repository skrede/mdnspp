#include "mdnspp/impl/mdnsbase.h"

using namespace mdnspp;

#ifdef _WIN32
BOOL console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        running = 0;
    }
    return TRUE;
}
#else
void signal_handler(int signal)
{
    printf("Signal received, %s", signal);
//    running = 0;
}
#endif

MDNSBase::MDNSBase()
{
    const char *hostname = "dummy-host";

#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData;
    if (WSAStartup(versionWanted, &wsaData)) {
        printf("Failed to initialize WinSock\n");
        return -1;
    }

    char hostname_buffer[256];
    DWORD hostname_size = (DWORD)sizeof(hostname_buffer);
    if (GetComputerNameA(hostname_buffer, &hostname_size))
        hostname = hostname_buffer;

    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    char hostname_buffer[256];
    size_t hostname_size = sizeof(hostname_buffer);
    if(gethostname(hostname_buffer, hostname_size) == 0)
        hostname = hostname_buffer;
    signal(SIGINT, signal_handler);
#endif
}

MDNSBase::~MDNSBase()
{
#ifdef _WIN32
    WSACleanup();
#endif
}
