// Standalone compile test — verifies infrastructure headers build in isolation.
// platform.h and dns_enums.h need no special defines.
// asio_completion.h requires ASIO_STANDALONE to be non-empty, but compiling
// without it is also valid (the file is empty when ASIO_STANDALONE is not defined).

#include "mdnspp/detail/platform.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/asio/asio_completion.h"

int main() {}
