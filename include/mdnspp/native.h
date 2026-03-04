#ifndef HPP_GUARD_MDNSPP_NATIVE_H
#define HPP_GUARD_MDNSPP_NATIVE_H

// mdnspp/native.h — umbrella header for NativePolicy standalone networking.
//
// Include this single header to access NativeContext, NativeSocket,
// NativeTimer, and NativePolicy. No ASIO in the include chain.
//
// Usage:
//   #include <mdnspp/native.h>
//   #include <mdnspp/observer.h>
//
//   mdnspp::NativeContext ctx;
//   mdnspp::observer<mdnspp::NativePolicy> obs{ctx, my_callback};
//   obs.start();
//   ctx.run();

#include "mdnspp/native/native_context.h"
#include "mdnspp/native/native_socket.h"
#include "mdnspp/native/native_timer.h"
#include "mdnspp/native/native_policy.h"

#endif // HPP_GUARD_MDNSPP_NATIVE_H
