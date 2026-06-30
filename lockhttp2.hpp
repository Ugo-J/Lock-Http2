#ifndef LOCKHTTP2_MAIN_HEADER_HPP
#define LOCKHTTP2_MAIN_HEADER_HPP

#ifdef USE_WOLFSSL
    // If the compiled with -DUSE_WOLFSSL, route to the wolfSSL variant
    #include "wolfssl/lockhttp2.hpp"
#else
    // default fallback variant using standard openSSL
    #include "openssl/lockhttp2.hpp"
#endif

#endif
