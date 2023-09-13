#include <mbedtls/glue.h>
//#include "isv_enclave_t.h"
static inline void Log(const std::string& fmt) {
    printf_sgx(fmt.c_str());
    printf_sgx("\n");
}
template <typename P1>
void Log(const std::string& fmt, const P1& p1) {
    printf_sgx(fmt.c_str(), p1);
    printf_sgx("\n");
}

template <typename P1, typename P2>
void Log(const std::string& fmt, const P1& p1, const P2& p2) {
    printf_sgx( fmt.c_str(), p1, p2 ) ;
    printf_sgx("\n");
}

template <typename P1, typename P2, typename P3>
void Log(const std::string& fmt, const P1& p1, const P2& p2, const P3& p3) {
    printf_sgx(fmt.c_str(), p1, p2, p3);
    printf_sgx("\n");
}

template <typename P1, typename P2, typename P3, typename P4>
void Log(const std::string& fmt, const P1& p1, const P2& p2, const P3& p3, const P4& p4) {
    printf_sgx(fmt.c_str(), p1, p2, p3, p4);
    printf_sgx("\n");
}

template <typename P1, typename P2, typename P3, typename P4, typename P5>
void Log(const std::string& fmt, const P1& p1, const P2& p2, const P3& p3, const P4& p4, const P5& p5) {
    printf_sgx(fmt.c_str(), p1, p2, p3, p4, p5);
    printf_sgx("\n");
}
