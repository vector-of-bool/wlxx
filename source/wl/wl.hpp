#ifndef WL_WL_HPP_INCLUDED
#define WL_WL_HPP_INCLUDED

#include <system_error>

struct wl_array;

namespace wl {

using string = std::string;
using error_code = std::error_code;
using fd = int;
using array = ::wl_array;
using fixed = double;
using uint = std::uint32_t;

namespace detail {

inline void ec_check(const std::error_code& ec, const char* msg) {
    if (ec) {
        throw std::system_error{ec, msg};
    }
}

inline std::error_code ec_from_errno() {
    return std::error_code(errno, std::system_category());
}

template <typename Func, typename... Args>
decltype(auto) call(Func fn, std::error_code& ec, Args&&... args) {
    errno = 0;
    auto ret = fn(args...);
    ec = ec_from_errno();
    return ret;
}
}
}

#endif  // WL_WL_HPP_INCLUDED