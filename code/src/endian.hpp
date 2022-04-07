#pragma once
#ifndef ENDIAN_HPP
#define ENDIAN_HPP
#include <utility>
/*
 * Seems that boost.endian not working on msvc
 * Use implementation on https://stackoverflow.com/a/36937049
 */
template <class T, std::size_t... N>
constexpr T bswap_impl(T i, std::index_sequence<N...>) {
  return ((((i >> (N * CHAR_BIT)) & (T)(unsigned char)(-1))
           << ((sizeof(T) - 1 - N) * CHAR_BIT)) |
          ...);
};
template <class T, class U = typename std::make_unsigned<T>::type>
constexpr U byteswap(T i) {
  return bswap_impl<U>(i, std::make_index_sequence<sizeof(T)>{});
}
template <class T> constexpr T native_to_big(const T &x) {
  if constexpr (std::endian::native == std::endian::big)
    return x;
  else
    return byteswap(
        x); // c++23 has this in STL, but compiler isn't ready for it.
}

#endif // ENDIAN_HPP
