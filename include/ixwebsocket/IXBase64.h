#ifndef _MACARON_BASE64_H_
#define _MACARON_BASE64_H_

/**
 * The MIT License (MIT)
 * Copyright (c) 2016 tomykaira
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>

namespace macaron {

class Base64 {
 public:

  static std::string Encode(const std::string& data) {
    static constexpr char sEncodingTable[] = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
      'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
      'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
      'w', 'x', 'y', 'z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '+', '/'
    };

    size_t in_len = data.size();
    if (in_len > (std::numeric_limits<size_t>::max() / 4) * 3)
    {
      throw std::length_error("Base64 input too large");
    }

    size_t out_len = 4 * ((in_len + 2) / 3);
    std::string ret(out_len, '\0');
    size_t i = 0;
    size_t j = 0;

    while (i + 2 < in_len) {
      unsigned char a = static_cast<unsigned char>(data[i++]);
      unsigned char b = static_cast<unsigned char>(data[i++]);
      unsigned char c = static_cast<unsigned char>(data[i++]);
      ret[j++] = sEncodingTable[(a >> 2) & 0x3F];
      ret[j++] = sEncodingTable[((a & 0x3) << 4) | (b >> 4)];
      ret[j++] = sEncodingTable[((b & 0xF) << 2) | (c >> 6)];
      ret[j++] = sEncodingTable[c & 0x3F];
    }
    if (i < in_len) {
      unsigned char a = static_cast<unsigned char>(data[i++]);
      ret[j++] = sEncodingTable[(a >> 2) & 0x3F];
      if (i == in_len) {
        ret[j++] = sEncodingTable[(a & 0x3) << 4];
        ret[j++] = '=';
      }
      else {
        unsigned char b = static_cast<unsigned char>(data[i]);
        ret[j++] = sEncodingTable[((a & 0x3) << 4) | (b >> 4)];
        ret[j++] = sEncodingTable[(b & 0xF) << 2];
      }
      ret[j++] = '=';
    }

    return ret;
  }

  static std::string Decode(const std::string& input, std::string& out) {
    static constexpr unsigned char kDecodingTable[] = {
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
      64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
      64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
      64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
    };

    size_t in_len = input.size();
    if (in_len == 0) {
      out.clear();
      return "";
    }
    if (in_len % 4 != 0) return "Input data size is not a multiple of 4";

    size_t padding = 0;
    if (input[in_len - 1] == '=') padding++;
    if (input[in_len - 2] == '=') padding++;

    for (size_t i = 0; i < in_len - padding; ++i) {
      unsigned char c = static_cast<unsigned char>(input[i]);
      if (input[i] == '=' || kDecodingTable[c] == 64) {
        return "Input data contains invalid base64 characters";
      }
    }

    for (size_t i = in_len - padding; i < in_len; ++i) {
      if (input[i] != '=') {
        return "Input data contains invalid base64 padding";
      }
    }

    size_t out_len = in_len / 4 * 3;
    out_len -= padding;

    out.resize(out_len);

    for (size_t i = 0, j = 0; i < in_len;) {
      uint32_t a = kDecodingTable[static_cast<unsigned char>(input[i++])];
      uint32_t b = kDecodingTable[static_cast<unsigned char>(input[i++])];
      uint32_t c = input[i] == '=' ? 0 : kDecodingTable[static_cast<unsigned char>(input[i])];
      ++i;
      uint32_t d = input[i] == '=' ? 0 : kDecodingTable[static_cast<unsigned char>(input[i])];
      ++i;

      uint32_t triple = (a << 3 * 6) + (b << 2 * 6) + (c << 1 * 6) + (d << 0 * 6);

      if (j < out_len) out[j++] = (triple >> 2 * 8) & 0xFF;
      if (j < out_len) out[j++] = (triple >> 1 * 8) & 0xFF;
      if (j < out_len) out[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return "";
  }

};

}

#endif /* _MACARON_BASE64_H_ */
