#ifndef MD5_HH
#define MD5_HH

#if defined(OS_WIN) || defined(_WINDOWS_) || defined(_WIN32) || defined(__MSC_VER)
#include <stdint.h>
#else
#include <inttypes.h>
#endif
#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cstdio>

namespace sw
{
  namespace detail
  {

    /**
     * @class basic_md5
     * @template
     */
    template <typename Char_Type = char>
    class basic_md5
    {
    public:
      /**
       * Types
       */
      typedef std::basic_string<Char_Type> str_t;

    public:
      /**
       * Constructor
       */
      inline basic_md5()
      {
        clear();
      }

      /**
       * Destructor
       */
      virtual ~basic_md5()
      {
        ;
      }

    public:
      /**
       * Clear/reset all internal buffers and states.
       */
      void clear()
      {
        cnt_[0] = cnt_[1] = 0;
        sum_[0] = 0x67452301;
        sum_[1] = 0xefcdab89;
        sum_[2] = 0x98badcfe;
        sum_[3] = 0x10325476;
        memset(buf_, 0, sizeof buf_);
      }

      /**
       * Push new binary data into the internal buf_ and recalculate the checksum.
       * @param const void* data
       * @param size_t size
       */
      void update(const void *data, uint32_t size)
      {
        uint32_t index = cnt_[0] / 8 % 64;
        if ((cnt_[0] += (size << 3)) < (size << 3))
          cnt_[1]++; // Update number of bits
        cnt_[1] += (size >> 29);
        uint32_t i = 0, thresh = 64 - index; // number of bytes to fill in buffer
        if (size >= thresh)
        {                                     // transform as many times as possible.
          memcpy(&buf_[index], data, thresh); // fill buffer first, transform
          transform(buf_);
          for (i = thresh; i + 64 <= size; i += 64)
            transform(((const uint8_t *)data) + i);
          index = 0;
        }
        memcpy(&buf_[index], ((const uint8_t *)data) + i, size - i); // remainder
      }

      /**
       * Finanlise checksum, return hex string.
       * @return str_t
       */
      std::string final()
      {
#define U32_B(O_, I_, len)                            \
  {                                                   \
    for (uint32_t i = 0, j = 0; j < len; i++, j += 4) \
    {                                                 \
      (O_)[j] = (I_)[i] & 0xff;                       \
      (O_)[j + 1] = ((I_)[i] >> 8) & 0xff;            \
      (O_)[j + 2] = ((I_)[i] >> 16) & 0xff;           \
      (O_)[j + 3] = ((I_)[i] >> 24) & 0xff;           \
    }                                                 \
  }

        uint8_t padding[64];
        memset(padding, 0, sizeof(padding));
        padding[0] = 0x80;
        uint8_t bits[8]; // Save number of bits
        U32_B(bits, cnt_, 8);
        uint32_t index = cnt_[0] / 8 % 64; // pad out to 56 mod 64.
        uint32_t padLen = (index < 56) ? (56 - index) : (120 - index);
        update(padding, padLen);
        update(bits, 8); // Append length (before padding)
        uint8_t res[16];
        U32_B(res, sum_, 16);                  // Store state in digest
        std::basic_stringstream<Char_Type> ss; // hex string
        for (unsigned i = 0; i < 16; ++i)
        { // stream hex includes endian conversion
          ss << std::hex << std::setfill('0') << std::setw(2) << (res[i] & 0xff);
        }
        clear();
        return ss.str();
#undef U32_B
      }

    public:
      /**
       * Calculates the MD5 for a given string.
       * @param const str_t & s
       * @return str_t
       */
      static str_t calculate(const str_t &s)
      {
        basic_md5 r;
        r.update(s.data(), s.length());
        return r.final();
      }

      /**
       * Calculates the MD5 for a given C-string.
       * @param const char* s
       * @return str_t
       */
      static str_t calculate(const void *data, size_t size)
      {
        basic_md5 r;
        r.update(data, size);
        return r.final();
      }

      /**
       * Calculates the MD5 for a stream. Returns an empty string on error.
       * @param std::istream & is
       * @return str_t
       */
      static str_t calculate(std::istream &is)
      {
        basic_md5 r;
        char data[64];
        while (is.good() && is.read(data, sizeof(data)).good())
        {
          r.update(data, sizeof(data));
        }
        if (!is.eof())
          return str_t();
        if (is.gcount())
          r.update(data, is.gcount());
        return r.final();
      }

      /**
       * Calculates the MD5 checksum for a given file, either read binary or as text.
       * @param const str_t & path
       * @param bool binary = true
       * @return str_t
       */
      static str_t file(const str_t &path, bool binary = true)
      {
        std::ifstream fs;
        fs.open(path.c_str(), binary ? (std::ios::in | std::ios::binary) : (std::ios::in));
        str_t s = calculate(fs);
        fs.close();
        return s;
      }

    private:
      /**
       * Performs the MD5 transformation on a given block
       * @param uint32_t *block
       */
      void transform(const uint8_t *block)
      {
#define F1(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F2(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define F3(x, y, z) ((x) ^ (y) ^ (z))
#define F4(x, y, z) ((y) ^ ((x) | (~(z))))
#define RL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define FF(a, b, c, d, x, s, ac)                     \
  {                                                  \
    a = RL(a + F1(b, c, d) + (x) + (ac), (s)) + (b); \
  }
#define GG(a, b, c, d, x, s, ac)                     \
  {                                                  \
    a = RL(a + F2(b, c, d) + (x) + (ac), (s)) + (b); \
  }
#define HH(a, b, c, d, x, s, ac)             \
  {                                          \
    a = RL(a + F3(b, c, d) + x + ac, s) + b; \
  }
#define II(a, b, c, d, x, s, ac)             \
  {                                          \
    a = RL(a + F4(b, c, d) + x + ac, s) + b; \
  }

#define B_U32(output, input, len)                                                            \
  {                                                                                          \
    for (unsigned i = 0, j = 0; j < len; i++, j += 4)                                        \
    {                                                                                        \
      (output)[i] = ((uint32_t)(input)[j]) | (((uint32_t)(input)[j + 1]) << 8) |             \
                    (((uint32_t)(input)[j + 2]) << 16) | (((uint32_t)(input)[j + 3]) << 24); \
    }                                                                                        \
  }

        uint32_t a = sum_[0], b = sum_[1], c = sum_[2], d = sum_[3], x[16];
        B_U32(x, block, 64);
        FF(a, b, c, d, x[0], 7, 0xd76aa478);
        FF(d, a, b, c, x[1], 12, 0xe8c7b756);
        FF(c, d, a, b, x[2], 17, 0x242070db);
        FF(b, c, d, a, x[3], 22, 0xc1bdceee);
        FF(a, b, c, d, x[4], 7, 0xf57c0faf);
        FF(d, a, b, c, x[5], 12, 0x4787c62a);
        FF(c, d, a, b, x[6], 17, 0xa8304613);
        FF(b, c, d, a, x[7], 22, 0xfd469501);
        FF(a, b, c, d, x[8], 7, 0x698098d8);
        FF(d, a, b, c, x[9], 12, 0x8b44f7af);
        FF(c, d, a, b, x[10], 17, 0xffff5bb1);
        FF(b, c, d, a, x[11], 22, 0x895cd7be);
        FF(a, b, c, d, x[12], 7, 0x6b901122);
        FF(d, a, b, c, x[13], 12, 0xfd987193);
        FF(c, d, a, b, x[14], 17, 0xa679438e);
        FF(b, c, d, a, x[15], 22, 0x49b40821);
        GG(a, b, c, d, x[1], 5, 0xf61e2562);
        GG(d, a, b, c, x[6], 9, 0xc040b340);
        GG(c, d, a, b, x[11], 14, 0x265e5a51);
        GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
        GG(a, b, c, d, x[5], 5, 0xd62f105d);
        GG(d, a, b, c, x[10], 9, 0x2441453);
        GG(c, d, a, b, x[15], 14, 0xd8a1e681);
        GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
        GG(a, b, c, d, x[9], 5, 0x21e1cde6);
        GG(d, a, b, c, x[14], 9, 0xc33707d6);
        GG(c, d, a, b, x[3], 14, 0xf4d50d87);
        GG(b, c, d, a, x[8], 20, 0x455a14ed);
        GG(a, b, c, d, x[13], 5, 0xa9e3e905);
        GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
        GG(c, d, a, b, x[7], 14, 0x676f02d9);
        GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
        HH(a, b, c, d, x[5], 4, 0xfffa3942);
        HH(d, a, b, c, x[8], 11, 0x8771f681);
        HH(c, d, a, b, x[11], 16, 0x6d9d6122);
        HH(b, c, d, a, x[14], 23, 0xfde5380c);
        HH(a, b, c, d, x[1], 4, 0xa4beea44);
        HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
        HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
        HH(b, c, d, a, x[10], 23, 0xbebfbc70);
        HH(a, b, c, d, x[13], 4, 0x289b7ec6);
        HH(d, a, b, c, x[0], 11, 0xeaa127fa);
        HH(c, d, a, b, x[3], 16, 0xd4ef3085);
        HH(b, c, d, a, x[6], 23, 0x4881d05);
        HH(a, b, c, d, x[9], 4, 0xd9d4d039);
        HH(d, a, b, c, x[12], 11, 0xe6db99e5);
        HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
        HH(b, c, d, a, x[2], 23, 0xc4ac5665);
        II(a, b, c, d, x[0], 6, 0xf4292244);
        II(d, a, b, c, x[7], 10, 0x432aff97);
        II(c, d, a, b, x[14], 15, 0xab9423a7);
        II(b, c, d, a, x[5], 21, 0xfc93a039);
        II(a, b, c, d, x[12], 6, 0x655b59c3);
        II(d, a, b, c, x[3], 10, 0x8f0ccc92);
        II(c, d, a, b, x[10], 15, 0xffeff47d);
        II(b, c, d, a, x[1], 21, 0x85845dd1);
        II(a, b, c, d, x[8], 6, 0x6fa87e4f);
        II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        II(c, d, a, b, x[6], 15, 0xa3014314);
        II(b, c, d, a, x[13], 21, 0x4e0811a1);
        II(a, b, c, d, x[4], 6, 0xf7537e82);
        II(d, a, b, c, x[11], 10, 0xbd3af235);
        II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
        II(b, c, d, a, x[9], 21, 0xeb86d391);
        sum_[0] += a;
        sum_[1] += b;
        sum_[2] += c;
        sum_[3] += d;
        memset(x, 0, sizeof x);
#undef F1
#undef F2
#undef F3
#undef F4
#undef RL
#undef FF
#undef GG
#undef HH
#undef II
      }

    private:
      uint8_t buf_[64];
      uint32_t cnt_[2];
      uint32_t sum_[4];
    };
  }
}

namespace sw
{
  typedef detail::basic_md5<> md5;
}
#endif