/*
 * Copyright 2013 Stanislav Artemkin <artemkin@gmail.com>.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Implementation of 32/Z85 specification (http://rfc.zeromq.org/spec:32/Z85)
 * Source repository: http://github.com/artemkin/z85
 */

#include <assert.h>
#include <limits.h>

#include "z85.h"

typedef unsigned int  uint32_t;
typedef unsigned char byte;

// make sure uint32_t is 32-bit
typedef char Z85_uint32_t_static_assert[(sizeof(uint32_t) * CHAR_BIT == 32) * 2 - 1];

#define DIV85_MAGIC 3233857729ULL
// make sure magic constant is 64-bit
typedef char Z85_div85_magic_static_assert[(sizeof(DIV85_MAGIC) * CHAR_BIT == 64) * 2 - 1];

#define DIV85(number) ((uint32_t)((DIV85_MAGIC * number) >> 32) >> 6)

static const char* base85 =
{
   "0123456789"
   "abcdefghij"
   "klmnopqrst"
   "uvwxyzABCD"
   "EFGHIJKLMN"
   "OPQRSTUVWX"
   "YZ.-:+=^!/"
   "*?&<>()[]{"
   "}@%$#"
};

static byte base256[] =
{
   0x00, 0x44, 0x00, 0x54, 0x53, 0x52, 0x48, 0x00,
   0x4B, 0x4C, 0x46, 0x41, 0x00, 0x3F, 0x3E, 0x45,
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
   0x08, 0x09, 0x40, 0x00, 0x49, 0x42, 0x4A, 0x47,
   0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
   0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
   0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
   0x3B, 0x3C, 0x3D, 0x4D, 0x00, 0x4E, 0x43, 0x00,
   0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
   0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
   0x21, 0x22, 0x23, 0x4F, 0x00, 0x50, 0x00, 0x00
};

char* Z85_encode_unsafe(const char* source, const char* sourceEnd, char* dest)
{
   byte* src = (byte*)source;
   byte* end = (byte*)sourceEnd;
   byte* dst = (byte*)dest;
   uint32_t value;
   uint32_t value2;

   for (; src != end; src += 4, dst += 5)
   {
      // unpack big-endian frame
      value = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];

      value2 = DIV85(value); dst[4] = base85[value - value2 * 85]; value = value2;
      value2 = DIV85(value); dst[3] = base85[value - value2 * 85]; value = value2;
      value2 = DIV85(value); dst[2] = base85[value - value2 * 85]; value = value2;
      value2 = DIV85(value); dst[1] = base85[value - value2 * 85];
      dst[0] = base85[value2];
   }

   return (char*)dst;
}

char* Z85_decode_unsafe(const char* source, const char* sourceEnd, char* dest)
{
   byte* src = (byte*)source;
   byte* end = (byte*)sourceEnd;
   byte* dst = (byte*)dest;
   uint32_t value;

   for (; src != end; src += 5, dst += 4)
   {
      value =              base256[(src[0] - 32) & 127];
      value = value * 85 + base256[(src[1] - 32) & 127];
      value = value * 85 + base256[(src[2] - 32) & 127];
      value = value * 85 + base256[(src[3] - 32) & 127];
      value = value * 85 + base256[(src[4] - 32) & 127];

      // pack big-endian frame
      dst[0] = value >> 24;
      dst[1] = (byte)(value >> 16);
      dst[2] = (byte)(value >> 8);
      dst[3] = (byte)(value);
   }

   return (char*)dst;
}

size_t Z85_encode_bound(size_t size)
{
   return size * 5 / 4;
}

size_t Z85_decode_bound(size_t size)
{
   return size * 4 / 5;
}

size_t Z85_encode(const char* source, char* dest, size_t inputSize)
{
   if (!source || !dest || inputSize % 4)
   {
      assert(!"wrong source, destination or input size");
      return 0;
   }

   return Z85_encode_unsafe(source, source + inputSize, dest) - dest;
}

size_t Z85_decode(const char* source, char* dest, size_t inputSize)
{
   if (!source || !dest || inputSize % 5)
   {
      assert(!"wrong source, destination or input size");
      return 0;
   }

   return Z85_decode_unsafe(source, source + inputSize, dest) - dest;
}

size_t Z85_encode_with_padding_bound(size_t size)
{
   if (size == 0) return 0;
   size = Z85_encode_bound(size);
   return size + (5 - size % 5) % 5 + 1;
}

size_t Z85_decode_with_padding_bound(const char* source, size_t size)
{
   if (size == 0 || !source || (byte)(source[0] - '0' - 1) > 3) return 0;
   return Z85_decode_bound(size - 1) - 4 + (source[0] - '0');
}

size_t Z85_encode_with_padding(const char* source, char* dest, size_t inputSize)
{
   size_t      tailBytes  = inputSize % 4;
   char        tailBuf[4] = { 0 };
   char*       dst        = dest;
   const char* end        = source + inputSize - tailBytes;

   assert(source && dest);

   // zero length string is not padded
   if (!source || !dest || inputSize == 0)
   {
      return 0;
   }

   (dst++)[0] = (tailBytes == 0 ? '4' : '0' + (char)tailBytes); // write tail bytes count
   dst = Z85_encode_unsafe(source, end, dst);                   // write body

   // write tail
   switch (tailBytes)
   {
   case 3:
      tailBuf[2] = end[2];
   case 2:
      tailBuf[1] = end[1];
   case 1:
      tailBuf[0] = end[0];
      dst = Z85_encode_unsafe(tailBuf, tailBuf + 4, dst);
   }

   return dst - dest;
}

size_t Z85_decode_with_padding(const char* source, char* dest, size_t inputSize)
{
   char*       dst        = dest;
   size_t      tailBytes;
   char        tailBuf[4] = { 0 };
   const char* end        = source + inputSize;

   assert(source && dest && (inputSize == 0 || (inputSize - 1) % 5 == 0));

   // zero length string is not padded
   if (!source || !dest || inputSize == 0 || (inputSize - 1) % 5)
   {
      return 0;
   }

   tailBytes = (source++)[0] - '0'; // possible values: 1, 2, 3 or 4
   if (tailBytes - 1 > 3)
   {
      assert(!"wrong tail bytes count");
      return 0;
   }

   end -= 5;
   if (source != end)
   {
      // decode body
      dst = Z85_decode_unsafe(source, end, dst);
   }

   // decode last 5 bytes chunk
   Z85_decode_unsafe(end, end + 5, tailBuf);

   switch (tailBytes)
   {
   case 4:
      dst[3] = tailBuf[3];
   case 3:
      dst[2] = tailBuf[2];
   case 2:
      dst[1] = tailBuf[1];
   case 1:
      dst[0] = tailBuf[0];
   }

   return dst - dest + tailBytes;
}
