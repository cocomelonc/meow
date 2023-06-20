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

#pragma once

#include <stddef.h>

#if defined (__cplusplus)
extern "C" {
#endif

/*******************************************************************************
 * ZeroMQ Base-85 encoding/decoding functions with custom padding              *
 *******************************************************************************/

/**
 * @brief Encodes 'inputSize' bytes from 'source' into 'dest'.
 *        If 'inputSize' is not divisible by 4 with no remainder, 'source' is padded.
 *        Destination buffer must be already allocated. Use Z85_encode_with_padding_bound() to
 *        evaluate size of the destination buffer.
 *
 * @param source in, input buffer (binary string to be encoded)
 * @param dest out, destination buffer
 * @param inputSize in, number of bytes to be encoded
 * @return number of printable symbols written into 'dest' or 0 if something goes wrong
 */
size_t Z85_encode_with_padding(const char* source, char* dest, size_t inputSize);

/**
 * @brief Decodes 'inputSize' printable symbols from 'source' into 'dest',
 *        encoded with Z85_encode_with_padding().
 *        Destination buffer must be already allocated. Use Z85_decode_with_padding_bound() to
 *        evaluate size of the destination buffer.
 *
 * @param source in, input buffer (printable string to be decoded)
 * @param dest out, destination buffer
 * @param inputSize in, number of symbols to be decoded
 * @return number of bytes written into 'dest' or 0 if something goes wrong
 */
size_t Z85_decode_with_padding(const char* source, char* dest, size_t inputSize);

/**
 * @brief Evaluates a size of output buffer needed to encode 'size' bytes
 *        into string of printable symbols using Z85_encode_with_padding().
 *
 * @param size in, number of bytes to be encoded
 * @return minimal size of output buffer in bytes
 */
size_t Z85_encode_with_padding_bound(size_t size);

/**
 * @brief Evaluates a size of output buffer needed to decode 'size' symbols
 *        into binary string using Z85_decode_with_padding().
 *
 * @param source in, input buffer (first symbol is read from 'source' to evaluate padding)
 * @param size in, number of symbols to be decoded
 * @return minimal size of output buffer in bytes
 */
size_t Z85_decode_with_padding_bound(const char* source, size_t size);



/*******************************************************************************
 * ZeroMQ Base-85 encoding/decoding functions (specification compliant)        *
 *******************************************************************************/

/**
 * @brief Encodes 'inputSize' bytes from 'source' into 'dest'.
 *        If 'inputSize' is not divisible by 4 with no remainder, 0 is retured.
 *        Destination buffer must be already allocated. Use Z85_encode_bound() to
 *        evaluate size of the destination buffer.
 *
 * @param source in, input buffer (binary string to be encoded)
 * @param dest out, destination buffer
 * @param inputSize in, number of bytes to be encoded
 * @return number of printable symbols written into 'dest' or 0 if something goes wrong
 */
size_t Z85_encode(const char* source, char* dest, size_t inputSize);

/**
 * @brief Decodes 'inputSize' printable symbols from 'source' into 'dest'.
 *        If 'inputSize' is not divisible by 5 with no remainder, 0 is returned.
 *        Destination buffer must be already allocated. Use Z85_decode_bound() to
 *        evaluate size of the destination buffer.
 *
 * @param source in, input buffer (printable string to be decoded)
 * @param dest out, destination buffer
 * @param inputSize in, number of symbols to be decoded
 * @return number of bytes written into 'dest' or 0 if something goes wrong
 */
size_t Z85_decode(const char* source, char* dest, size_t inputSize);

/**
 * @brief Evaluates a size of output buffer needed to encode 'size' bytes
 *        into string of printable symbols using Z85_encode().
 *
 * @param size in, number of bytes to be encoded
 * @return minimal size of output buffer in bytes
 */
size_t Z85_encode_bound(size_t size);

/**
 * @brief Evaluates a size of output buffer needed to decode 'size' symbols
 *        into binary string using Z85_decode().
 *
 * @param size in, number of symbols to be decoded
 * @return minimal size of output buffer in bytes
 */
size_t Z85_decode_bound(size_t size);



/*******************************************************************************
 * ZeroMQ Base-85 unsafe encoding/decoding functions (specification compliant) *
 *******************************************************************************/

/**
 * @brief Encodes bytes from [source;sourceEnd) range into 'dest'.
 *        It can be used for implementation of your own padding scheme.
 *        Preconditions:
 *           - (sourceEnd - source) % 4 == 0
 *           - destination buffer must be already allocated
 *
 * @param source in, begin of input buffer
 * @param sourceEnd in, end of input buffer (not included)
 * @param dest out, output buffer
 * @return a pointer immediately after last symbol written into the 'dest'
 */
char* Z85_encode_unsafe(const char* source, const char* sourceEnd, char* dest);

/**
 * @brief Decodes symbols from [source;sourceEnd) range into 'dest'.
 *        It can be used for implementation of your own padding scheme.
 *        Preconditions:
 *           - (sourceEnd - source) % 5 == 0
 *           - destination buffer must be already allocated
 *
 * @param source in, begin of input buffer
 * @param sourceEnd in, end of input buffer (not included)
 * @param dest out, output buffer
 * @return a pointer immediately after last byte written into the 'dest'
 */
char* Z85_decode_unsafe(const char* source, const char* sourceEnd, char* dest);

#if defined (__cplusplus)
}
#endif

