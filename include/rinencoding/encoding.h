/* SPDX-License-Identifier: MIT */
#ifndef RINENCODING_ENCODING_H
#define RINENCODING_ENCODING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RinEncodingStatus {
    RIN_ENCODING_OK = 0,
    RIN_ENCODING_INVALID_ARGUMENT = -1,
    RIN_ENCODING_BUFFER_TOO_SMALL = -2,
    RIN_ENCODING_MALFORMED = -3,
    RIN_ENCODING_OVERFLOW = -4
} RinEncodingStatus;

typedef enum RinEncodingBase64Alphabet {
    RIN_ENCODING_BASE64_STANDARD = 0,
    RIN_ENCODING_BASE64_URL_SAFE = 1
} RinEncodingBase64Alphabet;

enum {
    RIN_ENCODING_BASE64_PADDING_REQUIRED = 1u << 0,
    RIN_ENCODING_BASE64_ALLOW_UNPADDED = 1u << 1,
    RIN_ENCODING_BASE64_ALLOW_WHITESPACE = 1u << 2
};

/* All size helpers return SIZE_MAX when the result cannot be represented. */
size_t rin_encoding_base64_encoded_size(size_t input_size, int padded);
size_t rin_encoding_base64_decoded_size(size_t input_size);

int rin_encoding_base64_encode(const uint8_t* input, size_t input_size,
                               RinEncodingBase64Alphabet alphabet, int padded,
                               uint8_t* output, size_t output_capacity,
                               size_t* output_size);
int rin_encoding_base64_decode(const uint8_t* input, size_t input_size,
                               RinEncodingBase64Alphabet alphabet,
                               unsigned flags, uint8_t* output,
                               size_t output_capacity, size_t* output_size);

/* RFC 4648 base64url convenience API for web/token fields.  Encoding is
 * always unpadded; decoding accepts optional '=' padding but never ignores
 * whitespace or the standard '+' and '/' alphabet. */
size_t rin_encoding_base64url_encoded_size(size_t input_size);
int rin_encoding_base64url_encode(const uint8_t* input, size_t input_size,
                                  uint8_t* output, size_t output_capacity,
                                  size_t* output_size);
int rin_encoding_base64url_decode(const uint8_t* input, size_t input_size,
                                  uint8_t* output, size_t output_capacity,
                                  size_t* output_size);

/* Strict, bounded PEM armor for opaque key/certificate payloads.  The
 * encoder emits LF-terminated lines with at most 64 Base64 characters.  The
 * decoder accepts LF or CRLF line endings but rejects headers, labels, body
 * whitespace, trailing data, and mismatched BEGIN/END labels.  This helper
 * owns only the byte encoding; key type semantics and secret storage remain
 * with the private key owner. */
#define RIN_ENCODING_PEM_LABEL_MAX 64u
size_t rin_encoding_pem_encoded_size(const char* label, size_t input_size);
int rin_encoding_pem_encode(const char* label, const uint8_t* input,
                            size_t input_size, uint8_t* output,
                            size_t output_capacity, size_t* output_size);
int rin_encoding_pem_decode(const uint8_t* input, size_t input_size,
                            char* label_output, size_t label_capacity,
                            uint8_t* output, size_t output_capacity,
                            size_t* output_size);

/* Allocation-free incremental Base64 encoder.  update() reports the input
 * bytes it accepted; when output capacity is exhausted it may return
 * RIN_ENCODING_BUFFER_TOO_SMALL with a complete pending block retained in
 * the state, so the caller can retry with input_size == 0. */
typedef struct RinEncodingBase64Encoder {
    RinEncodingBase64Alphabet alphabet;
    uint8_t padded;
    uint8_t finalized;
    uint8_t tail_size;
    uint8_t tail[2];
} RinEncodingBase64Encoder;

int rin_encoding_base64_encoder_init(RinEncodingBase64Encoder* encoder,
                                     RinEncodingBase64Alphabet alphabet,
                                     int padded);
int rin_encoding_base64_encoder_update(RinEncodingBase64Encoder* encoder,
                                       const uint8_t* input, size_t input_size,
                                       uint8_t* output, size_t output_capacity,
                                       size_t* input_consumed,
                                       size_t* output_size);
int rin_encoding_base64_encoder_final(RinEncodingBase64Encoder* encoder,
                                      uint8_t* output, size_t output_capacity,
                                      size_t* output_size);

/* Allocation-free incremental Base64 decoder.  A completed quartet may be
 * retained when output capacity is insufficient; retry update/final with a
 * larger buffer and no new input.  The decoder applies the same strict
 * alphabet, padding, unpadded, and optional-whitespace policy as the
 * one-shot API. */
typedef struct RinEncodingBase64Decoder {
    RinEncodingBase64Alphabet alphabet;
    unsigned flags;
    int quartet[4];
    uint8_t quartet_size;
    uint8_t saw_padding;
    uint8_t finalized;
} RinEncodingBase64Decoder;

int rin_encoding_base64_decoder_init(RinEncodingBase64Decoder* decoder,
                                     RinEncodingBase64Alphabet alphabet,
                                     unsigned flags);
int rin_encoding_base64_decoder_update(RinEncodingBase64Decoder* decoder,
                                       const uint8_t* input, size_t input_size,
                                       uint8_t* output, size_t output_capacity,
                                       size_t* input_consumed,
                                       size_t* output_size);
int rin_encoding_base64_decoder_final(RinEncodingBase64Decoder* decoder,
                                      uint8_t* output, size_t output_capacity,
                                      size_t* output_size);

size_t rin_encoding_hex_encoded_size(size_t input_size);
int rin_encoding_hex_encode(const uint8_t* input, size_t input_size,
                            int uppercase, uint8_t* output,
                            size_t output_capacity, size_t* output_size);
int rin_encoding_hex_decode(const uint8_t* input, size_t input_size,
                            uint8_t* output, size_t output_capacity,
                            size_t* output_size);

/* Decode RFC 2045 quoted-printable into a bounded caller-owned buffer.
 * Soft line breaks ("=\\n" and "=\\r\\n") are removed. On failure,
 * output_size is zero and the status identifies malformed input or capacity. */
int rin_encoding_quoted_printable_decode(const uint8_t* input,
                                         size_t input_size, uint8_t* output,
                                         size_t output_capacity,
                                         size_t* output_size);

/* Decode the B or Q encoded-text payload of one RFC 2047 encoded-word.
 * Charset conversion and header folding remain the caller's responsibility. */
int rin_encoding_rfc2047_decode_payload(char encoding, const uint8_t* input,
                                         size_t input_size, uint8_t* output,
                                         size_t output_capacity,
                                         size_t* output_size);

size_t rin_encoding_percent_encoded_size(const uint8_t* input,
                                         size_t input_size);
int rin_encoding_percent_encode(const uint8_t* input, size_t input_size,
                                uint8_t* output, size_t output_capacity,
                                size_t* output_size);
int rin_encoding_percent_decode(const uint8_t* input, size_t input_size,
                                uint8_t* output, size_t output_capacity,
                                size_t* output_size);

#ifdef __cplusplus
}
#endif

#endif
