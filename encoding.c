/* SPDX-License-Identifier: MIT */
#include "include/rinencoding/encoding.h"
#include "../rinsecure/include/rinsecure/memory.h"

#include <limits.h>

static int rin_encoding_output_valid(uint8_t* output, size_t capacity,
                                     size_t* output_size)
{
    if (output_size == NULL || (capacity != 0u && output == NULL)) {
        if (output_size != NULL) *output_size = 0u;
        if (output != NULL && capacity != 0u) rin_secure_zero(output, capacity);
        return 0;
    }
    *output_size = 0u;
    if (output != NULL && capacity != 0u) rin_secure_zero(output, capacity);
    return 1;
}

size_t rin_encoding_base64_encoded_size(size_t input_size, int padded)
{
    size_t groups;
    if (input_size > SIZE_MAX - 2u) return SIZE_MAX;
    groups = (input_size + 2u) / 3u;
    if (groups > SIZE_MAX / 4u) return SIZE_MAX;
    if (padded) return groups * 4u;
    if (input_size % 3u == 0u) return groups * 4u;
    return groups * 4u - (3u - input_size % 3u);
}

size_t rin_encoding_base64_decoded_size(size_t input_size)
{
    const size_t groups = input_size / 4u;
    if (groups > (SIZE_MAX - 3u) / 3u) return SIZE_MAX;
    if (input_size % 4u == 0u) return groups * 3u;
    return groups * 3u + 2u;
}

static const char* rin_encoding_base64_alphabet(
    RinEncodingBase64Alphabet alphabet)
{
    static const char standard[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char url_safe[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return alphabet == RIN_ENCODING_BASE64_URL_SAFE ? url_safe : standard;
}

int rin_encoding_base64_encode(const uint8_t* input, size_t input_size,
                               RinEncodingBase64Alphabet alphabet, int padded,
                               uint8_t* output, size_t output_capacity,
                               size_t* output_size)
{
    const char* digits;
    size_t required;
    size_t index;
    size_t written = 0u;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    if (alphabet != RIN_ENCODING_BASE64_STANDARD &&
        alphabet != RIN_ENCODING_BASE64_URL_SAFE)
        return RIN_ENCODING_INVALID_ARGUMENT;
    required = rin_encoding_base64_encoded_size(input_size, padded != 0);
    if (required == SIZE_MAX) return RIN_ENCODING_OVERFLOW;
    if (required > output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
    if (required != 0u && output == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    digits = rin_encoding_base64_alphabet(alphabet);
    for (index = 0u; index < input_size; index += 3u) {
        const size_t remaining = input_size - index;
        const uint32_t block = ((uint32_t)input[index] << 16u) |
            (remaining > 1u ? (uint32_t)input[index + 1u] << 8u : 0u) |
            (remaining > 2u ? input[index + 2u] : 0u);
        output[written++] = (uint8_t)digits[(block >> 18u) & 63u];
        output[written++] = (uint8_t)digits[(block >> 12u) & 63u];
        if (remaining > 1u) output[written++] = (uint8_t)digits[(block >> 6u) & 63u];
        else if (padded) output[written++] = (uint8_t)'=';
        if (remaining > 2u) output[written++] = (uint8_t)digits[block & 63u];
        else if (padded) output[written++] = (uint8_t)'=';
    }
    *output_size = written;
    return RIN_ENCODING_OK;
}

static int rin_encoding_base64_digit(unsigned char value,
                                     RinEncodingBase64Alphabet alphabet)
{
    if (value >= (unsigned char)'A' && value <= (unsigned char)'Z')
        return (int)value - 'A';
    if (value >= (unsigned char)'a' && value <= (unsigned char)'z')
        return (int)value - 'a' + 26;
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9')
        return (int)value - '0' + 52;
    if (value == (unsigned char)(alphabet == RIN_ENCODING_BASE64_URL_SAFE ? '-' : '+'))
        return 62;
    if (value == (unsigned char)(alphabet == RIN_ENCODING_BASE64_URL_SAFE ? '_' : '/'))
        return 63;
    return -1;
}

static int rin_encoding_base64_space(unsigned char value)
{
    return value == (unsigned char)' ' || value == (unsigned char)'\t' ||
           value == (unsigned char)'\r' || value == (unsigned char)'\n';
}

int rin_encoding_base64_decode(const uint8_t* input, size_t input_size,
                               RinEncodingBase64Alphabet alphabet,
                               unsigned flags, uint8_t* output,
                               size_t output_capacity, size_t* output_size)
{
    int quartet[4];
    size_t quartet_size = 0u;
    size_t index;
    size_t written = 0u;
    int saw_padding = 0;
    int allow_unpadded;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    if (alphabet != RIN_ENCODING_BASE64_STANDARD &&
        alphabet != RIN_ENCODING_BASE64_URL_SAFE)
        return RIN_ENCODING_INVALID_ARGUMENT;
    if ((flags & RIN_ENCODING_BASE64_PADDING_REQUIRED) != 0u &&
        (flags & RIN_ENCODING_BASE64_ALLOW_UNPADDED) != 0u)
        return RIN_ENCODING_INVALID_ARGUMENT;
    allow_unpadded = (flags & RIN_ENCODING_BASE64_ALLOW_UNPADDED) != 0u;
    for (index = 0u; index < input_size; ++index) {
        const unsigned char value = input[index];
        int digit;
        if (rin_encoding_base64_space(value)) {
            if ((flags & RIN_ENCODING_BASE64_ALLOW_WHITESPACE) == 0u)
                return RIN_ENCODING_MALFORMED;
            continue;
        }
        if (saw_padding) return RIN_ENCODING_MALFORMED;
        if (value == (unsigned char)'=') {
            if (quartet_size < 2u) return RIN_ENCODING_MALFORMED;
            quartet[quartet_size++] = -2;
        } else {
            digit = rin_encoding_base64_digit(value, alphabet);
            if (digit < 0 || quartet_size >= 4u) return RIN_ENCODING_MALFORMED;
            quartet[quartet_size++] = digit;
        }
        if (quartet_size != 4u) continue;
        if (quartet[0] < 0 || quartet[1] < 0) return RIN_ENCODING_MALFORMED;
        if (written == output_capacity || output == NULL)
            return RIN_ENCODING_BUFFER_TOO_SMALL;
        output[written++] = (uint8_t)((quartet[0] << 2u) | (quartet[1] >> 4u));
        if (quartet[2] == -2) {
            if (quartet[3] != -2 || (quartet[1] & 15) != 0) return RIN_ENCODING_MALFORMED;
            saw_padding = 1;
        } else {
            if (quartet[2] < 0) return RIN_ENCODING_MALFORMED;
            if (written == output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
            output[written++] = (uint8_t)((quartet[1] << 4u) | (quartet[2] >> 2u));
            if (quartet[3] == -2) {
                if ((quartet[2] & 3) != 0) return RIN_ENCODING_MALFORMED;
                saw_padding = 1;
            } else {
                if (quartet[3] < 0) return RIN_ENCODING_MALFORMED;
                if (written == output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
                output[written++] = (uint8_t)((quartet[2] << 6u) | quartet[3]);
            }
        }
        quartet_size = 0u;
    }
    if (quartet_size != 0u) {
        if (!allow_unpadded || saw_padding || quartet_size == 1u)
            return RIN_ENCODING_MALFORMED;
        if (written == output_capacity || output == NULL)
            return RIN_ENCODING_BUFFER_TOO_SMALL;
        output[written++] = (uint8_t)((quartet[0] << 2u) | (quartet[1] >> 4u));
        if (quartet_size == 3u) {
            if (quartet[2] < 0)
                return RIN_ENCODING_MALFORMED;
            if (written == output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
            output[written++] = (uint8_t)((quartet[1] << 4u) | (quartet[2] >> 2u));
            if ((quartet[2] & 3) != 0) return RIN_ENCODING_MALFORMED;
        } else if ((quartet[1] & 15) != 0) {
            return RIN_ENCODING_MALFORMED;
        }
    }
    *output_size = written;
    return RIN_ENCODING_OK;
}

size_t rin_encoding_base64url_encoded_size(size_t input_size)
{
    return rin_encoding_base64_encoded_size(input_size, 0);
}

int rin_encoding_base64url_encode(const uint8_t* input, size_t input_size,
                                  uint8_t* output, size_t output_capacity,
                                  size_t* output_size)
{
    return rin_encoding_base64_encode(
        input, input_size, RIN_ENCODING_BASE64_URL_SAFE, 0, output,
        output_capacity, output_size);
}

int rin_encoding_base64url_decode(const uint8_t* input, size_t input_size,
                                  uint8_t* output, size_t output_capacity,
                                  size_t* output_size)
{
    return rin_encoding_base64_decode(
        input, input_size, RIN_ENCODING_BASE64_URL_SAFE,
        RIN_ENCODING_BASE64_ALLOW_UNPADDED, output, output_capacity,
        output_size);
}

static int rin_encoding_base64_alphabet_valid(
    RinEncodingBase64Alphabet alphabet)
{
    return alphabet == RIN_ENCODING_BASE64_STANDARD ||
           alphabet == RIN_ENCODING_BASE64_URL_SAFE;
}

static void rin_encoding_base64_emit_block(
    const uint8_t* block, size_t remaining,
    RinEncodingBase64Alphabet alphabet, int padded, uint8_t* output,
    size_t* written)
{
    const char* digits = rin_encoding_base64_alphabet(alphabet);
    const uint32_t value = ((uint32_t)block[0] << 16u) |
        (remaining > 1u ? (uint32_t)block[1] << 8u : 0u) |
        (remaining > 2u ? block[2] : 0u);
    output[(*written)++] = (uint8_t)digits[(value >> 18u) & 63u];
    output[(*written)++] = (uint8_t)digits[(value >> 12u) & 63u];
    if (remaining > 1u)
        output[(*written)++] = (uint8_t)digits[(value >> 6u) & 63u];
    else if (padded)
        output[(*written)++] = (uint8_t)'=';
    if (remaining > 2u)
        output[(*written)++] = (uint8_t)digits[value & 63u];
    else if (padded)
        output[(*written)++] = (uint8_t)'=';
}

int rin_encoding_base64_encoder_init(RinEncodingBase64Encoder* encoder,
                                     RinEncodingBase64Alphabet alphabet,
                                     int padded)
{
    if (encoder == NULL || !rin_encoding_base64_alphabet_valid(alphabet) ||
        (padded != 0 && padded != 1))
        return RIN_ENCODING_INVALID_ARGUMENT;
    encoder->alphabet = alphabet;
    encoder->padded = (uint8_t)padded;
    encoder->finalized = 0u;
    encoder->tail_size = 0u;
    encoder->tail[0] = 0u;
    encoder->tail[1] = 0u;
    return RIN_ENCODING_OK;
}

int rin_encoding_base64_encoder_update(RinEncodingBase64Encoder* encoder,
                                       const uint8_t* input, size_t input_size,
                                       uint8_t* output, size_t output_capacity,
                                       size_t* input_consumed,
                                       size_t* output_size)
{
    size_t input_index = 0u;
    size_t written = 0u;
    if (input_consumed != NULL) *input_consumed = 0u;
    if (input_consumed == NULL ||
        !rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (encoder == NULL || encoder->finalized != 0u ||
        !rin_encoding_base64_alphabet_valid(encoder->alphabet) ||
        encoder->tail_size > 2u ||
        (input_size != 0u && input == NULL))
        return RIN_ENCODING_INVALID_ARGUMENT;

    while (input_size - input_index >= 3u - encoder->tail_size) {
        uint8_t block[3];
        size_t needed = 3u - encoder->tail_size;
        size_t index;
        if (output_capacity - written < 4u) {
            *input_consumed = input_index;
            *output_size = written;
            return RIN_ENCODING_BUFFER_TOO_SMALL;
        }
        for (index = 0u; index < encoder->tail_size; ++index)
            block[index] = encoder->tail[index];
        for (index = 0u; index < needed; ++index)
            block[encoder->tail_size + index] = input[input_index + index];
        rin_encoding_base64_emit_block(block, 3u, encoder->alphabet, 0,
                                       output, &written);
        encoder->tail_size = 0u;
        encoder->tail[0] = 0u;
        encoder->tail[1] = 0u;
        input_index += needed;
    }
    while (input_index < input_size) {
        encoder->tail[encoder->tail_size++] = input[input_index++];
    }
    *input_consumed = input_index;
    *output_size = written;
    return RIN_ENCODING_OK;
}

int rin_encoding_base64_encoder_final(RinEncodingBase64Encoder* encoder,
                                      uint8_t* output, size_t output_capacity,
                                      size_t* output_size)
{
    size_t required;
    size_t written = 0u;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (encoder == NULL || encoder->finalized != 0u ||
        !rin_encoding_base64_alphabet_valid(encoder->alphabet) ||
        encoder->tail_size > 2u || encoder->padded > 1u)
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (encoder->tail_size == 0u) {
        encoder->finalized = 1u;
        return RIN_ENCODING_OK;
    }
    required = encoder->padded != 0u ? 4u :
        (encoder->tail_size == 1u ? 2u : 3u);
    if (required > output_capacity)
        return RIN_ENCODING_BUFFER_TOO_SMALL;
    rin_encoding_base64_emit_block(encoder->tail, encoder->tail_size,
                                   encoder->alphabet, encoder->padded != 0u,
                                   output, &written);
    encoder->tail_size = 0u;
    encoder->tail[0] = 0u;
    encoder->tail[1] = 0u;
    encoder->finalized = 1u;
    *output_size = written;
    return RIN_ENCODING_OK;
}

static int rin_encoding_base64_decoder_emit_quartet(
    RinEncodingBase64Decoder* decoder, uint8_t* output, size_t output_capacity,
    size_t* written)
{
    size_t required;
    int has_padding;
    if (decoder->quartet_size != 4u || decoder->quartet[0] < 0 ||
        decoder->quartet[1] < 0)
        return RIN_ENCODING_MALFORMED;
    if (decoder->quartet[2] == -2) {
        if (decoder->quartet[3] != -2 ||
            (decoder->quartet[1] & 15) != 0)
            return RIN_ENCODING_MALFORMED;
        required = 1u;
        has_padding = 1;
    } else if (decoder->quartet[2] < 0) {
        return RIN_ENCODING_MALFORMED;
    } else if (decoder->quartet[3] == -2) {
        if ((decoder->quartet[2] & 3) != 0)
            return RIN_ENCODING_MALFORMED;
        required = 2u;
        has_padding = 1;
    } else {
        if (decoder->quartet[3] < 0)
            return RIN_ENCODING_MALFORMED;
        required = 3u;
        has_padding = 0;
    }
    if (required > output_capacity - *written)
        return RIN_ENCODING_BUFFER_TOO_SMALL;
    output[(*written)++] = (uint8_t)((decoder->quartet[0] << 2u) |
                                     (decoder->quartet[1] >> 4u));
    if (required > 1u)
        output[(*written)++] = (uint8_t)((decoder->quartet[1] << 4u) |
                                         (decoder->quartet[2] >> 2u));
    if (required > 2u)
        output[(*written)++] = (uint8_t)((decoder->quartet[2] << 6u) |
                                         decoder->quartet[3]);
    decoder->quartet_size = 0u;
    if (has_padding != 0) decoder->saw_padding = 1u;
    return RIN_ENCODING_OK;
}

int rin_encoding_base64_decoder_init(RinEncodingBase64Decoder* decoder,
                                     RinEncodingBase64Alphabet alphabet,
                                     unsigned flags)
{
    size_t index;
    if (decoder == NULL || !rin_encoding_base64_alphabet_valid(alphabet) ||
        ((flags & RIN_ENCODING_BASE64_PADDING_REQUIRED) != 0u &&
         (flags & RIN_ENCODING_BASE64_ALLOW_UNPADDED) != 0u))
        return RIN_ENCODING_INVALID_ARGUMENT;
    decoder->alphabet = alphabet;
    decoder->flags = flags;
    decoder->quartet_size = 0u;
    decoder->saw_padding = 0u;
    decoder->finalized = 0u;
    for (index = 0u; index < 4u; ++index) decoder->quartet[index] = 0;
    return RIN_ENCODING_OK;
}

int rin_encoding_base64_decoder_update(RinEncodingBase64Decoder* decoder,
                                       const uint8_t* input, size_t input_size,
                                       uint8_t* output, size_t output_capacity,
                                       size_t* input_consumed,
                                       size_t* output_size)
{
    size_t input_index = 0u;
    size_t written = 0u;
    if (input_consumed != NULL) *input_consumed = 0u;
    if (input_consumed == NULL ||
        !rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (decoder == NULL || decoder->finalized != 0u ||
        !rin_encoding_base64_alphabet_valid(decoder->alphabet) ||
        decoder->quartet_size > 4u ||
        (input_size != 0u && input == NULL))
        return RIN_ENCODING_INVALID_ARGUMENT;
    while (input_index < input_size || decoder->quartet_size == 4u) {
        if (decoder->quartet_size == 4u) {
            const int status = rin_encoding_base64_decoder_emit_quartet(
                decoder, output, output_capacity, &written);
            if (status != RIN_ENCODING_OK) {
                *input_consumed = input_index;
                *output_size = written;
                return status;
            }
            continue;
        }
        if (input_index == input_size) break;
        {
            const unsigned char value = input[input_index];
            int digit;
            if (rin_encoding_base64_space(value)) {
                if ((decoder->flags & RIN_ENCODING_BASE64_ALLOW_WHITESPACE) == 0u) {
                    *input_consumed = input_index;
                    *output_size = written;
                    return RIN_ENCODING_MALFORMED;
                }
                ++input_index;
                continue;
            }
            if (decoder->saw_padding != 0u) {
                *input_consumed = input_index;
                *output_size = written;
                return RIN_ENCODING_MALFORMED;
            }
            if (value == (unsigned char)'=') {
                if (decoder->quartet_size < 2u) {
                    *input_consumed = input_index;
                    *output_size = written;
                    return RIN_ENCODING_MALFORMED;
                }
                decoder->quartet[decoder->quartet_size++] = -2;
            } else {
                digit = rin_encoding_base64_digit(value, decoder->alphabet);
                if (digit < 0 || decoder->quartet_size >= 4u) {
                    *input_consumed = input_index;
                    *output_size = written;
                    return RIN_ENCODING_MALFORMED;
                }
                decoder->quartet[decoder->quartet_size++] = digit;
            }
            ++input_index;
        }
    }
    *input_consumed = input_index;
    *output_size = written;
    return RIN_ENCODING_OK;
}

int rin_encoding_base64_decoder_final(RinEncodingBase64Decoder* decoder,
                                      uint8_t* output, size_t output_capacity,
                                      size_t* output_size)
{
    size_t written = 0u;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (decoder == NULL || decoder->finalized != 0u ||
        !rin_encoding_base64_alphabet_valid(decoder->alphabet) ||
        decoder->quartet_size > 4u)
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (decoder->quartet_size == 4u) {
        const int status = rin_encoding_base64_decoder_emit_quartet(
            decoder, output, output_capacity, &written);
        if (status != RIN_ENCODING_OK) {
            *output_size = written;
            return status;
        }
    }
    if (decoder->quartet_size != 0u) {
        size_t required;
        if ((decoder->flags & RIN_ENCODING_BASE64_ALLOW_UNPADDED) == 0u ||
            decoder->saw_padding != 0u || decoder->quartet_size == 1u ||
            decoder->quartet[0] < 0 || decoder->quartet[1] < 0)
            return RIN_ENCODING_MALFORMED;
        if (decoder->quartet_size == 2u) {
            if ((decoder->quartet[1] & 15) != 0) return RIN_ENCODING_MALFORMED;
            required = 1u;
        } else {
            if (decoder->quartet[2] < 0 ||
                (decoder->quartet[2] & 3) != 0)
                return RIN_ENCODING_MALFORMED;
            required = 2u;
        }
        if (required > output_capacity - written)
            return RIN_ENCODING_BUFFER_TOO_SMALL;
        output[written++] = (uint8_t)((decoder->quartet[0] << 2u) |
                                      (decoder->quartet[1] >> 4u));
        if (required == 2u)
            output[written++] = (uint8_t)((decoder->quartet[1] << 4u) |
                                          (decoder->quartet[2] >> 2u));
        decoder->quartet_size = 0u;
    }
    decoder->finalized = 1u;
    *output_size = written;
    return RIN_ENCODING_OK;
}

size_t rin_encoding_hex_encoded_size(size_t input_size)
{
    return input_size > SIZE_MAX / 2u ? SIZE_MAX : input_size * 2u;
}

int rin_encoding_hex_encode(const uint8_t* input, size_t input_size,
                            int uppercase, uint8_t* output,
                            size_t output_capacity, size_t* output_size)
{
    static const char lower[] = "0123456789abcdef";
    static const char upper[] = "0123456789ABCDEF";
    const char* digits = uppercase ? upper : lower;
    size_t index;
    size_t required = rin_encoding_hex_encoded_size(input_size);
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    if (required == SIZE_MAX) return RIN_ENCODING_OVERFLOW;
    if (required > output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
    if (required != 0u && output == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    for (index = 0u; index < input_size; ++index) {
        output[index * 2u] = (uint8_t)digits[input[index] >> 4u];
        output[index * 2u + 1u] = (uint8_t)digits[input[index] & 15u];
    }
    *output_size = required;
    return RIN_ENCODING_OK;
}

static int rin_encoding_hex_digit(unsigned char value)
{
    if (value >= (unsigned char)'0' && value <= (unsigned char)'9') return value - '0';
    if (value >= (unsigned char)'a' && value <= (unsigned char)'f') return value - 'a' + 10;
    if (value >= (unsigned char)'A' && value <= (unsigned char)'F') return value - 'A' + 10;
    return -1;
}

int rin_encoding_hex_decode(const uint8_t* input, size_t input_size,
                            uint8_t* output, size_t output_capacity,
                            size_t* output_size)
{
    size_t index;
    size_t required;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    if ((input_size & 1u) != 0u) return RIN_ENCODING_MALFORMED;
    required = input_size / 2u;
    if (required > output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
    if (required != 0u && output == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    for (index = 0u; index < required; ++index) {
        const int high = rin_encoding_hex_digit(input[index * 2u]);
        const int low = rin_encoding_hex_digit(input[index * 2u + 1u]);
        if (high < 0 || low < 0) return RIN_ENCODING_MALFORMED;
        output[index] = (uint8_t)((high << 4) | low);
    }
    *output_size = required;
    return RIN_ENCODING_OK;
}

int rin_encoding_quoted_printable_decode(const uint8_t* input,
                                         size_t input_size, uint8_t* output,
                                         size_t output_capacity,
                                         size_t* output_size)
{
    size_t index;
    size_t written = 0u;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    for (index = 0u; index < input_size; ++index) {
        const uint8_t value = input[index];
        if (value != (uint8_t)'=') {
            if (written >= output_capacity || output == NULL)
                return RIN_ENCODING_BUFFER_TOO_SMALL;
            output[written++] = value;
            continue;
        }
        if (index + 1u >= input_size) return RIN_ENCODING_MALFORMED;
        if (input[index + 1u] == (uint8_t)'\n') {
            ++index;
            continue;
        }
        if (input[index + 1u] == (uint8_t)'\r') {
            if (index + 2u >= input_size ||
                input[index + 2u] != (uint8_t)'\n')
                return RIN_ENCODING_MALFORMED;
            index += 2u;
            continue;
        }
        if (index + 2u >= input_size) return RIN_ENCODING_MALFORMED;
        {
            const int high = rin_encoding_hex_digit(input[index + 1u]);
            const int low = rin_encoding_hex_digit(input[index + 2u]);
            if (high < 0 || low < 0) return RIN_ENCODING_MALFORMED;
            if (written >= output_capacity || output == NULL)
                return RIN_ENCODING_BUFFER_TOO_SMALL;
            output[written++] = (uint8_t)((high << 4) | low);
        }
        index += 2u;
    }
    *output_size = written;
    return RIN_ENCODING_OK;
}

int rin_encoding_rfc2047_decode_payload(char encoding, const uint8_t* input,
                                         size_t input_size, uint8_t* output,
                                         size_t output_capacity,
                                         size_t* output_size)
{
    size_t index;
    size_t written = 0u;
    if (encoding == 'B' || encoding == 'b') {
        return rin_encoding_base64_decode(
            input, input_size, RIN_ENCODING_BASE64_STANDARD,
            RIN_ENCODING_BASE64_PADDING_REQUIRED, output, output_capacity,
            output_size);
    }
    if (encoding != 'Q' && encoding != 'q') {
        if (output_size != NULL) *output_size = 0u;
        if (output != NULL && output_capacity != 0u)
            rin_secure_zero(output, output_capacity);
        return RIN_ENCODING_INVALID_ARGUMENT;
    }
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    for (index = 0u; index < input_size; ++index) {
        const uint8_t value = input[index];
        if (value == (uint8_t)'=') {
            int high;
            int low;
            if (index + 2u >= input_size) return RIN_ENCODING_MALFORMED;
            high = rin_encoding_hex_digit(input[index + 1u]);
            low = rin_encoding_hex_digit(input[index + 2u]);
            if (high < 0 || low < 0) return RIN_ENCODING_MALFORMED;
            if (written >= output_capacity || output == NULL)
                return RIN_ENCODING_BUFFER_TOO_SMALL;
            output[written++] = (uint8_t)((high << 4) | low);
            index += 2u;
            continue;
        }
        if (value == (uint8_t)'_') {
            if (written >= output_capacity || output == NULL)
                return RIN_ENCODING_BUFFER_TOO_SMALL;
            output[written++] = (uint8_t)' ';
            continue;
        }
        if (value < 0x21u || value > 0x7eu || value == (uint8_t)'?')
            return RIN_ENCODING_MALFORMED;
        if (written >= output_capacity || output == NULL)
            return RIN_ENCODING_BUFFER_TOO_SMALL;
        output[written++] = value;
    }
    *output_size = written;
    return RIN_ENCODING_OK;
}

static int rin_encoding_percent_unreserved(uint8_t value)
{
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') || value == '-' || value == '.' ||
           value == '_' || value == '~';
}

size_t rin_encoding_percent_encoded_size(const uint8_t* input, size_t input_size)
{
    size_t index;
    size_t required = 0u;
    if (input_size != 0u && input == NULL) return SIZE_MAX;
    for (index = 0u; index < input_size; ++index) {
        const size_t add = rin_encoding_percent_unreserved(input[index]) ? 1u : 3u;
        if (required > SIZE_MAX - add) return SIZE_MAX;
        required += add;
    }
    return required;
}

int rin_encoding_percent_encode(const uint8_t* input, size_t input_size,
                                uint8_t* output, size_t output_capacity,
                                size_t* output_size)
{
    static const char digits[] = "0123456789ABCDEF";
    size_t index;
    size_t written = 0u;
    const size_t required = rin_encoding_percent_encoded_size(input, input_size);
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    if (required == SIZE_MAX) return RIN_ENCODING_OVERFLOW;
    if (required > output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
    if (required != 0u && output == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    for (index = 0u; index < input_size; ++index) {
        const uint8_t value = input[index];
        if (rin_encoding_percent_unreserved(value)) output[written++] = value;
        else {
            output[written++] = '%';
            output[written++] = (uint8_t)digits[value >> 4u];
            output[written++] = (uint8_t)digits[value & 15u];
        }
    }
    *output_size = written;
    return RIN_ENCODING_OK;
}

int rin_encoding_percent_decode(const uint8_t* input, size_t input_size,
                                uint8_t* output, size_t output_capacity,
                                size_t* output_size)
{
    size_t index;
    size_t written = 0u;
    if (!rin_encoding_output_valid(output, output_capacity, output_size))
        return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size != 0u && input == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    if (input_size > output_capacity) return RIN_ENCODING_BUFFER_TOO_SMALL;
    if (input_size != 0u && output == NULL) return RIN_ENCODING_INVALID_ARGUMENT;
    for (index = 0u; index < input_size; ++index) {
        if (input[index] != '%') {
            output[written++] = input[index];
            continue;
        }
        if (index + 2u >= input_size) return RIN_ENCODING_MALFORMED;
        {
            const int high = rin_encoding_hex_digit(input[index + 1u]);
            const int low = rin_encoding_hex_digit(input[index + 2u]);
            if (high < 0 || low < 0) return RIN_ENCODING_MALFORMED;
            output[written++] = (uint8_t)((high << 4) | low);
        }
        index += 2u;
    }
    *output_size = written;
    return RIN_ENCODING_OK;
}
