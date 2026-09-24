# RinEncoding

Bounded Base64/Base64URL, PEM, hex, quoted-printable, RFC 2047 payload, and percent encoding helpers.

## Public API contract

| Requirement | Contract |
| --- | --- |
| Purpose | Bounded Base64/Base64URL, PEM, hex, quoted-printable, RFC 2047 payload, and percent encoding helpers. |
| Supported API | include/rinencoding/encoding.h; counted one-shot and caller-state streaming APIs. |
| Unsupported API | No general character-set conversion or MIME/URI policy beyond explicitly named codecs. |
| ownership | Inputs, outputs, and streaming state are caller-owned; output size is cleared on failure. |
| thread-safety | One-shot calls are independent; streaming state is mutable and must be serialized. |
| limits | Counted inputs, checked size calculations, and caller-provided output capacity; overflow is rejected. |
| errors | RinEncodingStatus distinguishes malformed, invalid, short-buffer, and overflow. |
| ABI stability | C source interface; public streaming structs require coordinated rebuild on layout changes. |
| security | Malformed data is rejected and failed output is cleared; decoding is not authorization or canonicalization. |
| build | No standalone build file; compile encoding.c through a consumer build with RinSecure. |
| test | No standalone test target; parent consumer contracts cover integration. No tests/builds run for this README update. |
