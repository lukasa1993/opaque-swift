#ifndef OPAQUE_SWIFT_H
#define OPAQUE_SWIFT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct opaque_buffer_t {
    uint8_t *ptr;
    size_t len;
} opaque_buffer_t;

enum {
    OPAQUE_SWIFT_OK = 0,
    OPAQUE_SWIFT_ERR_INVALID_ARGUMENT = 1,
    OPAQUE_SWIFT_ERR_PROTOCOL = 2,
    OPAQUE_SWIFT_ERR_INTERNAL = 3,
};

uint32_t opaque_swift_ffi_version(void);
void opaque_buffer_free(opaque_buffer_t buffer);

int32_t opaque_client_registration_start(
    const uint8_t *password,
    size_t password_len,
    opaque_buffer_t *request_out,
    opaque_buffer_t *state_out
);

int32_t opaque_client_registration_finish(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *state,
    size_t state_len,
    const uint8_t *response,
    size_t response_len,
    opaque_buffer_t *upload_out,
    opaque_buffer_t *export_key_out,
    opaque_buffer_t *server_public_key_out
);

int32_t opaque_client_login_start(
    const uint8_t *password,
    size_t password_len,
    opaque_buffer_t *request_out,
    opaque_buffer_t *state_out
);

int32_t opaque_client_login_finish(
    const uint8_t *password,
    size_t password_len,
    const uint8_t *state,
    size_t state_len,
    const uint8_t *response,
    size_t response_len,
    opaque_buffer_t *finalization_out,
    opaque_buffer_t *session_key_out,
    opaque_buffer_t *export_key_out,
    opaque_buffer_t *server_public_key_out
);

#ifdef __cplusplus
}
#endif

#endif
