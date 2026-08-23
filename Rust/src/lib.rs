use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use opaque_ke::argon2::Argon2;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse, Ristretto255,
    TripleDh,
};
use rand::rngs::OsRng;
use sha2::Sha512;

const OK: i32 = 0;
const ERR_INVALID_ARGUMENT: i32 = 1;
const ERR_PROTOCOL: i32 = 2;
const ERR_INTERNAL: i32 = 3;

struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OpaqueBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl OpaqueBuffer {
    const fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

fn run_ffi<F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), i32>,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => OK,
        Ok(Err(code)) => code,
        Err(_) => ERR_INTERNAL,
    }
}

unsafe fn input_bytes<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ERR_INVALID_ARGUMENT);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

unsafe fn reset_output(out: *mut OpaqueBuffer) -> Result<(), i32> {
    if out.is_null() {
        return Err(ERR_INVALID_ARGUMENT);
    }
    *out = OpaqueBuffer::empty();
    Ok(())
}

unsafe fn write_output(out: *mut OpaqueBuffer, data: Vec<u8>) -> Result<(), i32> {
    if out.is_null() {
        return Err(ERR_INVALID_ARGUMENT);
    }

    if data.is_empty() {
        *out = OpaqueBuffer::empty();
        return Ok(());
    }

    let mut boxed = data.into_boxed_slice();
    let len = boxed.len();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    *out = OpaqueBuffer { ptr, len };
    Ok(())
}

fn protocol_error<T, E>(result: Result<T, E>) -> Result<T, i32> {
    result.map_err(|_| ERR_PROTOCOL)
}

#[no_mangle]
pub extern "C" fn opaque_swift_ffi_version() -> u32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn opaque_buffer_free(buffer: OpaqueBuffer) {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return;
    }

    let slice_ptr = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
    drop(Box::from_raw(slice_ptr));
}

#[no_mangle]
pub unsafe extern "C" fn opaque_client_registration_start(
    password: *const u8,
    password_len: usize,
    request_out: *mut OpaqueBuffer,
    state_out: *mut OpaqueBuffer,
) -> i32 {
    run_ffi(|| {
        if request_out == state_out {
            return Err(ERR_INVALID_ARGUMENT);
        }

        reset_output(request_out)?;
        reset_output(state_out)?;
        let password = input_bytes(password, password_len)?;

        let mut rng = OsRng;
        let result = protocol_error(ClientRegistration::<Suite>::start(&mut rng, password))?;
        let request = result.message.serialize().to_vec();
        let state = result.state.serialize().to_vec();

        write_output(request_out, request)?;
        write_output(state_out, state)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn opaque_client_registration_finish(
    password: *const u8,
    password_len: usize,
    state: *const u8,
    state_len: usize,
    response: *const u8,
    response_len: usize,
    upload_out: *mut OpaqueBuffer,
    export_key_out: *mut OpaqueBuffer,
    server_public_key_out: *mut OpaqueBuffer,
) -> i32 {
    run_ffi(|| {
        if upload_out == export_key_out
            || upload_out == server_public_key_out
            || export_key_out == server_public_key_out
        {
            return Err(ERR_INVALID_ARGUMENT);
        }

        reset_output(upload_out)?;
        reset_output(export_key_out)?;
        reset_output(server_public_key_out)?;

        let password = input_bytes(password, password_len)?;
        let state = input_bytes(state, state_len)?;
        let response = input_bytes(response, response_len)?;

        let state = protocol_error(ClientRegistration::<Suite>::deserialize(state))?;
        let response = protocol_error(RegistrationResponse::<Suite>::deserialize(response))?;
        let mut rng = OsRng;
        let result = protocol_error(state.finish(
            &mut rng,
            password,
            response,
            ClientRegistrationFinishParameters::default(),
        ))?;

        let upload = result.message.serialize().to_vec();
        let export_key = result.export_key.to_vec();
        let server_public_key = result.server_s_pk.serialize().to_vec();

        write_output(upload_out, upload)?;
        write_output(export_key_out, export_key)?;
        write_output(server_public_key_out, server_public_key)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn opaque_client_login_start(
    password: *const u8,
    password_len: usize,
    request_out: *mut OpaqueBuffer,
    state_out: *mut OpaqueBuffer,
) -> i32 {
    run_ffi(|| {
        if request_out == state_out {
            return Err(ERR_INVALID_ARGUMENT);
        }

        reset_output(request_out)?;
        reset_output(state_out)?;
        let password = input_bytes(password, password_len)?;

        let mut rng = OsRng;
        let result = protocol_error(ClientLogin::<Suite>::start(&mut rng, password))?;
        let request = result.message.serialize().to_vec();
        let state = result.state.serialize().to_vec();

        write_output(request_out, request)?;
        write_output(state_out, state)?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn opaque_client_login_finish(
    password: *const u8,
    password_len: usize,
    state: *const u8,
    state_len: usize,
    response: *const u8,
    response_len: usize,
    finalization_out: *mut OpaqueBuffer,
    session_key_out: *mut OpaqueBuffer,
    export_key_out: *mut OpaqueBuffer,
    server_public_key_out: *mut OpaqueBuffer,
) -> i32 {
    run_ffi(|| {
        let outputs = [
            finalization_out as usize,
            session_key_out as usize,
            export_key_out as usize,
            server_public_key_out as usize,
        ];
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                if outputs[i] == outputs[j] {
                    return Err(ERR_INVALID_ARGUMENT);
                }
            }
        }

        reset_output(finalization_out)?;
        reset_output(session_key_out)?;
        reset_output(export_key_out)?;
        reset_output(server_public_key_out)?;

        let password = input_bytes(password, password_len)?;
        let state = input_bytes(state, state_len)?;
        let response = input_bytes(response, response_len)?;

        let state = protocol_error(ClientLogin::<Suite>::deserialize(state))?;
        let response = protocol_error(CredentialResponse::<Suite>::deserialize(response))?;
        let mut rng = OsRng;
        let result = protocol_error(state.finish(
            &mut rng,
            password,
            response,
            ClientLoginFinishParameters::default(),
        ))?;

        let finalization = result.message.serialize().to_vec();
        let session_key = result.session_key.to_vec();
        let export_key = result.export_key.to_vec();
        let server_public_key = result.server_s_pk.serialize().to_vec();

        write_output(finalization_out, finalization)?;
        write_output(session_key_out, session_key)?;
        write_output(export_key_out, export_key)?;
        write_output(server_public_key_out, server_public_key)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_start_round_trips_state() {
        let mut rng = OsRng;
        let start = ClientRegistration::<Suite>::start(&mut rng, b"test password").unwrap();
        let serialized = start.state.serialize();
        ClientRegistration::<Suite>::deserialize(&serialized).unwrap();
        assert!(!start.message.serialize().is_empty());
    }

    #[test]
    fn login_start_round_trips_state() {
        let mut rng = OsRng;
        let start = ClientLogin::<Suite>::start(&mut rng, b"test password").unwrap();
        let serialized = start.state.serialize();
        ClientLogin::<Suite>::deserialize(&serialized).unwrap();
        assert!(!start.message.serialize().is_empty());
    }
}
