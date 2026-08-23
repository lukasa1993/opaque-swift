use opaque_ke::argon2::Argon2;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, RegistrationRequest, RegistrationResponse, RegistrationUpload, Ristretto255,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup, TripleDh,
};
use rand::rngs::OsRng;
use sha2::Sha512;

struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

#[test]
fn registration_and_login_round_trip_over_serialized_messages() {
    let password = b"correct horse battery staple";
    let credential_identifier = b"alice";

    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<Suite>::new(&mut server_rng);

    // Registration: client -> server.
    let mut client_rng = OsRng;
    let client_registration =
        ClientRegistration::<Suite>::start(&mut client_rng, password).unwrap();
    let client_registration_state = client_registration.state.serialize();
    let registration_request = RegistrationRequest::<Suite>::deserialize(
        &client_registration.message.serialize(),
    )
    .unwrap();

    // Registration: server -> client.
    let server_registration = ServerRegistration::<Suite>::start(
        &server_setup,
        registration_request,
        credential_identifier,
    )
    .unwrap();
    let registration_response = RegistrationResponse::<Suite>::deserialize(
        &server_registration.message.serialize(),
    )
    .unwrap();

    // Registration: client -> server.
    let client_registration_state =
        ClientRegistration::<Suite>::deserialize(&client_registration_state).unwrap();
    let client_registration_finish = client_registration_state
        .finish(
            &mut client_rng,
            password,
            registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap();

    let pinned_server_public_key = client_registration_finish.server_s_pk.serialize();
    let registration_upload = RegistrationUpload::<Suite>::deserialize(
        &client_registration_finish.message.serialize(),
    )
    .unwrap();
    let password_file = ServerRegistration::<Suite>::finish(registration_upload);

    // Login: client -> server.
    let mut client_rng = OsRng;
    let client_login = ClientLogin::<Suite>::start(&mut client_rng, password).unwrap();
    let client_login_state = client_login.state.serialize();
    let credential_request =
        CredentialRequest::<Suite>::deserialize(&client_login.message.serialize()).unwrap();

    // Login: server -> client.
    let mut server_rng = OsRng;
    let server_login = ServerLogin::start(
        &mut server_rng,
        &server_setup,
        Some(password_file),
        credential_request,
        credential_identifier,
        ServerLoginParameters::default(),
    )
    .unwrap();
    let credential_response =
        CredentialResponse::<Suite>::deserialize(&server_login.message.serialize()).unwrap();

    // Login: client -> server.
    let client_login_state = ClientLogin::<Suite>::deserialize(&client_login_state).unwrap();
    let client_login_finish = client_login_state
        .finish(
            &mut client_rng,
            password,
            credential_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap();

    assert_eq!(
        pinned_server_public_key.as_slice(),
        client_login_finish.server_s_pk.serialize().as_slice()
    );

    let credential_finalization = CredentialFinalization::<Suite>::deserialize(
        &client_login_finish.message.serialize(),
    )
    .unwrap();
    let server_login_finish = server_login
        .state
        .finish(credential_finalization, ServerLoginParameters::default())
        .unwrap();

    assert_eq!(
        client_login_finish.session_key.as_slice(),
        server_login_finish.session_key.as_slice()
    );
}
