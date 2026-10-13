use jend_auth::{
    client_login_finish, client_login_start, client_registration_finish,
    client_registration_start, AuthServer, SensitivePassword, Username,
};

fn registered_password_file(
    server: &AuthServer,
    username: &Username,
    password: &SensitivePassword,
) -> Vec<u8> {
    let (client_state, request) = client_registration_start(password).unwrap();
    let started = server.registration_start(username, &request, 1_000).unwrap();
    let client_finish = client_registration_finish(
        client_state,
        password,
        &started.response,
    )
    .unwrap();
    server
        .registration_finish(
            username,
            &started.ticket,
            &client_finish.upload,
            1_001,
        )
        .unwrap()
}

#[test]
fn opaque_registration_then_login_roundtrip() {
    let server = AuthServer::generate().unwrap();
    let username = Username::parse("alice_01").unwrap();
    let password = SensitivePassword::from_utf8("correct horse battery staple").unwrap();
    let password_file = registered_password_file(&server, &username, &password);

    let (client_state, request) = client_login_start(&password).unwrap();
    let started = server
        .login_start(&username, Some(&password_file), &request, 2_000)
        .unwrap();
    let client_finish = client_login_finish(client_state, &password, &started.response).unwrap();
    let server_finish = server
        .login_finish(&started.ticket, &client_finish.finalization, 2_001)
        .unwrap();

    assert_eq!(server_finish.username, username);
    assert_eq!(server_finish.session_key.as_slice(), client_finish.session_key.as_slice());
}

#[test]
fn opaque_wrong_password_fails_client_finish() {
    let server = AuthServer::generate().unwrap();
    let username = Username::parse("alice_02").unwrap();
    let correct = SensitivePassword::from_utf8("correct horse battery staple").unwrap();
    let wrong = SensitivePassword::from_utf8("this is definitely the wrong password").unwrap();
    let password_file = registered_password_file(&server, &username, &correct);

    let (client_state, request) = client_login_start(&wrong).unwrap();
    let started = server
        .login_start(&username, Some(&password_file), &request, 2_000)
        .unwrap();

    assert!(client_login_finish(client_state, &wrong, &started.response).is_err());
}

#[test]
fn opaque_unknown_user_uses_fake_record_path_and_still_fails() {
    let server = AuthServer::generate().unwrap();
    let username = Username::parse("nobody_01").unwrap();
    let password = SensitivePassword::from_utf8("correct horse battery staple").unwrap();

    let (client_state, request) = client_login_start(&password).unwrap();
    let started = server.login_start(&username, None, &request, 2_000).unwrap();

    assert!(client_login_finish(client_state, &password, &started.response).is_err());
}
