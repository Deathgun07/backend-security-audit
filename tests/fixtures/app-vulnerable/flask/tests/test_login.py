def test_login(client):
    password = "local-test-password-1"
    assert client.post("/login", data={"password": password}).status_code == 200
