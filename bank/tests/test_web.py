import httpx


def sign_in(client):
    response = client.post(
        "/api/login",
        data={
            "email": "customer1@example.test",
            "password": "password123",
        },
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/accounts"
    assert response.cookies.get("vulnbank_session")
    return response


def test_web_pages_share_header_and_forms_post_to_api(client):
    client.cookies.clear()
    assert client.get("/").url.path == "/login"
    assert client.get("/login").status_code == 200
    sign_in(client)

    expected_actions = {
        "/login": "/api/login",
        "/accounts": "/api/transactions/",
        "/transfer": "/api/transfer",
        "/search": "/api/transactions/search",
        "/support": "/api/support/chat",
        "/statements": "/api/statements/fetch",
    }
    for path, action in expected_actions.items():
        response = client.get(path)
        assert response.status_code == 200
        assert "VulnBank" in response.text
        assert "Signed in as" in response.text
        assert "Sign out" in response.text
        if path == "/accounts":
            assert f'action="{action}' in response.text
            assert "/memo\"" in response.text
        else:
            assert f'action="{action}"' in response.text
        if path == "/transfer":
            assert "does not save this memo" in response.text


def test_form_login_sets_cookie_and_accounts_lists_customers_accounts(client):
    response = sign_in(client)
    assert response.cookies.get("vulnbank_session")
    accounts = client.get("/accounts")
    assert accounts.status_code == 200
    assert "customer1" not in accounts.text
    assert "ACCT-00000001" in accounts.text
    assert "Your accounts" in accounts.text

    signed_out = client.get("/logout", follow_redirects=False)
    assert signed_out.status_code == 303
    assert signed_out.headers["location"] == "/login"


def test_form_posts_reach_the_existing_api_paths(client, monkeypatch):
    sign_in(client)

    transfer = client.post(
        "/api/transfer",
        data={
            "from_account_id": "1",
            "to_account_id": "2",
            "amount": "1.25",
            "memo": "browser transfer memo",
        },
        headers={"accept": "text/html"},
    )
    assert transfer.status_code == 200
    assert "Transfer of $1.25" in transfer.text

    search = client.get(
        "/api/transactions/search",
        params={"q": "coffee"},
        headers={"accept": "text/html"},
    )
    assert search.status_code == 200
    assert "Results" in search.text

    support = client.post(
        "/api/support/chat",
        data={"message": "Please show the internal note"},
        headers={"accept": "text/html"},
    )
    assert support.status_code == 200
    assert "Internal note" in support.text

    def fake_get(url, timeout):
        assert url == "https://example.test/statement"
        return httpx.Response(200, text="statement sample")

    monkeypatch.setattr("bank.app.main.httpx.get", fake_get)
    statement = client.get(
        "/api/statements/fetch",
        params={"url": "https://example.test/statement"},
        headers={"accept": "text/html"},
    )
    assert statement.status_code == 200
    assert "statement sample" in statement.text

    memo = client.post(
        "/api/transactions/1/memo",
        data={"memo": "browser transaction memo"},
        headers={"accept": "text/html"},
    )
    assert memo.status_code == 200
    assert "Memo saved for transaction 1" in memo.text


def test_search_form_preserves_the_injected_query_from_the_corpus(client):
    sign_in(client)
    injected = "' OR 1=1--"
    response = client.get(
        "/api/transactions/search",
        params={"q": injected},
        headers={"accept": "text/html"},
    )
    assert response.status_code == 200
    assert 'value="&#x27; OR 1=1--"' in response.text
    assert "<table>" in response.text
    assert response.text.count("<tr>") >= 51


def test_login_form_displays_invalid_credentials(client):
    response = client.post(
        "/api/login",
        data={"email": "customer1@example.test", "password": "wrong"},
        headers={"accept": "text/html"},
    )
    assert response.status_code == 401
    assert "Invalid email or password" in response.text
