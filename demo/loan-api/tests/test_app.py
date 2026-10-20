import sqlite3

import pytest

import app as service


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "loans.db"
    con = sqlite3.connect(db)
    con.execute("create table accounts (id text primary key, balance real)")
    con.execute("insert into accounts values ('A100', 18250.75)")
    con.commit()
    con.close()
    monkeypatch.setattr(service, "DB_PATH", str(db))
    service.app.testing = True
    return service.app.test_client()


def test_monthly_payment_matches_the_standard_formula():
    assert service.monthly_payment(30000, 6.9, 60) == 592.62
    assert service.monthly_payment(12000, 0, 48) == 250.0
    with pytest.raises(ValueError):
        service.monthly_payment(1000, 5, 0)


def test_schedule_pays_off_the_loan(client):
    rows = client.post("/schedule", json={"principal": 30000, "apr": 6.9, "months": 60}).get_json()
    assert len(rows) == 60
    assert abs(rows[-1]["balance"]) < 1.0
    assert abs(sum(r["principal"] for r in rows) - 30000) < 1.0


def test_quote_endpoint(client):
    assert client.post("/quote", json={"principal": 30000, "apr": 6.9, "months": 60}).get_json() == {
        "monthly_payment": 592.62}


def test_token_round_trip_and_account_access(client):
    token = client.post("/token", json={"account_id": "A100"}).get_json()["token"]
    assert isinstance(token, str)
    r = client.get("/accounts/A100", headers={"Authorization": f"Bearer {token}"})
    assert r.get_json() == {"id": "A100", "balance": 18250.75}
    assert client.get("/accounts/A100", headers={"Authorization": "Bearer nonsense"}).status_code == 401


def test_other_accounts_are_forbidden(client):
    token = client.post("/token", json={"account_id": "A100"}).get_json()["token"]
    assert client.get("/accounts/B200", headers={"Authorization": f"Bearer {token}"}).status_code == 403


def test_rate_import(client):
    r = client.post("/rates/import", data="tiers:\n  - {score: 720, apr: 5.9}\n  - {score: 660, apr: 8.4}\n")
    assert r.get_json() == {"tiers": 2}
