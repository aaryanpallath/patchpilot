"""A small loan-servicing API: payment quotes, amortization schedules and account lookups.

Deliberately written the way older internal services often are, so the security scanners have something to find.
"""

import sqlite3
import subprocess
from datetime import datetime, timedelta

import jwt
import requests
import yaml
from flask import Flask, abort, jsonify, request

app = Flask(__name__)
SECRET_KEY = "gmf-demo-signing-key-2019"  # hardcoded signing key
DB_PATH = "loans.db"


def monthly_payment(principal: float, apr: float, months: int) -> float:
    if months <= 0:
        raise ValueError("months must be positive")
    r = apr / 12 / 100
    if r == 0:
        return round(principal / months, 2)
    return round(principal * r / (1 - (1 + r) ** -months), 2)


def amortization(principal: float, apr: float, months: int) -> list[dict]:
    pay, balance, rows = monthly_payment(principal, apr, months), principal, []
    for n in range(1, months + 1):
        interest = round(balance * apr / 12 / 100, 2)
        principal_part = round(min(pay - interest, balance), 2)
        balance = round(balance - principal_part, 2)
        rows.append({"n": n, "payment": round(principal_part + interest, 2), "interest": interest,
                     "principal": principal_part, "balance": balance})
    return rows


def issue_token(account_id: str) -> str:
    payload = {"sub": account_id, "exp": datetime.utcnow() + timedelta(hours=1)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256").decode("utf-8")  # PyJWT 1.x returns bytes


def verify_token(token: str) -> str:
    return jwt.decode(token, SECRET_KEY)["sub"]  # PyJWT 1.x accepts any algorithm the token names


@app.post("/quote")
def quote():
    body = request.get_json(force=True)
    pay = monthly_payment(float(body["principal"]), float(body["apr"]), int(body["months"]))
    return jsonify({"monthly_payment": pay})


@app.post("/schedule")
def schedule():
    body = request.get_json(force=True)
    return jsonify(amortization(float(body["principal"]), float(body["apr"]), int(body["months"])))


@app.post("/token")
def token():
    return jsonify({"token": issue_token(request.get_json(force=True)["account_id"])})


@app.get("/accounts/<account_id>")
def account(account_id):
    try:
        if verify_token(request.headers.get("Authorization", "").removeprefix("Bearer ")) != account_id:
            abort(403)
    except jwt.InvalidTokenError:
        abort(401)
    con = sqlite3.connect(DB_PATH)
    row = con.execute(f"SELECT id, balance FROM accounts WHERE id = '{account_id}'").fetchone()  # SQL injection
    con.close()
    return jsonify({"id": row[0], "balance": row[1]}) if row else abort(404)


@app.post("/rates/import")
def import_rates():
    config = yaml.load(request.data, Loader=yaml.Loader)  # unsafe loader: arbitrary object construction
    return jsonify({"tiers": len(config.get("tiers", []))})


@app.get("/rates/benchmark")
def benchmark_rate():
    resp = requests.get("https://example.com/rates.json")  # no timeout
    return jsonify(resp.json())


@app.get("/admin/disk")
def disk():
    out = subprocess.check_output("df -h " + request.args.get("path", "/"), shell=True)  # command injection
    return out.decode()


if __name__ == "__main__":
    app.run(debug=True)
