from flask import Flask, render_template, request, redirect, session
import json
import mercadopago

app = Flask(__name__)
app.secret_key = "segredo123"

# TOKEN DO MERCADO PAGO
sdk = mercadopago.SDK("SEU_ACCESS_TOKEN_AQUI")


# ----------------------
# LOGIN
# ----------------------

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        senha = request.form["senha"]

        with open("usuarios.json") as f:
            usuarios = json.load(f)

        for u in usuarios:
            if u["email"] == email and u["senha"] == senha:
                session["usuario"] = email
                return redirect("/dashboard")

    return render_template("login.html")


# ----------------------
# DASHBOARD
# ----------------------

@app.route("/dashboard")
def dashboard():

    if "usuario" not in session:
        return redirect("/")

    return render_template("dashboard.html")


# ----------------------
# CRIAR PAGAMENTO
# ----------------------

@app.route("/criar_pagamento")
def criar_pagamento():

    preference_data = {
        "items": [
            {
                "title": "Planner de Casamento Premium",
                "quantity": 1,
                "unit_price": 29.0
            }
        ],
        "back_urls": {
            "success": "http://localhost:5000/pagamento_sucesso",
            "failure": "http://localhost:5000/pagamento_erro",
            "pending": "http://localhost:5000/pagamento_pendente"
        },
        "auto_return": "approved"
    }

    preference_response = sdk.preference().create(preference_data)
    preference = preference_response["response"]

    return redirect(preference["init_point"])


# ----------------------
# RETORNOS
# ----------------------

@app.route("/pagamento_sucesso")
def pagamento_sucesso():
    return render_template("sucesso.html")


@app.route("/pagamento_erro")
def pagamento_erro():
    return "Pagamento não aprovado."


@app.route("/pagamento_pendente")
def pagamento_pendente():
    return "Pagamento pendente."


# ----------------------

if __name__ == "__main__":
    app.run(debug=True)
