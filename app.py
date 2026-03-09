from flask import Flask, render_template, request, redirect, session
import json
import mercadopago

app = Flask(__name__)
app.secret_key = "segredo123"

sdk = mercadopago.SDK("APP_USR-2200969351841973-030910-6e3fa5fb3a1f638d0916a3fbd6a97fa6-3250901281")


# -----------------------
# FUNÇÃO LIMITE POR PLANO
# -----------------------

def limite_fornecedores(plano):

    if plano == "basic":
        return 3

    if plano == "pro":
        return 999

    if plano == "premium":
        return 999

    return 3


# -----------------------
# LOGIN
# -----------------------

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


# -----------------------
# DASHBOARD
# -----------------------

@app.route("/dashboard")
def dashboard():

    if "usuario" not in session:
        return redirect("/")

    usuario = session["usuario"]

    with open("usuarios.json") as f:
        usuarios = json.load(f)

    plano = "basic"

    for u in usuarios:
        if u["email"] == usuario:
            plano = u.get("plano", "basic")

    with open("dados.json") as f:
        dados = json.load(f)

    fornecedores = []

    if usuario in dados:
        fornecedores = dados[usuario]

    limite = limite_fornecedores(plano)

    return render_template(
        "dashboard.html",
        plano=plano,
        fornecedores=fornecedores,
        limite=limite
    )


# -----------------------
# ADICIONAR FORNECEDOR
# -----------------------

@app.route("/adicionar_fornecedor", methods=["POST"])
def adicionar_fornecedor():

    if "usuario" not in session:
        return redirect("/")

    usuario = session["usuario"]

    nome = request.form["nome"]
    categoria = request.form["categoria"]
    telefone = request.form["telefone"]
    total = request.form["total"]

    with open("usuarios.json") as f:
        usuarios = json.load(f)

    plano = "basic"

    for u in usuarios:
        if u["email"] == usuario:
            plano = u.get("plano", "basic")

    limite = limite_fornecedores(plano)

    with open("dados.json") as f:
        dados = json.load(f)

    if usuario not in dados:
        dados[usuario] = []

    if len(dados[usuario]) >= limite:
        return "⚠️ Limite de fornecedores atingido no plano."

    novo = {
        "nome": nome,
        "categoria": categoria,
        "telefone": telefone,
        "total": total
    }

    dados[usuario].append(novo)

    with open("dados.json", "w") as f:
        json.dump(dados, f, indent=4)

    return redirect("/dashboard")


# -----------------------
# EXCLUIR FORNECEDOR
# -----------------------

@app.route("/excluir_fornecedor/<int:id>")
def excluir_fornecedor(id):

    if "usuario" not in session:
        return redirect("/")

    usuario = session["usuario"]

    with open("dados.json") as f:
        dados = json.load(f)

    if usuario in dados:
        dados[usuario].pop(id)

    with open("dados.json", "w") as f:
        json.dump(dados, f, indent=4)

    return redirect("/dashboard")


# -----------------------
# TELA DE PLANOS
# -----------------------

@app.route("/planos")
def planos():
    return render_template("planos.html")


# -----------------------
# PAGAMENTO MERCADO PAGO
# -----------------------
@app.route("/criar_pagamento")
def criar_pagamento():

    preference_data = {
        "items": [
            {
                "title": "Planner de Casamento Premium",
                "quantity": 1,
                "unit_price": 29.0,
                "currency_id": "BRL"
            }
        ],
        "back_urls": {
            "success": "http://127.0.0.1:5000/pagamento_sucesso",
            "failure": "http://127.0.0.1:5000/pagamento_erro",
            "pending": "http://127.0.0.1:5000/pagamento_pendente"
        }
    }

    preference_response = sdk.preference().create(preference_data)

    # Mostrar resposta da API
    print(preference_response)

    if preference_response["status"] != 201:
        return f"Erro ao criar pagamento: {preference_response}"

    preference = preference_response["response"]

    return redirect(preference["init_point"])
# -----------------------
# PAGAMENTO SUCESSO
# -----------------------

@app.route("/pagamento_sucesso")
def pagamento_sucesso():

    usuario = session["usuario"]

    with open("usuarios.json") as f:
        usuarios = json.load(f)

    for u in usuarios:

        if u["email"] == usuario:
            u["plano"] = "premium"

    with open("usuarios.json", "w") as f:
        json.dump(usuarios, f, indent=4)

    return render_template("sucesso.html")


# -----------------------
# PAGAMENTO ERRO
# -----------------------

@app.route("/pagamento_erro")
def pagamento_erro():
    return "Pagamento não aprovado"


# -----------------------
# PAGAMENTO PENDENTE
# -----------------------

@app.route("/pagamento_pendente")
def pagamento_pendente():
    return "Pagamento pendente"


# -----------------------

if __name__ == "__main__":
    app.run(debug=True)
