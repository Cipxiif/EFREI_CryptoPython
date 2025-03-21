from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, render_template_string, render_template, jsonify, redirect, url_for, session
from flask import json
from urllib.request import urlopen
import sqlite3

import os

app = Flask(__name__)                                                                                                                  
app.secret_key = ${{ secrets.SECRET_KEY }}

@app.route('/')
def hello_world():
    return render_template('hello.html')

key = Fernet.generate_key()
f = Fernet(key)

@app.route('/encrypt/<key>/<string:valeur>')
def encryptage(key, valeur):
    try:
        f = Fernet(key.encode())
        token = f.encrypt(valeur.encode())
        return f"Valeur chiffrée : {token.decode()}"
    except Exception as e:
        return f"Erreur : clé invalide ou autre problème - {str(e)}"

@app.route('/decrypt/<key>/<string:valeur>')
def decryptage(key, valeur):
    try:
        f = Fernet(key.encode())
        valeur_bytes = valeur.encode()
        decrypted = f.decrypt(valeur_bytes)
        return f"Valeur déchiffrée : {decrypted.decode()}"
    except InvalidToken:
        return "Erreur : clé incorrecte ou valeur invalide (non déchiffrable)."
    except Exception as e:
        return f"Erreur : clé invalide ou autre problème - {str(e)}"

@app.route('/my_key', methods=['GET', 'POST'])
def my_key():
    if 'user_key' not in session:
        session['user_key'] = Fernet.generate_key().decode()

    key = session['user_key']
    message = ""
    encrypted_value = ""
    decrypted_value = ""

    if request.method == 'POST':
        f = Fernet(key.encode())

        if 'encrypt_value' in request.form and request.form['encrypt_value']:
            try:
                encrypted_value = f.encrypt(request.form['encrypt_value'].encode()).decode()
                message = "Texte chiffré avec succès."
            except Exception as e:
                message = f"Erreur lors du chiffrement : {str(e)}"

        elif 'decrypt_value' in request.form and request.form['decrypt_value']:
            try:
                decrypted_value = f.decrypt(request.form['decrypt_value'].encode()).decode()
                message = "Texte déchiffré avec succès."
            except Exception as e:
                message = f"Erreur lors du déchiffrement : {str(e)}"

    html = f"""
    <h1>Votre clé personnelle</h1>
    <form method="post">
        <label>Clé (personnelle, générée automatiquement) :</label><br>
        <input type="text" name="key" value="{key}" readonly size="80"><br><br>

        <label>Texte à chiffrer :</label><br>
        <input type="text" name="encrypt_value" size="80"><br>
        <input type="submit" value="Chiffrer"><br><br>

        <label>Texte à déchiffrer :</label><br>
        <input type="text" name="decrypt_value" size="80"><br>
        <input type="submit" value="Déchiffrer"><br><br>

        <strong>{message}</strong><br><br>
    """

    if encrypted_value:
        html += f"<b>Résultat :</b> {encrypted_value}<br>"
    if decrypted_value:
        html += f"<b>Résultat :</b> {decrypted_value}<br>"

    html += "</form>"

    return html

if __name__ == "__main__":
  app.run(debug=True)
