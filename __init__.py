from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, render_template_string, render_template, jsonify, redirect, url_for, session
from flask import json
from urllib.request import urlopen
import sqlite3

import os

app = Flask(__name__)                                                                                                                  
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

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

@app.route('/mykey')
def my_key():
    if 'user_key' not in session:
        session['user_key'] = Fernet.generate_key().decode()

    key = session['user_key']
    return f"""
        <h1>Votre clé personnelle</h1>
        <p><strong>Clé :</strong> {key}</p>
        <p>Copiez cette clé pour chiffrer/déchiffrer vos données.</p>
        <p>Exemple : <a href="/encrypt/{key}/Bonjour">/encrypt/{key}/Bonjour</a></p>
    """

if __name__ == "__main__":
  app.run(debug=True)
