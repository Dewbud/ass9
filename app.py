from dotenv import load_dotenv
load_dotenv()

from ciphers import encrypt_aes, decrypt_aes, decrypt_json
import base64

from db import connect, migrate, connection, insert_key, get_key, delete_key

if connect() is False:
    print('Database failed to connect')
else:
    migrate()

from flask import Flask, render_template, request, jsonify
app = Flask(__name__)

@app.route('/', methods=['GET'])
def show_form():
    return render_template("index.html")

@app.route('/key', methods=['GET'])
def create_keys():
    from ciphers import create_rsa_key_pair
    private_key, public_key = create_rsa_key_pair()
    
    # Store private key
    key_id = insert_key(private_key)

    return jsonify(
        id=key_id,
        public_key=public_key
    )

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    json = request.get_json()

    # Retrieve private key
    private_key = get_key(json['id'])
    
    # Decrypt payload
    message = decrypt_json(private_key, json['message'])

    # Delete private key
    delete_key(json['id'])

    return jsonify(
        message=message.decode("utf-8"),
    )

if __name__ == "__main__":
    app.run(debug=True)