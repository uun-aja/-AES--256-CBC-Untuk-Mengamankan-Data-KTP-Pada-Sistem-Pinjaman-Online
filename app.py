from flask import Flask, jsonify, render_template, send_from_directory, request
import json
import os
from Crypto.Cipher import AES
import base64

app = Flask(__name__)

ENCRYPTION_KEY = 'abcdefghijklmnopqrstuvwxyz123456'  # kunci enkripsi 32 karakter

def decrypt_file(encrypted_file_path):
    with open(encrypted_file_path, 'rb') as file:
        iv = file.read(16)
        ciphertext = file.read()

    cipher = AES.new(ENCRYPTION_KEY.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)

    padding_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding_length]

    # Mengonversi hasil dekripsi ke Base64 agar dapat ditampilkan langsung di HTML
    return base64.b64encode(decrypted_data).decode('utf-8')

@app.route('/')
def admin_pengguna():
    return send_from_directory(directory='.', path='admin_pengguna.html')

@app.route('/get_data', methods=['GET'])
def get_data():
    try:
        with open('uploads/data.json', 'r') as f:
            data = f.readlines()
            json_data = [json.loads(line) for line in data]
        return jsonify(json_data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file_route():
    filename = request.json.get('filename')
    encrypted_file_path = os.path.join('uploads', filename)
    
    if os.path.exists(encrypted_file_path):
        try:
            decrypted_base64 = decrypt_file(encrypted_file_path)
            return jsonify({'decrypted_text': decrypted_base64}), 200
        except Exception as e:
            return jsonify({'error': f'Gagal mendekripsi file: {str(e)}'}), 500
    else:
        return jsonify({'error': 'File tidak ditemukan.'}), 404

if __name__ == '__main__':
    app.run(debug=True)
