from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
from cryptography.fernet import Fernet

app = Flask(__name__)

# Generate a key for encryption and decryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_data(data):
    return cipher_suite.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher_suite.decrypt(encrypted_data).decode()

def get_openai_key(company, mac_id):
    """Fetch OpenAI key for a given company and MAC ID from the MySQL database and encrypt it."""
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(host='localhost',
                                             database='Customer',
                                             user='root')
        if connection.is_connected():
            cursor = connection.cursor()
            # Decrypt company name and MAC ID before querying the database
            company = decrypt_data(company)
            mac_id = decrypt_data(mac_id)
            print("Original Company Name:", company)
            print("Original MAC ID:", mac_id)
            # Prepare the query and execute
            query = "SELECT key FROM companies WHERE company_name = %s AND mac_id = %s"
            cursor.execute(query, (company, mac_id))
            # Fetch one record
            result = cursor.fetchone()
            if result:
                openai_key = result[0]
                encrypted_openai_key = encrypt_data(openai_key)
                # Convert bytes to string before returning
                encrypted_openai_key_str = encrypted_openai_key.decode()
                return encrypted_openai_key_str
            else:
                return None
    except Error as e:
        return None
    finally:
        if connection.is_connected():
            connection.close()

@app.route('/check_access', methods=['POST'])
def check_access():
    # Extract data from the request sent by Streamlit
    data = request.json
    encrypted_company = encrypt_data(data.get('company'))
    encrypted_mac_address = encrypt_data(data.get('mac_address'))

    # Get encrypted OpenAI key from the database
    encrypted_openai_key = get_openai_key(encrypted_company, encrypted_mac_address)
    print("Encrypted Company Name:", encrypted_company)
    print("Encrypted MAC ID:", encrypted_mac_address)

    # Prepare response
    if encrypted_openai_key:
        # Decrypt the encrypted OpenAI key
        decrypted_openai_key = decrypt_data(encrypted_openai_key.encode())
        response = {'status': 'success', 'decrypted_openai_key': decrypted_openai_key}
    else:
        response = {'status': 'error', 'message': 'No match found for the given company and MAC address.'}

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
