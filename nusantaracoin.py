from flask import Flask, jsonify, request, send_file
import sqlite3
import hashlib
import uuid
import json
from time import time

# Inisialisasi Flask
app = Flask(__name__)

# Kunci rahasia untuk hashing password
SECRET_KEY = "your_secret_key"

# Fungsi untuk menghash password
def hash_password(password):
    return hashlib.sha256((password + SECRET_KEY).encode()).hexdigest()

# Fungsi untuk mengecek apakah password cocok dengan hash
def verify_password(password, hash):
    return hash_password(password) == hash

# Fungsi untuk mendapatkan data pengguna dari database berdasarkan username
def get_user(username):
    conn = sqlite3.connect('blockchain.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

# Fungsi untuk menambahkan pengguna baru ke database
def add_user(username, password):
    conn = sqlite3.connect('blockchain.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password, wallet) VALUES (?, ?, ?)", (username, hash_password(password), str(uuid.uuid4())))
    conn.commit()
    conn.close()

# Fungsi untuk mendapatkan data wallet dari database berdasarkan username
def get_wallet(username):
    user = get_user(username)
    if user:
        return user[2]  # index 2 is wallet column in database
    return None

# Inisialisasi database
def init_db():
    conn = sqlite3.connect('blockchain.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (username TEXT PRIMARY KEY, password TEXT, wallet TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS blocks
                      (block_index INTEGER PRIMARY KEY, timestamp REAL, proof INTEGER, previous_hash TEXT)''')
    conn.commit()
    conn.close()

# Inisialisasi blockchain
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []

        # Membuat blok genesis
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        """
        Membuat blok baru dalam blockchain

        :param proof: Bukti yang dihasilkan oleh algoritma Proof of Work
        :param previous_hash: Hash dari blok sebelumnya
        :return: Blok baru yang ditambahkan
        """

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset list transaksi saat ini
        self.current_transactions = []

        # Simpan blok ke dalam database
        self.save_block_to_db(block)

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount):
        """
        Menambahkan transaksi baru ke dalam daftar transaksi yang akan dimasukkan dalam blok berikutnya

        :param sender: Alamat pengirim
        :param recipient: Alamat penerima
        :param amount: Jumlah uang yang ditransfer
        :return: Index blok yang akan menaunginya transaksi ini
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })

        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        Membuat hash SHA-256 dari blok

        :param block: Blok
        :return: Hash dalam format string
        """
        # Pastikan dictionary diurutkan untuk hasil yang konsisten
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        # Mengembalikan blok terakhir dalam rantai
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        """
        Algoritma Proof of Work:
         - Cari nilai p' yang membuat hash(p * p') memiliki 4 angka nol pertama

        :param last_proof: Proof terakhir
        :return: Nilai proof yang memenuhi kondisi
        """
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Memvalidasi proof:
         - Apakah hash(last_proof * proof) memiliki 4 angka nol pertama?

        :param last_proof: Proof terakhir
        :param proof: Proof yang akan divalidasi
        :return: True jika valid, False jika tidak
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"
    
    def save_block_to_db(self, block):
        """
        Menyimpan blok ke dalam database

        :param block: Blok yang akan disimpan
        """
        conn = sqlite3.connect('blockchain.db')
        cursor = conn.cursor()

        try:
            cursor.execute('''INSERT INTO blocks (block_index, timestamp, proof, previous_hash)
                              VALUES (?, ?, ?, ?)''',
                           (block['index'], block['timestamp'], block['proof'], block['previous_hash']))
        except sqlite3.IntegrityError:
            # Jika kesalahan keintegritasian terjadi, 
            # atur kembali nilai block_index dengan nilai yang unik
            cursor.execute('''SELECT MAX(block_index) FROM blocks''')
            last_index = cursor.fetchone()[0]
            block['index'] = last_index + 1
            cursor.execute('''INSERT INTO blocks (block_index, timestamp, proof, previous_hash)
                              VALUES (?, ?, ?, ?)''',
                           (block['index'], block['timestamp'], block['proof'], block['previous_hash']))

        conn.commit()
        conn.close()


# Inisialisasi blockchain
blockchain = Blockchain()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return 'Username or password missing', 400
    if get_user(username):
        return 'User already exists', 400
    add_user(username, password)
    return 'User created successfully', 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return 'Username or password missing', 400
    user = get_user(username)
    if not user or not verify_password(password, user[1]):  # index 1 is password column in database
        return 'Invalid username or password', 401
    return 'Login successful', 200

@app.route('/mine', methods=['POST'])
def mine():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    wallet = data.get('wallet')
    if not username or not password or not wallet:
        return 'Username, password, or wallet missing', 400
    user = get_user(username)
    if not user or not verify_password(password, user[1]):  # index 1 is password column in database
        return 'Invalid username or password', 401
    # Proses Proof of Work untuk menambahkan blok baru
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    # Menambahkan blok baru ke dalam blockchain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "Blok baru telah ditambahkan",
        'block_index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    sender_wallet = data.get('sender_wallet')
    recipient_wallet = data.get('recipient_wallet')
    amount = data.get('amount')
    if not username or not password or not sender_wallet or not recipient_wallet or not amount:
        return 'Incomplete data', 400
    user = get_user(username)
    if not user or not verify_password(password, user[1]):  # index 1 is password column in database
        return 'Invalid username or password', 401
    index = blockchain.new_transaction(sender_wallet, recipient_wallet, amount)
    response = {'message': f'Transaction will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/chain-info', methods=['GET'])
def chain_info():
    conn = sqlite3.connect('blockchain.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM blocks")
    count = cursor.fetchone()[0]
    conn.close()
    response = {'blockchain_length': count}
    return jsonify(response), 200

@app.route('/')
def index():
    return send_file('index.html')  # Assuming index.html is in the same directory as your Python script

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
