import sqlite3

# Membuat koneksi ke database
conn = sqlite3.connect('blockchain.db')

# Membuat kursor untuk mengeksekusi perintah SQL
cursor = conn.cursor()

# Membuat tabel blocks jika belum ada
cursor.execute('''CREATE TABLE IF NOT EXISTS blocks
                  (block_index INTEGER PRIMARY KEY, 
                   timestamp REAL, 
                   proof INTEGER, 
                   previous_hash TEXT)''')

# Menyimpan perubahan ke dalam database
conn.commit()

# Menutup koneksi ke database
conn.close()

# Sekarang Anda dapat mendefinisikan kelas Blockchain dan menjalankan aplikasi Flask Anda
