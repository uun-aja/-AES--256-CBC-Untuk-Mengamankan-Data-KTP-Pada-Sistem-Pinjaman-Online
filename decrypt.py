import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import os

# ----------------- Admin Credentials ----------------#
ADMIN_CREDENTIALS = {"admin": "admin123"}  # username: password

# ----------------- Padding Key to 32 Characters ----------------#
def pad_key(key):
    """Pad the key to 32 characters."""
    return key.ljust(32, '0')

# ----------------- Dekripsi File ----------------#
def decrypt_file(encrypted_file_path, encryption_key, root):
    # Pad encryption key to 32 characters
    padded_key = pad_key(encryption_key)

    try:
        with open(encrypted_file_path, 'rb') as file:
            iv = file.read(16)  # Read IV
            ciphertext = file.read()  # Read encrypted data

        # Create AES cipher
        cipher = AES.new(padded_key.encode('utf-8'), AES.MODE_CBC, iv)

        # Decrypt the ciphertext
        decrypted_data = cipher.decrypt(ciphertext)

        # Remove padding from decrypted data
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]

        # Save the decrypted data to a new file in the 'uploads' folder
        uploads_folder = "uploads"
        if not os.path.exists(uploads_folder):
            os.makedirs(uploads_folder)  # Create 'uploads' folder if it doesn't exist
        
        decrypted_file_path = os.path.join(uploads_folder, os.path.basename(encrypted_file_path).replace('.enc', ''))
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)

        messagebox.showinfo("Decryption Complete", f"The file has been decrypted and saved as {decrypted_file_path}.")
    
    except (ValueError, IndexError) as e:
        messagebox.showerror("Decryption Error", "Password is incorrect or an error occurred during decryption.")

    finally:
        root.quit()  # Stop the mainloop
        root.destroy()  # Close the window


# --------------------- Browse File --------------------- #
def browse_file():
    filename = filedialog.askopenfilename(title="Pilih File Terenkripsi", filetypes=[("Encrypted Files", "*.enc")])
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filename)


# --------------------- Proses Dekripsi --------------------- #
def decrypt():
    dec_pass = password_entry.get()  # Ambil password yang dimasukkan
    filename = file_entry.get()  # Ambil nama file terenkripsi

    # Validasi input
    if len(dec_pass) < 8:
        messagebox.showerror("Kesalahan", "Kunci enkripsi minimal 8 karakter.")
    elif not os.path.exists(filename):
        messagebox.showerror("Kesalahan", "File tidak ditemukan.")
    else:
        try:
            # Membaca file terenkripsi dan mencoba dekripsi dengan password yang dimasukkan
            with open(filename, 'rb') as f:
                iv = f.read(16)  # Membaca IV
                ciphertext = f.read()  # Membaca data terenkripsi

            # Mencoba mendekripsi untuk memvalidasi apakah password benar
            cipher = AES.new(pad_key(dec_pass).encode('utf-8'), AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(ciphertext)  # Coba dekripsi

            # Mengecek apakah dekripsi berhasil
            if decrypted_data:
                decrypt_file(filename, dec_pass, root)  # Lanjutkan dekripsi file jika password benar
            else:
                raise ValueError("Dekripsi gagal: Password salah atau file rusak.")

        except Exception as e:
            messagebox.showerror("Kesalahan", f"Password salah atau file rusak.\n{str(e)}")



# --------------------- Admin Login --------------------- #
def login():
    username = user_entry.get()
    password = pass_entry.get()

    if username in ADMIN_CREDENTIALS and ADMIN_CREDENTIALS[username] == password:
        login_window.destroy()  # Close the login window
        main_window()  # Open the main decryption window
    else:
        messagebox.showerror("Login Error", "Username atau password salah!")
        return  # Don't proceed further if login fails


# --------------------- Main Window After Login --------------------- #
def main_window():
    global password_entry
    global file_entry
    global root  # Declare root as global to access in other parts of the code

    root = tk.Tk()
    root.title("Dekripsi File KTP")

    # Label dan input untuk kunci enkripsi
    tk.Label(root, text="Masukkan Kunci Enkripsi (Minimal 8 karakter):").pack(pady=10)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=5)

    # Label dan input untuk memilih file
    tk.Label(root, text="Pilih File Terenkripsi (.enc):").pack(pady=10)
    file_entry = tk.Entry(root, width=50)
    file_entry.pack(pady=5)
    tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

    # Tombol untuk mendekripsi
    tk.Button(root, text="Dekripsi", command=decrypt).pack(pady=20)

    # Jalankan aplikasi
    root.mainloop()


# ------------------ MAIN: Admin Login Window -------------#
login_window = tk.Tk()
login_window.title("Admin Login")
login_window.geometry("400x300")  # Set ukuran jendela login
login_window.configure(bg='#2C3E50')  # Warna latar belakang gelap

# Gaya lebih modern untuk tampilan login
header_label = tk.Label(login_window, text="Admin Login", font=('Helvetica', 24, 'bold'), fg='white', bg='#2C3E50')
header_label.pack(pady=20)  # Ruang di atas dan bawah untuk header

user_label = tk.Label(login_window, text="Username:", font=('Helvetica', 12), fg='white', bg='#2C3E50')
user_label.pack(pady=5)
user_entry = tk.Entry(login_window, font=('Helvetica', 12), width=30)
user_entry.pack(pady=5)

pass_label = tk.Label(login_window, text="Password:", font=('Helvetica', 12), fg='white', bg='#2C3E50')
pass_label.pack(pady=5)
pass_entry = tk.Entry(login_window, show="*", font=('Helvetica', 12), width=30)
pass_entry.pack(pady=5)

# Tombol login dengan gaya modern
login_button = tk.Button(login_window, text="Login", font=('Helvetica', 14, 'bold'), bg='#3498DB', fg='white', width=15, height=2, command=login)
login_button.pack(pady=20)

login_window.mainloop()
