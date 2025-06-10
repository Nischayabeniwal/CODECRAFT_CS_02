import tkinter as tk
from tkinter import filedialog, messagebox
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import secrets

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_image(image_path, save_path, password):
    with open(image_path, "rb") as f:
        data = f.read()
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(12)
    ext = os.path.splitext(image_path)[1].encode()  # e.g. b'.png'
    ext_len = len(ext).to_bytes(1, 'big')           # 1 byte for extension length
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    with open(save_path, "wb") as f:
        # [salt][iv][tag][ext_len][ext][ciphertext]
        f.write(salt + iv + encryptor.tag + ext_len + ext + ciphertext)

def decrypt_image(image_path, save_path, password):
    with open(image_path, "rb") as f:
        raw = f.read()
    salt = raw[:16]
    iv = raw[16:28]
    tag = raw[28:44]
    ext_len = raw[44]
    ext = raw[45:45+ext_len].decode()
    ciphertext = raw[45+ext_len:]
    key = derive_key(password, salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    try:
        data = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted file.")
    # Save with correct extension
    if not save_path.endswith(ext):
        save_path += ext
    with open(save_path, "wb") as f:
        f.write(data)
    return save_path

class ImageEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Encryption Tool")
        self.image_path = None

        tk.Label(root, text="Image Encryption Tool", font=("Arial", 16)).pack(pady=10)

        self.img_label = tk.Label(root, text="No image selected")
        self.img_label.pack()

        tk.Button(root, text="Select Image", command=self.select_image).pack(pady=5)

        tk.Label(root, text="Password:").pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(root, text="Encrypt Image", command=self.encrypt).pack(pady=5)
        tk.Button(root, text="Decrypt Image", command=self.decrypt).pack(pady=5)

    def select_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image/Encrypted Files", "*.png;*.jpg;*.jpeg;*.bmp;*.enc"), ("All Files", "*.*")]
        )
        if path:
            self.image_path = path
            self.img_label.config(text=os.path.basename(path))

    def get_save_path(self, default_ext):
        return filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=[("Encrypted File", "*.enc"), ("All Files", "*.*")]
        )

    def get_save_path_decrypt(self):
        return filedialog.asksaveasfilename(
            filetypes=[("All Files", "*.*")]
        )

    def encrypt(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        save_path = self.get_save_path(".enc")
        if save_path:
            try:
                encrypt_image(self.image_path, save_path, password)
                messagebox.showinfo("Success", f"Image encrypted and saved to:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def decrypt(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an encrypted file.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        save_path = self.get_save_path_decrypt()
        if save_path:
            try:
                out_path = decrypt_image(self.image_path, save_path, password)
                messagebox.showinfo("Success", f"Image decrypted and saved to:\n{out_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ImageEncryptorApp(root)
    root.mainloop()