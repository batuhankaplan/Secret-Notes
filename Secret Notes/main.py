import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import os

# Ana uygulama sınıfı
class SecretNotesApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secret Notes")

        # Uygulama penceresinin başlangıç boyutunu ayarlama (Genişlik x Yükseklik)
        self.root.geometry("450x480")

        # Logo ekleme ve boyutlandırma
        logo_path = r"C:\Users\PC\Desktop\logos.png"  # Dosya yolunu güncelleyin
        logo_image = Image.open(logo_path)
        logo_image = logo_image.resize((150, 150), Image.LANCZOS)
        self.logo = ImageTk.PhotoImage(logo_image)

        # Logo label'ı
        self.logo_label = tk.Label(root, image=self.logo)
        self.logo_label.pack()

        # Anahtar metnini çapraz koymak için frame
        self.key_frame = tk.Frame(root)
        self.key_frame.pack()

        # Çapraz metin label'ı (örnek anahtar)
        self.key_label = tk.Label(self.key_frame, text="YOUR_SECRET_KEY", font=("Arial", 14), fg="red")
        self.key_label.pack()

        # Anahtar label'ı çapraz görünmesi için
        self.key_label.place(relx=0.5, rely=0.5, anchor='center')

        # Başlık alanı
        self.title_label = tk.Label(root, text="Title")
        self.title_label.pack()
        self.title_entry = tk.Entry(root, width=50)
        self.title_entry.pack()

        # Gizli mesaj alanı
        self.message_label = tk.Label(root, text="Secret Message")
        self.message_label.pack()
        self.message_entry = tk.Text(root, height=10, width=50)
        self.message_entry.pack()

        # Şifre alanı
        self.password_label = tk.Label(root, text="Secret Password")
        self.password_label.pack()
        self.password_entry = tk.Entry(root, show='*', width=50)
        self.password_entry.pack()

        # Butonlar
        self.save_button = tk.Button(root, text="Save & Encrypt", command=self.save_and_encrypt)
        self.save_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

    def save_and_encrypt(self):
        title = self.title_entry.get()
        message = self.message_entry.get("1.0", tk.END).strip()
        password = self.password_entry.get()

        if not title or not message or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        # Şifreleme işlemi
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted_message = cipher.encrypt(message.encode())

        # Dosyaya yazma
        with open(f"{title}.txt", "wb") as file:
            file.write(key + b'\n' + encrypted_message)

        # Giriş alanlarını temizle
        self.title_entry.delete(0, tk.END)
        self.message_entry.delete("1.0", tk.END)
        self.password_entry.delete(0, tk.END)

        messagebox.showinfo("Success", "Message saved and encrypted successfully!")

    def decrypt(self):
        title = self.title_entry.get()
        encrypted_file = f"{title}.txt"

        if not os.path.exists(encrypted_file):
            messagebox.showerror("Error", "No such file found.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter the password.")
            return

        # Dosyadan okuma
        with open(encrypted_file, "rb") as file:
            key = file.readline().strip()
            encrypted_message = file.read()

        # Şifre çözme işlemi
        cipher = Fernet(key)
        try:
            decrypted_message = cipher.decrypt(encrypted_message).decode()
            self.message_entry.delete("1.0", tk.END)
            self.message_entry.insert(tk.END, decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Check your password.")

# Uygulamayı başlat
if __name__ == "__main__":
    root = tk.Tk()
    app = SecretNotesApp(root)
    root.mainloop()
