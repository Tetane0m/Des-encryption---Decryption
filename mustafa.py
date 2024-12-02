import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from Crypto.Util.Padding import pad, unpad
import base64


# DES Encryption Function
def des_encrypt_custom(data, key, num_rounds):
    key = key.encode('utf-8')
    cipher = bytearray()
    for chunk in [data[i:i + 8] for i in range(0, len(data), 8)]:
        padded_chunk = pad(chunk.encode('utf-8'), 8)
        encrypted_chunk = bytearray(padded_chunk)
        for i in range(num_rounds):
            encrypted_chunk = bytearray([b ^ key[i % len(key)] for b in encrypted_chunk])
        cipher.extend(encrypted_chunk)
    return base64.b64encode(cipher).decode('utf-8')


# DES Decryption Function
def des_decrypt_custom(data, key, num_rounds):
    key = key.encode('utf-8')
    cipher = base64.b64decode(data)
    plain_text = bytearray()
    for chunk in [cipher[i:i + 8] for i in range(0, len(cipher), 8)]:
        decrypted_chunk = bytearray(chunk)
        for i in reversed(range(num_rounds)):
            decrypted_chunk = bytearray([b ^ key[i % len(key)] for b in decrypted_chunk])
        try:
            plain_text.extend(unpad(decrypted_chunk, 8))
        except ValueError:
            plain_text.extend(decrypted_chunk)
    return plain_text.decode('utf-8', errors='ignore')


# File Selection Function
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_path_var.set(file_path)
        data_entry.delete(0, tk.END)
        with open(file_path, 'r') as f:
            file_content = f.read()
            data_entry.insert(0, file_content)


# Process File or Text
def process_file_or_text():
    operation = operation_var.get()
    key = key_entry.get()
    rounds = 16
    is_file_mode = input_mode_var.get() == "File"

    if len(key) != 8:
        messagebox.showerror("Error", "Key must be exactly 8 characters (64 bits).")
        return

    try:
        if is_file_mode:
            file_path = file_path_var.get()
            if not file_path:
                messagebox.showerror("Error", "No file selected.")
                return

            output_file = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                title="Save Processed File"
            )
            if not output_file:
                return

            with open(file_path, 'r') as f:
                file_data = f.read()

            processed_data = des_encrypt_custom(file_data, key,
                                                rounds) if operation == "Encrypt" else des_decrypt_custom(file_data,
                                                                                                          key, rounds)

            with open(output_file, 'w') as f:
                f.write(processed_data)

            messagebox.showinfo("Success", f"File processed successfully.\nSaved at: {output_file}")

        else:
            data = data_entry.get()
            if not data:
                messagebox.showerror("Error", "No text provided.")
                return

            processed_data = des_encrypt_custom(data, key, rounds) if operation == "Encrypt" else des_decrypt_custom(
                data, key, rounds)
            output_text.delete("1.0", tk.END)
            output_text.insert("1.0", processed_data)

    except Exception as e:
        messagebox.showerror("Error", f"Processing failed: {e}")


# Toggle Input Mode
def toggle_input_mode():
    # Enable or disable the file button and data entry based on the selected mode
    if input_mode_var.get() == "File":
        file_button.config(state="normal")   # Enable the file button
        data_entry.delete(0, tk.END)        # Clear the data entry field
        data_entry.config(state="disabled") # Disable the data entry field
    else:
        file_button.config(state="disabled") # Disable the file button
        data_entry.delete(0, tk.END)        # Clear the data entry field
        data_entry.config(state="normal")    # Enable the data entry field


    # Clear fields when toggling input mode
    key_entry.delete(0, tk.END)  # Clear the key entry field
    output_text.delete("1.0", tk.END)  # Clear the output text area


# Close the Application
def close_application():
    root.destroy()


# GUI Setup
root = tk.Tk()
root.title("DES Encryption Tool")
root.geometry("750x750")
root.resizable(False, False)

# Font Configuration
font_family = "zain"
font_size = 16
entry_width = 42

# Title
title_label = tk.Label(root, text="DES Tool", font=(font_family, font_size + 4, "bold"))
title_label.pack(pady=20)

# Main Frame
frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

# Input Mode Selection
input_mode_label = tk.Label(frame, text="Input Mode:", font=(font_family, font_size), anchor="w", width=20)
input_mode_label.grid(row=0, column=0, sticky="w", padx=10, pady=5)

input_mode_var = tk.StringVar(value="Text")
input_mode_menu = ttk.Combobox(frame, textvariable=input_mode_var, values=["Text", "File"],
                               font=(font_family, font_size), width=entry_width)
input_mode_menu.grid(row=0, column=1, padx=10, pady=5)
input_mode_menu.bind("<<ComboboxSelected>>", lambda _: toggle_input_mode())

# Operation Selection
operation_label = tk.Label(frame, text="Select Operation:", font=(font_family, font_size), anchor="w", width=20)
operation_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)

operation_var = tk.StringVar(value="Encrypt")
operation_menu = ttk.Combobox(frame, textvariable=operation_var, values=["Encrypt", "Decrypt"],
                              font=(font_family, font_size), width=entry_width)
operation_menu.grid(row=1, column=1, padx=10, pady=5)

# Key Entry
key_label = tk.Label(frame, text="Enter Key (8 characters):", font=(font_family, font_size), anchor="w", width=20)
key_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)

key_entry = tk.Entry(frame, show="*", font=(font_family, font_size), width=entry_width)
key_entry.grid(row=2, column=1, padx=10, pady=5)

# Data Entry
data_label = tk.Label(frame, text="Enter Text Data:", font=(font_family, font_size), anchor="w", width=20)
data_label.grid(row=3, column=0, sticky="w", padx=10, pady=5)

data_entry = tk.Entry(frame, font=(font_family, font_size), width=entry_width)
data_entry.grid(row=3, column=1, padx=10, pady=5)

# File Selection
file_label = tk.Label(frame, text="Select File:", font=(font_family, font_size), anchor="w", width=20)
file_label.grid(row=4, column=0, sticky="w", padx=10, pady=5)

file_path_var = tk.StringVar()
file_button = tk.Button(
    frame,
    text="Browse",
    command=select_file,
    font=(font_family, font_size),
    width=entry_width + 10,
    bg="#17e658",
    fg="white",
    height=1
)
file_button.grid(row=4, column=1, padx=10, pady=5)

# Output Frame
output_label = tk.Label(root, text="Output:", font=(font_family, font_size), anchor="w")
output_label.pack(padx=10, pady=5, anchor="w")

output_text = tk.Text(root, wrap="word", font=(font_family, font_size), height=5, width=67)
output_text.pack(pady=10)

# Process Button
process_button = tk.Button(
    root,
    text="Process",
    command=process_file_or_text,
    font=(font_family, font_size),
    width=100,
    bg="#17a4e6",
    fg="white",
    height=2
)
process_button.pack(pady=5)

# Close Button
close_button = tk.Button(
    root,
    text="Close",
    command=close_application,
    font=(font_family, font_size),
    width=100,
    bg="red",
    fg="white",
    height=2
)
close_button.pack(pady=5)

# Initialize Input Mode
toggle_input_mode()

# Run GUI
root.mainloop()
