import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
import csv
import pickle

# --- Main Window ---
root = tk.Tk()
root.title("File Integrity Validator")
root.geometry("1200x700")

# --- Frames ---
top_frame = tk.Frame(root)
top_frame.pack(fill=tk.BOTH, expand=True)

bottom_frame = tk.Frame(root)
bottom_frame.pack(fill=tk.X, pady=10)

button_frame = tk.Frame(root)
button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

# --- Treeview (Main Display) ---
tree = ttk.Treeview(top_frame, columns=("Name", "Location", "MD5"), show="headings")
tree.heading("Name", text="Name")
tree.heading("Location", text="Location")
tree.heading("MD5", text="MD5 Hash")
tree.column("Name", width=200)
tree.column("Location", width=500)
tree.column("MD5", width=500)
tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# --- Overall Hash Display (Now at Bottom) ---
generate_button = tk.Button(bottom_frame, text="Generate Overall Hash", command=lambda: generate_overall_md5())
generate_button.pack(side=tk.LEFT, padx=(10, 10))

hash_label = tk.Label(bottom_frame, text="Overall MD5:", font=("Courier", 10, "bold"))
hash_label.pack(side=tk.LEFT, padx=(20, 5))

overall_md5_entry = tk.Entry(bottom_frame, font=("Courier", 10, "bold"), width=50, state='readonly', readonlybackground="white", borderwidth=1)
overall_md5_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

# --- Horizontal Buttons ---
tk.Button(button_frame, text="Add Files", width=20, command=lambda: add_files()).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Delete Selected", width=20, command=lambda: delete_selected()).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Clear All", width=20, command=lambda: clear_all()).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Save (.bin)", width=20, command=lambda: save_binary()).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Export CSV", width=20, command=lambda: export_csv()).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Verify Files", width=20, command=lambda: verify_files()).pack(side=tk.LEFT, padx=5)

# --- Data Storage ---
file_data = []

# --- Functions ---
def compute_md5(filepath):
    hasher = hashlib.md5()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest().upper()

def add_files():
    files = filedialog.askopenfilenames()
    for file in files:
        name = os.path.basename(file)
        md5_hash = compute_md5(file)
        tree.insert("", "end", values=(name, file, md5_hash))
        file_data.append((name, file, md5_hash))

def delete_selected():
    selected = tree.selection()
    for item in selected:
        tree.delete(item)

def clear_all():
    tree.delete(*tree.get_children())
    file_data.clear()
    overall_md5_entry.config(state='normal')
    overall_md5_entry.delete(0, tk.END)
    overall_md5_entry.config(state='readonly')

def save_binary():
    with open("file_hashes.bin", "wb") as f:
        pickle.dump(file_data, f)
    messagebox.showinfo("Saved", "Data saved as file_hashes.bin")

def export_csv():
    with open("file_hashes.csv", "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Name", "Location", "MD5"])
        for row in tree.get_children():
            writer.writerow(tree.item(row)["values"])
    messagebox.showinfo("Exported", "Data exported to file_hashes.csv")

def verify_files():
    mismatches = []
    for row in tree.get_children():
        name, path, original_md5 = tree.item(row)["values"]
        if not os.path.exists(path):
            mismatches.append(f"{name} - File not found")
            continue
        current_md5 = compute_md5(path)
        if current_md5 != original_md5:
            mismatches.append(f"{name} - Checksum mismatch")
    if mismatches:
        messagebox.showwarning("Verification Failed", "\n".join(mismatches))
    else:
        messagebox.showinfo("Verified", "All files match their original checksums.")

def generate_overall_md5():
    all_md5s = [tree.item(row)["values"][2] for row in tree.get_children()]
    joined = ''.join(all_md5s).encode()
    overall = hashlib.md5(joined).hexdigest().upper()
    overall_md5_entry.config(state='normal')
    overall_md5_entry.delete(0, tk.END)
    overall_md5_entry.insert(0, overall)
    overall_md5_entry.config(state='readonly')

# --- Start App ---
root.mainloop()
