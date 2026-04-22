import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import threading
import time

from attack_simulator import upload_file_vulnerable
from validator import upload_file_secure
from utils import load_whitelist, save_whitelist, parse_extensions_input


class UploadSimulator:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Range - File Upload Simulator")
        self.root.geometry("1000x650")
        self.root.configure(bg="#0b1220")

        self.status = tk.StringVar(value="READY")
        self.whitelist_text = tk.StringVar()

        self.build_ui()
        self.refresh_whitelist()

    # ---------------- UI ----------------
    def build_ui(self):
        # HEADER
        header = tk.Label(
            self.root,
            text="File Upload Attack vs Defense Simulator",
            font=("Segoe UI", 20, "bold"),
            bg="#111827",
            fg="white",
            pady=10,
        )
        header.pack(fill=tk.X)

        main_frame = tk.Frame(self.root, bg="#0b1220")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left = tk.Frame(main_frame, bg="#111827", padx=10, pady=10)
        left.pack(side=tk.LEFT, fill=tk.Y)

        right = tk.Frame(main_frame, bg="#111827", padx=10, pady=10)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # BUTTONS
        self.create_button(left, "Upload (Vulnerable)", self.vulnerable_upload, "#dc2626")
        self.create_button(left, "Upload (Secure)", self.secure_upload, "#16a34a")
        self.create_button(left, "Clear Logs", self.clear_logs, "#374151")

        # EDIT BUTTON
        self.create_button(left, "Edit Whitelist", self.edit_whitelist, "#2563eb")

        # STATUS
        tk.Label(left, textvariable=self.status, fg="white", bg="#1f2937",
                 font=("Segoe UI", 12, "bold")).pack(fill=tk.X, pady=10)

        # WHITELIST
        tk.Label(left, text="Whitelist", fg="cyan", bg="#111827").pack(anchor="w")
        tk.Label(left, textvariable=self.whitelist_text, fg="white", bg="#111827").pack(anchor="w")

        # LOG AREA
        self.log_box = tk.Text(right, bg="#020617", fg="lime", font=("Consolas", 10))
        self.log_box.pack(fill=tk.BOTH, expand=True)

    def create_button(self, parent, text, command, color):
        tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="white",
            font=("Segoe UI", 11, "bold"),
            pady=8,
        ).pack(fill=tk.X, pady=6)

    # ---------------- LOGGING ----------------
    def log(self, msg):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

    def clear_logs(self):
        self.log_box.delete(1.0, tk.END)

    # ---------------- WHITELIST ----------------
    def refresh_whitelist(self):
        wl = load_whitelist() or []
        self.whitelist_text.set(", ".join(wl))

    def edit_whitelist(self):
        current = load_whitelist() or []
        new = simpledialog.askstring(
            "Edit Whitelist",
            f"Current: {','.join(current)}\nEnter new:"
        )
        if not new:
            return
        updated = parse_extensions_input(new)
        save_whitelist(updated)
        self.refresh_whitelist()
        self.log(f"[INFO] Whitelist updated: {updated}")

    # ---------------- ANIMATION ----------------
    def animate_status(self, text):
        for _ in range(3):
            self.status.set(text + ".")
            time.sleep(0.3)
            self.status.set(text + "..")
            time.sleep(0.3)
            self.status.set(text + "...")
            time.sleep(0.3)

    # ---------------- ACTIONS ----------------
    def vulnerable_upload(self):
        file = filedialog.askopenfilename()
        if not file:
            return
        result = upload_file_vulnerable(file)
        self.log("[VULNERABLE] Uploaded without validation")
        messagebox.showwarning("Vulnerable", result)

    def secure_upload(self):
        file = filedialog.askopenfilename()
        if not file:
            return

        # REAL-TIME ANIMATION THREAD
        thread = threading.Thread(target=self.run_secure, args=(file,))
        thread.start()

    def run_secure(self, file):
        self.animate_status("Validating")
        result = upload_file_secure(file)

        self.status.set(result["status"])
        self.log("\n".join(result["details"]))

        messagebox.showinfo("Result", result["message"])


if __name__ == "__main__":
    root = tk.Tk()
    app = UploadSimulator(root)
    root.mainloop()