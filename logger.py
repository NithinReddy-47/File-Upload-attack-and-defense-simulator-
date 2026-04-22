"""Tkinter log panel helpers for the simulator UI."""

import tkinter as tk
from tkinter import scrolledtext


LOG_COLORS = {
    "INFO": "#f5f7fa",
    "WARNING": "#f4d35e",
    "BLOCKED": "#ff6b6b",
    "SUCCESS": "#6ee7b7",
}


class EventLogger:
    """Manage the scrollable, color-coded event log."""

    def __init__(self, parent):
        self.text_widget = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            height=16,
            bg="#101826",
            fg="#f5f7fa",
            insertbackground="#f5f7fa",
            relief=tk.FLAT,
            font=("Consolas", 10),
            padx=12,
            pady=12,
        )
        self.text_widget.configure(state=tk.DISABLED)

        for level, color in LOG_COLORS.items():
            self.text_widget.tag_config(level, foreground=color)

    def widget(self):
        """Return the underlying Tk widget for layout placement."""
        return self.text_widget

    def log(self, level, message):
        """Append one entry with the color for its severity."""
        self.text_widget.configure(state=tk.NORMAL)
        self.text_widget.insert(tk.END, f"[{level}] {message}\n", level)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state=tk.DISABLED)

    def clear(self):
        """Remove all log entries."""
        self.text_widget.configure(state=tk.NORMAL)
        self.text_widget.delete("1.0", tk.END)
        self.text_widget.configure(state=tk.DISABLED)
