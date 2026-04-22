"""Insecure file upload simulation logic."""

import os
import shutil


def upload_file_vulnerable(source_path):
    """Copy any selected file into the uploads folder without validation."""
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)

    file_name = os.path.basename(source_path)
    destination_path = os.path.join(upload_dir, file_name)
    shutil.copy(source_path, destination_path)

    return "File uploaded successfully (No validation)"
