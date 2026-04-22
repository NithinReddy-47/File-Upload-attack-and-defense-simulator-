"""Shared helper functions for file inspection and secure storage."""

import json
import mimetypes
import os
import uuid

try:
    import magic  # type: ignore
except ImportError:
    magic = None


# Maximum accepted upload size: 5 MB.
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024

# MIME expectations for common simulation file types.
EXPECTED_MIME_TYPES = {
    ".jpg": {"image/jpeg"},
    ".png": {"image/png"},
    ".txt": {"text/plain"},
}

WHITELIST_FILE = "whitelist.json"


def get_file_name(file_path):
    """Return the final path component."""
    return os.path.basename(file_path)


def get_file_extension(file_path):
    """Return the lowercase file extension."""
    _, extension = os.path.splitext(file_path)
    return extension.lower()


def normalize_extension(extension):
    """Normalize user input so extensions are lowercase and start with a dot."""
    cleaned_extension = extension.strip().lower()
    if not cleaned_extension:
        return ""
    if not cleaned_extension.startswith("."):
        cleaned_extension = f".{cleaned_extension}"
    return cleaned_extension


def get_file_size(file_path):
    """Return the file size in bytes."""
    return os.path.getsize(file_path)


def format_file_size(file_size):
    """Format a file size in a human-friendly unit."""
    if file_size < 1024:
        return f"{file_size} B"
    if file_size < 1024 * 1024:
        return f"{file_size / 1024:.2f} KB"
    return f"{file_size / (1024 * 1024):.2f} MB"


def get_expected_mime_types(extension):
    """Return expected MIME types for an extension, using static and guessed values."""
    normalized_extension = normalize_extension(extension)
    expected_mime_types = set(EXPECTED_MIME_TYPES.get(normalized_extension, set()))

    guessed_mime_type, _ = mimetypes.guess_type(f"sample{normalized_extension}")
    if guessed_mime_type:
        expected_mime_types.add(guessed_mime_type)

    return expected_mime_types


def save_whitelist(extensions):
    """Persist the allowed extensions to the whitelist JSON file."""
    normalized_extensions = sorted(
        {normalize_extension(extension) for extension in extensions if normalize_extension(extension)}
    )

    with open(WHITELIST_FILE, "w", encoding="utf-8") as whitelist_file:
        json.dump({"allowed_extensions": normalized_extensions}, whitelist_file, indent=2)

    return normalized_extensions


def load_whitelist():
    """Load the whitelist from disk or return None when it is missing or invalid."""
    if not os.path.exists(WHITELIST_FILE):
        return None

    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as whitelist_file:
            whitelist_data = json.load(whitelist_file)
    except (json.JSONDecodeError, OSError):
        return None

    extensions = whitelist_data.get("allowed_extensions", [])
    normalized_extensions = [
        normalize_extension(extension) for extension in extensions if normalize_extension(extension)
    ]

    if not normalized_extensions:
        return None

    return sorted(set(normalized_extensions))


def normalize_extensions(extensions):
    """Normalize a collection of extensions and remove duplicates."""
    normalized = [normalize_extension(extension) for extension in extensions]
    return sorted({extension for extension in normalized if extension})


def parse_extensions_input(raw_input):
    """Normalize a comma-separated extension list and remove duplicates."""
    return normalize_extensions(raw_input.split(","))


def detect_actual_mime_type(file_path):
    """Use python-magic when available, else fall back to lightweight inspection."""
    if magic is not None:
        try:
            return magic.from_file(file_path, mime=True)
        except (AttributeError, OSError, ValueError):
            pass

    with open(file_path, "rb") as uploaded_file:
        header = uploaded_file.read(16)

    if header.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"

    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"

    if is_probably_plain_text(file_path):
        return "text/plain"

    return "application/octet-stream"


def guess_extension_mime_type(file_path):
    """Return the MIME type guessed from the filename extension."""
    guessed_mime_type, _ = mimetypes.guess_type(file_path)
    return guessed_mime_type or "unknown"


def read_file_signature(file_path, length=16):
    """Read the first bytes used for file signature validation."""
    with open(file_path, "rb") as uploaded_file:
        return uploaded_file.read(length)


def is_probably_plain_text(file_path, sample_size=4096):
    """Return True when a file sample decodes as UTF-8 text."""
    try:
        with open(file_path, "r", encoding="utf-8") as uploaded_file:
            uploaded_file.read(sample_size)
        return True
    except UnicodeDecodeError:
        return False


def generate_secure_filename(file_path):
    """Generate a UUID-based storage name while preserving the validated extension."""
    extension = get_file_extension(file_path)
    return f"{uuid.uuid4()}{extension}"
