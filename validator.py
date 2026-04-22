"""Defense-in-depth validation helpers for the secure upload simulation."""

import os
import shutil

from utils import (
    MAX_FILE_SIZE_BYTES,
    detect_actual_mime_type,
    format_file_size,
    generate_secure_filename,
    get_expected_mime_types,
    get_file_extension,
    get_file_name,
    get_file_size,
    guess_extension_mime_type,
    is_probably_plain_text,
    load_whitelist,
    read_file_signature,
)


# Known signatures for the allowed binary formats.
FILE_SIGNATURES = {
    ".jpg": (b"\xff\xd8",),
    ".png": (b"\x89PNG",),
}

# Suspicious byte patterns used for educational deep-scan simulation.
SUSPICIOUS_CONTENT_PATTERNS = (
    b"<?php",
    b"<script>",
    b"eval(",
    b"exec(",
    b"base64",
)


def build_result(message, status, log_level, attack_type=None, details=None):
    """Standardize validator responses for the GUI controller."""
    return {
        "message": message,
        "status": status,
        "log_level": log_level,
        "attack_type": attack_type or "None",
        "details": details or [],
    }


def build_step_result(status, reason, details=None):
    """Return a single validation stage outcome."""
    return {
        "status": status,
        "reason": reason,
        "details": details or [],
    }


def has_double_extension(file_path):
    """Reject filenames that contain more than one extension segment."""
    file_name = get_file_name(file_path)
    return len(file_name.split(".")) > 2


def validate_extension(file_path):
    """Apply the whitelist policy and reject double extensions."""
    extension = get_file_extension(file_path)
    allowed_extensions = load_whitelist()

    if has_double_extension(file_path):
        return build_step_result(
            "fail",
            "Blocked: Double extension detected",
            [f"Extension check: rejected multi-extension filename ({get_file_name(file_path)})"],
        )

    if not allowed_extensions:
        return build_step_result(
            "fail",
            "Blocked: Whitelist configuration unavailable",
            ["Current whitelist used for validation: unavailable or invalid"],
        )

    if extension not in allowed_extensions:
        return build_step_result(
            "fail",
            "Blocked: Extension not allowed (Whitelist Policy)",
            [
                f"Current whitelist used for validation: {', '.join(allowed_extensions)}",
                f"Extension check: {extension or 'none'} is not allowed by whitelist policy",
                f"Whitelist policy: {', '.join(allowed_extensions)}",
            ],
        )

    return build_step_result(
        "pass",
        "Whitelist validated",
        [
            f"Current whitelist used for validation: {', '.join(allowed_extensions)}",
            f"Extension check: {extension} is allowed by whitelist policy",
        ],
    )


def validate_mime(file_path):
    """Compare detected MIME information with the expected type for the extension."""
    extension = get_file_extension(file_path)
    actual_mime_type = detect_actual_mime_type(file_path)
    guessed_mime_type = guess_extension_mime_type(file_path)
    expected_mime_types = get_expected_mime_types(extension)

    if not expected_mime_types:
        return build_step_result(
            "fail",
            "Blocked: MIME mismatch",
            [f"MIME result: no trusted MIME mapping is available for {extension}"],
        )

    if actual_mime_type not in expected_mime_types:
        return build_step_result(
            "fail",
            "Blocked: MIME mismatch",
            [
                f"MIME result: detected {actual_mime_type}",
                f"MIME expectation: {', '.join(sorted(expected_mime_types))}",
            ],
        )

    if guessed_mime_type != "unknown" and guessed_mime_type not in expected_mime_types:
        return build_step_result(
            "fail",
            "Blocked: MIME mismatch",
            [
                f"MIME result: detected {actual_mime_type}",
                f"Extension-based MIME guess: {guessed_mime_type}",
            ],
        )

    return build_step_result(
        "pass",
        "MIME validated",
        [
            f"MIME result: detected {actual_mime_type}",
            f"Extension-based MIME guess: {guessed_mime_type}",
        ],
    )


def validate_signature(file_path):
    """Validate the file signature or plain text content."""
    extension = get_file_extension(file_path)

    if extension == ".txt":
        if is_probably_plain_text(file_path):
            return build_step_result(
                "pass",
                "File signature validated",
                ["Signature check: plain text content confirmed"],
            )
        return build_step_result(
            "fail",
            "Blocked: Invalid file signature",
            ["Signature check: .txt file did not decode as plain UTF-8 text"],
        )

    signature = read_file_signature(file_path)
    valid_signatures = FILE_SIGNATURES.get(extension, ())
    if any(signature.startswith(valid_signature) for valid_signature in valid_signatures):
        return build_step_result(
            "pass",
            "File signature validated",
            [f"Signature check: matched known signature for {extension}"],
        )

    return build_step_result(
        "fail",
        "Blocked: Invalid file signature",
        [f"Signature check: file header does not match expected {extension} signature"],
    )


def scan_file_content(file_path):
    """Perform a simple deep content scan for dangerous embedded markers."""
    with open(file_path, "rb") as uploaded_file:
        file_bytes = uploaded_file.read()

    lowercase_bytes = file_bytes.lower()
    for pattern in SUSPICIOUS_CONTENT_PATTERNS:
        if pattern in lowercase_bytes:
            return build_step_result(
                "fail",
                "Blocked: Suspicious content detected",
                [f"Content scan result: detected dangerous pattern {pattern.decode('ascii')}"],
            )

    return build_step_result(
        "pass",
        "Content scan passed",
        ["Content scan result: no suspicious patterns detected"],
    )


def validate_size(file_path):
    """Reject files larger than the configured upload limit."""
    file_size = get_file_size(file_path)
    if file_size > MAX_FILE_SIZE_BYTES:
        return build_step_result(
            "fail",
            "Blocked: File too large",
            [f"File size: {format_file_size(file_size)} exceeds 5 MB limit"],
        )

    return build_step_result(
        "pass",
        "File size validated",
        [f"File size: {format_file_size(file_size)}"],
    )


def map_attack_type(reason):
    """Map blocked reasons to educational scenario labels."""
    if "Double extension" in reason:
        return "Double Extension Attack"
    if "Whitelist configuration unavailable" in reason:
        return "Policy Configuration Error"
    if "Whitelist Policy" in reason:
        return "Policy Violation"
    if "MIME mismatch" in reason:
        return "MIME Spoofing Attack"
    if "Invalid file signature" in reason:
        return "File Signature Spoofing"
    if "Suspicious content" in reason:
        return "Malicious Embedded Content"
    return "Malicious File Upload Attempt"


def secure_validate(file_path):
    """Run the full defense-in-depth pipeline and stop on first failure."""
    validation_details = [f"File selected: {get_file_name(file_path)}"]
    validation_steps = (
        validate_extension,
        validate_mime,
        validate_signature,
        scan_file_content,
        validate_size,
    )

    for validator in validation_steps:
        step_result = validator(file_path)
        validation_details.extend(step_result["details"])
        if step_result["status"] == "fail":
            return build_result(
                step_result["reason"],
                "BLOCKED",
                "BLOCKED",
                attack_type=map_attack_type(step_result["reason"]),
                details=validation_details + [f"Final decision: {step_result['reason']}"],
            )

    return build_result(
        "Validation pipeline passed",
        "SAFE",
        "SUCCESS",
        details=validation_details + ["Final decision: all validation layers passed"],
    )


def upload_file_secure(source_path):
    """Validate the file and store it using a UUID-based safe filename."""
    try:
        validation_result = secure_validate(source_path)
        if validation_result["status"] != "SAFE":
            return validation_result

        upload_dir = "uploads_secure"
        os.makedirs(upload_dir, exist_ok=True)

        secure_file_name = generate_secure_filename(source_path)
        destination_path = os.path.join(upload_dir, secure_file_name)
        shutil.copy(source_path, destination_path)

        return build_result(
            "Uploaded safely",
            "SAFE",
            "SUCCESS",
            details=validation_result["details"] + [f"Secure storage: saved as {secure_file_name}"],
        )
    except OSError as error:
        return build_result(
            "Blocked: File processing error",
            "BLOCKED",
            "BLOCKED",
            attack_type="File Handling Error",
            details=[
                f"File selected: {get_file_name(source_path)}",
                f"Final decision: file processing failed ({error})",
            ],
        )
