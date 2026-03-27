import hashlib
import re


def mask_pii(value: str, active: bool = True) -> str:
    """Mask personally identifiable information using SHA-256.

    Args:
        value: Raw value to anonymize.
        active: If False, returns the original value.

    Returns:
        Masked value with deterministic prefix or original value.
    """
    if not active or not value:
        return value
    # Keep deterministic short token for correlation across records.
    return f"MASKED_{hashlib.sha256(value.encode()).hexdigest()[:8]}"


def mask_path(path: str, active: bool = True) -> str:
    """Mask username segment under Windows ``Users`` folder.

    Args:
        path: Raw file system path.
        active: If False, returns the original path.

    Returns:
        Path with anonymized user segment.
    """
    if not active or not path:
        return path
    # Example: C:\Users\Ahmet\Desktop\x.exe -> C:\Users\[ANONYMIZED]\Desktop\x.exe
    return re.sub(r"(?i)([A-Z]:\\Users\\)([^\\]+)", r"\1[ANONYMIZED]", path)
