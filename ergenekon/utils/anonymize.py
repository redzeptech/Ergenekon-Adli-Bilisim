from __future__ import annotations

import re

# Hash tabanlı profil maskeleme: ergenekon.utils.masker.mask_users_folder_in_path


def anonymize_user_segments(path: str, placeholder: str = "<USER>") -> str:
    """Windows yolundaki Users\\<ad> segmentini maskele."""
    return re.sub(
        r"(?i)(Users\\)([^\\/]+)(\\)",
        rf"\1{placeholder}\3",
        path,
        count=1,
    )


def anonymize_path(path: str, placeholder: str = "<USER>") -> str:
    """Yol maskeleme için kısayol; şimdilik yalnızca kullanıcı segmenti."""
    return anonymize_user_segments(path, placeholder)
