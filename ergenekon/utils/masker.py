"""
KVKK / test ortamı için sözdeanonimleştirme (hash tabanlı maskeleme).

Gerçek kimlik, IP veya SID raporlarda yer almamalıdır; bu fonksiyonlar
tutarlı kısa takma kimlik üretir (aynı girdi → aynı maske, aynı veri seti içinde
korelasyon korunur).

Not: SHA-256'ın kısaltılmış çıktısı çakışma riski taşır; yüksek hacimde
`length` artırılabilir veya tam hex digest kullanılabilir.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Collection, Mapping
from typing import Any

_DEFAULT_HASH_LEN = 10

# KVKK / rapor paylaşımı için tipik alan adları (büyük/küçük harf duyarsız eşleşme)
_DEFAULT_KVKK_USERNAME_KEYS: frozenset[str] = frozenset(
    {"user", "username", "user_name", "windows_user", "kullanici"}
)
_DEFAULT_KVKK_PATH_KEYS: frozenset[str] = frozenset(
    {
        "path",
        "filepath",
        "artifact",
        "lowercaselongpath",
        "name",
        "rootdirpath",
        "uninstallstring",
    }
)
_DEFAULT_KVKK_SID_KEYS: frozenset[str] = frozenset({"sid", "securityidentifier", "objectsid"})


def mask_kvkk_identifiers(
    record: Mapping[str, Any],
    *,
    username_keys: Collection[str] | None = None,
    path_keys: Collection[str] | None = None,
    sid_keys: Collection[str] | None = None,
    hash_len: int = _DEFAULT_HASH_LEN,
) -> dict[str, Any]:
    """
    Tek kayıt sözlüğünde kullanıcı adı, yol ve SID alanlarını sözdeanonimleştirir.

    Kurumsal test / paylaşım öncesi KVKK riskini azaltmak için kullanılır; hukuki
    uyumluluk denetimi yerine geçmez.

    Args:
        record: Anahtar-değer çiftleri (genelde JSON-serileştirilebilir).
        username_keys: Kullanıcı adı sayılacak alan adları (varsayılan: yaygın adlar).
        path_keys: Dosya yolu veya yol içeren metin alanları.
        sid_keys: Windows SID alanları.
        hash_len: SHA-256 hex önek uzunluğu.

    Returns:
        Maskeleme uygulanmış yeni bir ``dict`` (girdi mutasyona uğramaz).
    """
    u_keys = {k.lower() for k in (username_keys or _DEFAULT_KVKK_USERNAME_KEYS)}
    p_keys = {k.lower() for k in (path_keys or _DEFAULT_KVKK_PATH_KEYS)}
    s_keys = {k.lower() for k in (sid_keys or _DEFAULT_KVKK_SID_KEYS)}

    out: dict[str, Any] = dict(record)
    for key, value in list(out.items()):
        if not isinstance(value, str) or not value:
            continue
        lk = str(key).lower()
        if lk in u_keys:
            out[key] = mask_sensitive_data(value, length=hash_len)
        elif lk in s_keys:
            out[key] = mask_sid(value, length=hash_len)
        elif lk in p_keys:
            out[key] = mask_users_folder_in_path(
                mask_ips_in_text(mask_sids_in_text(value, length=hash_len), length=hash_len),
                length=hash_len,
            )
    return out


def mask_sensitive_data(data: str, *, length: int = _DEFAULT_HASH_LEN) -> str:
    """
    Kullanıcı adı, dahili ID veya benzeri metni SHA-256 ile özetleyip
    hex'in ilk `length` karakterini döndürür (test / paylaşım için).
    """
    if data is None:
        return ""
    s = str(data)
    if not s:
        return ""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:length]


def mask_ip(ip: str, *, length: int = _DEFAULT_HASH_LEN) -> str:
    """IPv4 / IPv6 metin temsilini maskele (tam adres tek blok olarak hashlenir)."""
    if not ip or not str(ip).strip():
        return ""
    return mask_sensitive_data(str(ip).strip().lower(), length=length)


# Windows SID: S-1-5-21-... veya S-1-5-80-... gibi
_SID_PATTERN = re.compile(
    r"\bS-1-(?:5|15)-(?:\d+-){1,14}\d+\b",
    re.IGNORECASE,
)


def mask_sid(sid: str, *, length: int = _DEFAULT_HASH_LEN) -> str:
    """Tam SID dizisini tutarlı kısa takma kimliğe çevirir."""
    if not sid or not str(sid).strip():
        return ""
    normalized = str(sid).strip().upper()
    return mask_sensitive_data(normalized, length=length)


def mask_sids_in_text(text: str, *, length: int = _DEFAULT_HASH_LEN) -> str:
    """Serbest metindeki SID kalıplarını tek tek maskeler."""

    def repl(m: re.Match[str]) -> str:
        return f"SID_{mask_sid(m.group(0), length=length)}"

    return _SID_PATTERN.sub(repl, text)


# IPv4 (basit); IPv6 için daha gevşek bir blok
_IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b"
)
# Basit IPv6 (tam adres; sıkıştırılmış :: destekli değil — gerekirse genişletilir)
_IPV6_PATTERN = re.compile(
    r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b",
    re.IGNORECASE,
)


def mask_ips_in_text(text: str, *, length: int = _DEFAULT_HASH_LEN) -> str:
    """Metindeki IPv4 ve basit IPv6 kalıplarını maskeler."""

    def repl_ip(m: re.Match[str]) -> str:
        return f"IP_{mask_ip(m.group(0), length=length)}"

    out = _IPV4_PATTERN.sub(repl_ip, text)
    return _IPV6_PATTERN.sub(repl_ip, out)


def mask_users_folder_in_path(path: str, *, length: int = _DEFAULT_HASH_LEN) -> str:
    """
    `Users/<profil>` veya `Users\\<profil>` segmentindeki profil adını hash tabanlı takma adla değiştirir.
    Örnek: C:\\Users\\Ayse\\... -> C:\\Users\\u_a1b2c3d4e5\\...
    """
    if not path:
        return path

    def repl(m: re.Match[str]) -> str:
        sep1 = m.group(2)
        user = m.group(3)
        sep2 = m.group(4)
        pseudo = mask_sensitive_data(user, length=length)
        return f"{m.group(1)}{sep1}u_{pseudo}{sep2}"

    return re.sub(
        r"(?i)(Users)([\\/])([^\\/]+)([\\/])",
        repl,
        path,
        count=1,
    )


def mask_structure(
    obj: Any,
    *,
    hash_len: int = _DEFAULT_HASH_LEN,
    mask_keys: frozenset[str] | None = None,
) -> Any:
    """
    dict / list iç içe yapıda string alanları toplu maskele (anahtar adına göre).

    `mask_keys`: küçük harf normalize edilir; örn. frozenset({"username", "ip", "sid"}).
    Varsayılan: yaygın hassas anahtarlar.
    """
    if mask_keys is None:
        mask_keys = frozenset(
            {
                "user",
                "username",
                "user_name",
                "userid",
                "sid",
                "ip",
                "ipaddress",
                "client_ip",
                "host",
                "email",
                "path",
                "filepath",
                "lowercaselongpath",
            }
        )
    lowered = {k.lower() for k in mask_keys}

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            out: dict[str, Any] = {}
            for k, v in o.items():
                lk = str(k).lower()
                if lk in lowered and isinstance(v, str) and v:
                    if lk in ("ip", "ipaddress", "client_ip"):
                        out[k] = mask_ip(v, length=hash_len)
                    elif lk == "sid":
                        out[k] = mask_sid(v, length=hash_len)
                    elif lk in ("path", "filepath", "lowercaselongpath"):
                        out[k] = mask_users_folder_in_path(
                            mask_ips_in_text(
                                mask_sids_in_text(v, length=hash_len),
                                length=hash_len,
                            ),
                            length=hash_len,
                        )
                    else:
                        out[k] = mask_sensitive_data(v, length=hash_len)
                elif isinstance(v, (dict, list)):
                    out[k] = walk(v)
                else:
                    out[k] = v
            return out
        if isinstance(o, list):
            return [walk(i) for i in o]
        return o

    return walk(obj)
