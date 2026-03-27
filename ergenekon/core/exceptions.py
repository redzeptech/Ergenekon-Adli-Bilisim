from __future__ import annotations


class ErgenekonError(Exception):
    """Paket genelinde yakalanabilir taban istisna sınıfı."""


class HiveParseError(ErgenekonError):
    """Hive dosyası okunamadı, bozuk veya geçerli bir registry biçimi değil."""
