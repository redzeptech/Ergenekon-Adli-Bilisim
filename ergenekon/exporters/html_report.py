from __future__ import annotations

import html
from collections.abc import Iterable


def render_simple_html(title: str, sections: Iterable[tuple[str, str]]) -> str:
    """Render a minimal UTF-8 HTML report body.

    Args:
        title: Report title.
        sections: Iterable of (section title, section body).

    Returns:
        Complete HTML document string.
    """
    parts = [
        "<!DOCTYPE html>",
        '<html lang="tr">',
        "<head><meta charset=\"utf-8\"/>",
        f"<title>{html.escape(title)}</title></head><body>",
        f"<h1>{html.escape(title)}</h1>",
    ]
    for heading, body in sections:
        parts.append(f"<h2>{html.escape(heading)}</h2>")
        parts.append(f"<pre>{html.escape(body)}</pre>")
    parts.append("</body></html>")
    return "\n".join(parts)
