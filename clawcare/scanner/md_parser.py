"""Markdown-aware parser — extracts typed segments for context-aware scanning.

Uses ``markdown-it-py`` to parse Markdown into an AST, then produces a list
of :class:`Segment` objects that the scanner can match rules against with
full context (code block vs. prose, language hint, line numbers).
"""

from __future__ import annotations

from dataclasses import dataclass

from markdown_it import MarkdownIt


@dataclass
class Segment:
    """A contiguous block of text extracted from a Markdown file."""

    content: str
    kind: str  # "code" | "prose"
    lang: str | None = None  # fenced code block language (e.g. "bash")
    start_line: int = 1  # 1-indexed line in the original file


def parse_markdown(text: str) -> list[Segment]:
    """Parse *text* as Markdown and return a list of typed segments.

    Fenced code blocks become ``kind="code"`` segments with the language
    tag preserved.  Everything else is grouped into ``kind="prose"``
    segments.  Line numbers are 1-indexed to match editor conventions.
    """
    md = MarkdownIt()
    tokens = md.parse(text)
    segments: list[Segment] = []

    for token in tokens:
        if token.type == "fence":
            # Fenced code block: ```lang ... ```
            lang = token.info.strip() or None
            # token.map is [start_line, end_line) 0-indexed
            # Content starts on the line after the opening fence
            start = (token.map[0] + 2) if token.map else 1
            segments.append(
                Segment(
                    content=token.content,
                    kind="code",
                    lang=lang,
                    start_line=start,
                )
            )
        elif token.type == "code_block":
            # Indented code block (4-space indent)
            start = (token.map[0] + 1) if token.map else 1
            segments.append(
                Segment(
                    content=token.content,
                    kind="code",
                    lang=None,
                    start_line=start,
                )
            )
        elif token.type == "inline" and token.content:
            # Inline content (paragraphs, headings, list items, etc.)
            start = (token.map[0] + 1) if token.map else 1
            segments.append(
                Segment(
                    content=token.content,
                    kind="prose",
                    start_line=start,
                )
            )
        elif token.type == "html_block" and token.content:
            start = (token.map[0] + 1) if token.map else 1
            segments.append(
                Segment(
                    content=token.content,
                    kind="prose",
                    start_line=start,
                )
            )

    return segments
