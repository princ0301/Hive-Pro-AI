import re


def clean_prose(text: str) -> str:
    cleaned = re.sub(r"\{\{\s*insert:[^}]+\}\}", "", text or "")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def first_sentence(text: str, fallback_words: int = 36) -> str:
    cleaned = clean_prose(text)
    if not cleaned:
        return ""
    pieces = cleaned.split(". ")
    if pieces and len(pieces[0].split()) >= 8:
        sentence = pieces[0].strip()
        return sentence if sentence.endswith(".") else f"{sentence}."
    words = cleaned.split()
    excerpt = " ".join(words[:fallback_words]).strip()
    return excerpt if excerpt.endswith(".") else f"{excerpt}."


def brief_recommendation(text: str, max_words: int = 26) -> str:
    cleaned = clean_prose(text)
    if not cleaned:
        return ""
    first_clause = re.split(r"[.;:]", cleaned)[0].strip()
    words = first_clause.split()
    result = first_clause if len(words) <= max_words else " ".join(words[:max_words]).strip()
    return result if result.endswith(".") else f"{result}."
