"""Heuristic screening of untrusted text. ADVISORY ONLY: it warns officers, it never grants or removes authority.

A clean result does NOT mean the text is safe. The gateway still decides every action regardless.
English, Hindi and Marathi (Devanagari and Latin-script) patterns. Offline, deterministic, no model.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

I = re.I | re.S
CATEGORIES = {
    "override": ("Tries to override instructions",
                 "The text tells the AI to ignore its earlier instructions or rules.", [
        r"\b(ignore|disregard|forget|override|bypass)\b[^.]{0,40}\b(instructions?|messages?|rules?|prompts?|commands?|polic(?:y|ies)|guidelines?)\b",
        r"(पिछले|पहले के|ऊपर के)[^।.]{0,20}(निर्देश|आदेश)[^।.]{0,15}(अनदेखा|भूल|नज़रअंदाज़)",
        r"(मागील|आधीच्या|वरील)[^.]{0,20}(सूचना|आदेश)[^.]{0,15}(दुर्लक्षित|विसरा|दुर्लक्ष)",
        r"\b(pichle|pehle|purane|magchya|aadhichya)\b[^.]{0,20}\b(nirdesh|suchna|suchana|aadesh)\b"]),
    "destructive": ("Asks to delete data",
                    "The text asks to delete or wipe the database or records.", [
        r"\b(delete|drop|erase|wipe|destroy|truncate|format)\b[^.]{0,30}\b(database|db|tables?|all (records|data|complaints)|everything)\b",
        r"\bdrop\s+table\b",
        r"(डेटाबेस|डाटाबेस|सर्व डेटा|सारा डेटा)[^.]{0,25}(डिलीट|हटव|मिटा|काढून)",
        r"(डिलीट|हटव|मिटा)[^.]{0,25}(डेटाबेस|डाटाबेस)"]),
    "exfiltration": ("Asks to send out contact details",
                     "The text asks to send or export people's contact details to someone.", [
        r"\b(send|export|forward|email|share|mail)\b[^.]{0,50}\b(phone|contacts?|numbers?|details|citizens?|list|data)\b[^.]{0,40}(@|\bto\b)",
        r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+[^.]{0,40}\b(phone|contacts?|numbers?|details)\b",
        r"(फोन|संपर्क|नंबर)[^.।]{0,30}(भेज|पाठव)"]),
    "closure": ("Asks to close the complaint",
                "The text asks to close or mark the complaint as resolved. Only an authorised officer can do that.", [
        r"\b(close|resolve)\b[^.]{0,25}\b(this |the )?(complaint|ticket|case)\b",
        r"\bmark\b[^.]{0,20}\b(resolved|closed)\b",
        r"(बंद कर|बंद करा)"]),
    "authority": ("Claims to be an official order",
                  "The text pretends to come from an official, system or administrator.", [
        r"\b(official notice|commissioner|system\s*:|\[system|admin(istrator)? (override|order)|urgent order)\b"]),
    "tamper": ("Tries to set work-order details",
               "The text tries to dictate fields such as priority or location, or to create extra work orders.", [
        r"\b(set|change|downgrade|lower)\b[^.]{0,25}\b(priority|location)\b",
        r"\b(create|draft)\s+\d+\s+(more\s+)?work orders\b"]),
    "other_record": ("Asks about another complaint",
                     "The text asks to read a different complaint record.", [
        r"\b(fetch|read|open|include|show|get)\b[^.]{0,30}\bcomplaint\s+[A-Za-z]-\d+"]),
    "hidden": ("Contains hidden markup",
               "The text contains hidden comments, script tags or invisible characters.", [
        r"<!--|-->|<script|​|‌|⁠"]),
}
HIGH = {"destructive", "exfiltration"}


@dataclass
class Finding:
    category: str
    title: str
    explain: str
    snippet: str


@dataclass
class Screening:
    level: str  # none | suspicious | high
    findings: list[Finding] = field(default_factory=list)


def screen(text: str) -> Screening:
    found: list[Finding] = []
    for cat, (title, why, pats) in CATEGORIES.items():
        for p in pats:
            m = re.search(p, text or "", I)
            if m:
                s = " ".join(m.group(0).split())
                found.append(Finding(cat, title, why, s[:90] + ("…" if len(s) > 90 else "")))
                break
    cats = {f.category for f in found}
    if not cats:
        return Screening("none")
    high = bool(cats & HIGH) or ("override" in cats and len(cats) >= 2)
    return Screening("high" if high else "suspicious", found)


def combine(a: str, b: str) -> str:
    """The stronger warning wins. Nothing here can ever lower a level."""
    order = ["none", "suspicious", "high"]
    return order[max(order.index(a), order.index(b))]
