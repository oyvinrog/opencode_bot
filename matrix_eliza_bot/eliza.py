"""A small, dependency-free ELIZA-style conversation engine."""

from __future__ import annotations

import random
import re
from dataclasses import dataclass


REFLECTIONS = {
    "am": "are",
    "are": "am",
    "i": "you",
    "i'd": "you would",
    "i've": "you have",
    "me": "you",
    "my": "your",
    "myself": "yourself",
    "was": "were",
    "you": "I",
    "you'd": "I would",
    "you've": "I have",
    "your": "my",
    "yourself": "myself",
}


def reflect(fragment: str) -> str:
    """Turn a first-person fragment into a second-person fragment."""
    return " ".join(REFLECTIONS.get(word.lower(), word) for word in fragment.split())


@dataclass(frozen=True)
class Pattern:
    expression: re.Pattern[str]
    responses: tuple[str, ...]


PATTERNS = (
    Pattern(re.compile(r"^I need (.+)$", re.I), (
        "Why do you need {0}?",
        "Would getting {0} really help you?",
        "Are you sure you need {0}?",
    )),
    Pattern(re.compile(r"^Why (?:don't|do not) you (.+)\??$", re.I), (
        "Do you really think I don't {0}?",
        "Perhaps eventually I will {0}.",
        "Do you want me to {0}?",
    )),
    Pattern(re.compile(r"^Why can't I (.+)\??$", re.I), (
        "What makes you think you can't {0}?",
        "If you could {0}, what would change?",
        "Have you really tried to {0}?",
    )),
    Pattern(re.compile(r"^I can't (.+)$", re.I), (
        "How do you know you can't {0}?",
        "What would it take for you to {0}?",
        "Perhaps you could {0} if you tried.",
    )),
    Pattern(re.compile(r"^I am (.+)$", re.I), (
        "How long have you been {0}?",
        "How do you feel about being {0}?",
        "Why do you tell me you're {0}?",
    )),
    Pattern(re.compile(r"^I'm (.+)$", re.I), (
        "How does being {0} make you feel?",
        "Do you enjoy being {0}?",
        "Why are you {0}?",
    )),
    Pattern(re.compile(r"^I feel (.+)$", re.I), (
        "Tell me more about feeling {0}.",
        "Do you often feel {0}?",
        "When you feel {0}, what do you do?",
    )),
    Pattern(re.compile(r"^I (.+) you$", re.I), (
        "Why do you {0} me?",
        "What makes you think you {0} me?",
        "Does it please you to believe you {0} me?",
    )),
    Pattern(re.compile(r"^Because (.+)$", re.I), (
        "Is that the real reason?",
        "What other reasons come to mind?",
        "Does that reason explain anything else?",
    )),
    Pattern(re.compile(r"^(.+) sorry(.+)?$", re.I), (
        "There is no need to apologize.",
        "What feelings do apologies bring up for you?",
    )),
    Pattern(re.compile(r"^Hello[!.]?$", re.I), (
        "Hello. How are you feeling today?",
        "Hello. What would you like to discuss?",
    )),
    Pattern(re.compile(r"^(.+) friend(.+)?$", re.I), (
        "Tell me more about your friends.",
        "What do you value in a friendship?",
    )),
    Pattern(re.compile(r"^Yes[.!]?$", re.I), (
        "You seem quite certain.",
        "I see. Can you tell me more?",
    )),
    Pattern(re.compile(r"^No[.!]?$", re.I), (
        "Why not?",
        "Are you saying no just to be negative?",
    )),
    Pattern(re.compile(r"^Is it (.+)\??$", re.I), (
        "Do you think it is {0}?",
        "What would it mean if it were {0}?",
    )),
    Pattern(re.compile(r"^Can you (.+)\??$", re.I), (
        "What makes you wonder whether I can {0}?",
        "Perhaps you would like to be able to {0} yourself.",
    )),
    Pattern(re.compile(r"^You are (.+)$", re.I), (
        "Why does it matter whether I am {0}?",
        "Would you prefer that I weren't {0}?",
    )),
    Pattern(re.compile(r"^You (.+)$", re.I), (
        "We were discussing you, not me.",
        "Why do you say that about me?",
    )),
    Pattern(re.compile(r"^(.+)\?$", re.I), (
        "What answer would satisfy you most?",
        "What do you think?",
        "Why do you ask?",
    )),
)

FALLBACKS = (
    "Please tell me more.",
    "How does that make you feel?",
    "Can you elaborate on that?",
    "Why do you say that?",
    "What comes to mind when you say that?",
)


class Eliza:
    """Choose an ELIZA response for each input line."""

    def __init__(self, rng: random.Random | None = None) -> None:
        self.rng = rng or random.SystemRandom()

    def respond(self, text: str) -> str:
        cleaned = " ".join(text.strip().split())
        if not cleaned:
            return "Please say something."

        for pattern in PATTERNS:
            match = pattern.expression.match(cleaned)
            if match:
                fragments = tuple(reflect(value or "").strip(" .?!") for value in match.groups())
                return self.rng.choice(pattern.responses).format(*fragments)
        return self.rng.choice(FALLBACKS)

