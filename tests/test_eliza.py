import random

from matrix_eliza_bot.eliza import Eliza, reflect


def test_reflects_pronouns() -> None:
    assert reflect("I am worried about my work") == "you are worried about your work"


def test_need_response_reflects_capture() -> None:
    response = Eliza(random.Random(1)).respond("I need my family")
    assert "your family" in response


def test_empty_input() -> None:
    assert Eliza().respond("   ") == "Please say something."


def test_question_gets_question_response() -> None:
    assert Eliza(random.Random(2)).respond("Will this work?") in {
        "What answer would satisfy you most?",
        "What do you think?",
        "Why do you ask?",
    }

