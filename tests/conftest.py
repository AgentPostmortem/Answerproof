import pytest

from answerproof.builder import ReceiptBuilder
from answerproof.crypto import SigningKey

SOURCES = {
    "s1": "The Eiffel Tower is a wrought-iron lattice tower in Paris, France.",
    "s2": "It was completed in 1889 and stands 330 metres tall.",
    "s3": "The Louvre is the world's most-visited museum, also in Paris.",
}

ANSWER = "The Eiffel Tower is a wrought-iron lattice tower in Paris, France. It was completed in 1889 and stands 330 metres tall."


@pytest.fixture
def signing_key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def sources() -> dict[str, str]:
    return dict(SOURCES)


@pytest.fixture
def receipt(signing_key):
    builder = ReceiptBuilder(signing_key)
    builder.set_query("Tell me about the Eiffel Tower.")
    builder.set_answer(ANSWER)
    builder.set_principal("user-42", permissions=["kb:paris"], tenant="acme")
    builder.set_model("demo-llm", provider="local", params={"temperature": 0.0})
    for sid, content in SOURCES.items():
        builder.add_source(sid, content=content, score=0.9)
    return builder.finalize()
