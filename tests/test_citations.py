from answerproof.citations import bind_citations, overlap_score, split_claims


def test_split_claims_basic():
    claims = split_claims("The sky is blue. Water is wet! Is it? Yes.")
    assert claims == ["The sky is blue.", "Water is wet!", "Is it?", "Yes."]


def test_overlap_full_match():
    text = "the mitochondria is the powerhouse of the cell"
    assert overlap_score(text, text) == 1.0


def test_overlap_no_match():
    assert overlap_score("apples and oranges grow", "quantum chromodynamics theory") == 0.0


def test_cited_source_is_bound():
    source = "The Eiffel Tower is located in Paris and was completed in 1889."
    answer = "The Eiffel Tower is located in Paris."
    citations, grounding = bind_citations(answer, [("s1", source)])
    assert len(citations) == 1
    assert citations[0].source_id == "s1"
    assert grounding.grounding_score == 1.0
    assert grounding.unsupported_claims == []


def test_unsupported_claim_flagged():
    source = "The Eiffel Tower is located in Paris."
    answer = "The Eiffel Tower is located in Paris. It was designed by aliens from Mars."
    citations, grounding = bind_citations(answer, [("s1", source)])
    assert grounding.grounding_score == 0.5
    assert "It was designed by aliens from Mars." in grounding.unsupported_claims
    assert all(c.source_id == "s1" for c in citations)


def test_best_source_selected_among_many():
    answer = "Photosynthesis converts sunlight into chemical energy."
    sources = [
        ("wrong", "The stock market fell three percent on Tuesday."),
        ("right", "Photosynthesis converts sunlight into chemical energy in plants."),
    ]
    citations, grounding = bind_citations(answer, sources)
    assert len(citations) == 1
    assert citations[0].source_id == "right"


def test_empty_answer_yields_zero_grounding():
    citations, grounding = bind_citations("", [("s1", "content")])
    assert citations == []
    assert grounding.grounding_score == 0.0
