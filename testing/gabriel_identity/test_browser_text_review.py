"""Candidate passages retain literal provenance and never constitute qualified detection."""
from gabriel.identity.browser_text_review import candidate_passages


def test_candidates_are_exact_substrings_without_incident_or_authority_claims():
    source='Generated tenant\nFailed login for generated-user\nMalware detected on generated-host\n'
    result=candidate_passages(source)
    assert {r['family'] for r in result['findings']}=={'authentication','malware'}
    assert all(source[r['start']:r['end']]==r['quote'] for r in result['findings'])
    assert not result['incident_confirmed'] and not result['quality_qualified'] and not result['model_used']


def test_zero_negation_and_documentation_do_not_become_activity_candidates():
    source='0 failed login attempts\nNo malware detected\nExample: brute force\nDocumentation: data exfiltration\n'
    assert candidate_passages(source)['findings']==[]


def test_match_overflow_is_disclosed_not_silently_dropped():
    result=candidate_passages(('Failed login for generated-user\n')*20)
    assert len(result['findings'])==16 and result['omitted_matches']==4
