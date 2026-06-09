from temporal_exploit.features import has_list_value, list_len


def test_list_len_handles_lists_tuples_and_missing_values() -> None:
    assert list_len(["CWE-79"]) == 1
    assert list_len(("apache", "httpd")) == 2
    assert list_len(None) == 0
    assert list_len("not-a-list") == 0


def test_has_list_value_flags_only_non_empty_lists_and_tuples() -> None:
    assert has_list_value(["CWE-79"]) == 1
    assert has_list_value(("apache",)) == 1
    assert has_list_value([]) == 0
    assert has_list_value(None) == 0
