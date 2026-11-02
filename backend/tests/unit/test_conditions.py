import pytest

from app.rules.conditions import (
    MISSING,
    ConditionSyntaxError,
    ConditionTypeError,
    evaluate,
    nest,
    parse,
    resolve_path,
)


@pytest.mark.parametrize("cond,value,expected", [
    ("== 'enabled'", "enabled", True),
    ("== 'enabled'", "disabled", False),
    ("!= 0", 2, True),
    ("== 0", 0, True),
    (">= 12", 14, True),
    ("> 0 and <= 10", 5, True),
    ("> 0 and <= 10", 0, False),
    ("> 0 and <= 10 or == 99", 99, True),
    ("in ['blocked', 'read_only']", "blocked", True),
    ("not in ['Windows 10 Enterprise']", "Windows 11 Enterprise", True),
    ("contains 'Windows' and not contains 'Server'", "Microsoft Windows 11 Enterprise", True),
    ("contains 'Windows' and not contains 'Server'", "Microsoft Windows Server 2019", False),
    ("contains 4840", [135, 4840], True),
    ("intersects [102, 44818]", [102], True),
    ("not intersects ['RemoteTool Demo']", ["7-Zip", "RemoteTool Demo"], False),
    ("matches '^eng-?ws'", "eng-ws-01", True),
    ("matches '(TIA Portal|STEP 7)'", ["7-Zip", "Siemens-style TIA Portal V18"], True),
    ("count >= 2", [1], False),
    ("is empty", [], True),
    ("is not empty", "V2.9", True),
    ("== true", True, True),
    ("== 'it\\'s'", "it's", True),
])
def test_evaluate(cond, value, expected):
    assert evaluate(cond, value) is expected


def test_parameters():
    assert evaluate("<= $max", 2, {"max": 2})
    assert evaluate("not in $bad", "x", {"bad": ["y"]})
    assert parse("not intersects $a and <= $b").params() == {"a", "b"}


@pytest.mark.parametrize("cond,value", [(">= 12", "fourteen"), ("== 'x'", 3), ("count > 1", "abc"),
                                        ("in ['a']", ["a"]), ("== 1", [1]), ("== 'x'", MISSING)])
def test_type_errors(cond, value):
    with pytest.raises(ConditionTypeError):
        evaluate(cond, value)


@pytest.mark.parametrize("cond", ["", "==", "=== 1", "in 'x' extra", "matches 5", "foo 1", "[1, 2"])
def test_syntax_errors(cond):
    with pytest.raises(ConditionSyntaxError):
        parse(cond)


def test_never_uses_eval():
    with pytest.raises(ConditionSyntaxError):
        parse("__import__('os').system('true')")


def test_resolve_path_projection_and_missing():
    doc = nest({"software.installed": [{"name": "a", "v": 1}, {"name": "b"}], "os.name": "x",
                "services.winrm.available": True, "usb.storage_policy": None})
    assert resolve_path(doc, "software.installed[].name") == ["a", "b"]
    assert resolve_path(doc, "services.winrm.available") is True
    assert resolve_path(doc, "os.build") is MISSING
    assert resolve_path(doc, "usb.storage_policy") is MISSING
    assert resolve_path(doc, "nope[].x") is MISSING
