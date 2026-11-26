from soc.sigma import SigmaEngine, SigmaRule


def ev(**kw):
    base = {"type": "process_exec", "binary": "", "cmdline": "", "parent_binary": "", "uid": 1000,
            "host": "web-01"}
    return base | kw


def test_all_rules_load():
    eng = SigmaEngine()
    assert len(eng.rules) >= 15
    assert all(r.techniques for r in eng.rules)


def test_webshell_rule():
    hits = {r.title for r in SigmaEngine().evaluate(ev(binary="/bin/sh", parent_binary="/usr/sbin/php-fpm8.2",
                                                       cmdline="/bin/sh -c id", uid=33))}
    assert "Web Server Process Spawns a Shell (Web Shell)" in hits


def test_condition_grammar_not_and_or():
    rule = SigmaRule({"title": "t", "detection": {
        "a": {"Image|endswith": "/curl"}, "b": {"CommandLine|contains": "evil"}, "c": {"User": 0},
        "condition": "(a or b) and not c"}})
    assert rule.matches(ev(binary="/usr/bin/curl"))
    assert rule.matches(ev(cmdline="evil thing"))
    assert not rule.matches(ev(binary="/usr/bin/curl", uid=0))
    assert not rule.matches(ev(binary="/usr/bin/ls"))


def test_one_of_pattern_and_re_modifier():
    rule = SigmaRule({"title": "t", "detection": {
        "sel_x": {"CommandLine|re": r"^x\d+$"}, "sel_y": {"Image": "/bin/y"},
        "condition": "1 of sel_*"}})
    assert rule.matches(ev(cmdline="x42"))
    assert rule.matches(ev(binary="/bin/y"))
    assert not rule.matches(ev(cmdline="x4a"))


def test_legit_root_escalation_not_flagged():
    eng = SigmaEngine()
    sudo = {"type": "privilege_change", "binary": "/usr/bin/sudo", "uid": 1000, "new_uid": 0,
            "cmdline": "/usr/bin/sudo ls", "host": "h"}
    assert not [r for r in eng.evaluate(sudo) if "Root" in r.title]
    exploit = sudo | {"binary": "/tmp/.x/pwnkit", "cmdline": "/tmp/.x/pwnkit"}
    assert [r for r in eng.evaluate(exploit) if "Root" in r.title]
