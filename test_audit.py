from audit import score


def rating(pw):
    return score(pw)[1][0]


def test_common_and_disguised_are_very_weak():
    for pw in ("password123", "P@ssw0rd!", "Summer2024", "letmein"):
        assert rating(pw) == "VERY WEAK", pw


def test_short_passwords_capped():
    assert rating("Tr0ub4dor&3") != "STRONG"


def test_long_passphrase_and_random_are_strong():
    assert rating("correct-horse-battery-staple") == "STRONG"
    assert rating("m7#Kq!v9Zp$2wLx4") == "STRONG"


def test_keyboard_walk_penalized():
    assert score("qwertyzebra99!")[0] < score("plumzebra99!xq")[0]


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f()
    print("all tests passed")
