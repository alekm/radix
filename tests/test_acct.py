"""Unit tests for the accounting parse logic in acct.py."""
import acct


def _base(**over):
    attrs = {
        'Acct-Status-Type': 'Start',
        'Acct-Session-Id': 'sess-1',
        'Calling-Station-Id': 'AA-BB-CC-DD-EE-FF',
        'User-Name': 'alice',
        'Called-Station-Id': '00-11-22-33-44-55:CorpWiFi',
        'NAS-IP-Address': '10.0.0.1',
        'Framed-IP-Address': '10.20.0.42',
    }
    attrs.update(over)
    return attrs


def test_parse_basic_fields():
    rec = acct.parse(_base())
    assert rec['session_id'] == 'sess-1'
    assert rec['mac'] == 'aa:bb:cc:dd:ee:ff'
    assert rec['username'] == 'alice'
    assert rec['ssid'] == 'CorpWiFi'
    assert rec['framed_ip'] == '10.20.0.42'
    assert rec['status'] == 'start'


def test_parse_status_name_and_int_both_map():
    assert acct.parse(_base(**{'Acct-Status-Type': 'Stop'}))['status'] == 'stop'
    assert acct.parse(_base(**{'Acct-Status-Type': '2'}))['status'] == 'stop'
    assert acct.parse(_base(**{'Acct-Status-Type': '3'}))['status'] == 'interim'


def test_parse_gigawords_high_word():
    rec = acct.parse(_base(**{
        'Acct-Status-Type': 'Interim-Update',
        'Acct-Input-Octets': '100',
        'Acct-Input-Gigawords': '2',       # +2 * 2^32
        'Acct-Output-Octets': '50',
    }))
    assert rec['in_octets'] == 100 + (2 << 32)
    assert rec['out_octets'] == 50


def test_parse_session_time_int():
    rec = acct.parse(_base(**{'Acct-Session-Time': '3661'}))
    assert rec['session_time'] == 3661


def test_parse_ignores_unknown_status():
    # Accounting-On (7) / Accounting-Off (8) are not session events.
    assert acct.parse(_base(**{'Acct-Status-Type': '7'})) is None


def test_parse_requires_session_id():
    attrs = _base()
    del attrs['Acct-Session-Id']
    assert acct.parse(attrs) is None


def test_parse_handles_missing_optional_fields():
    rec = acct.parse({'Acct-Status-Type': 'Stop', 'Acct-Session-Id': 's2'})
    assert rec['mac'] is None
    assert rec['ssid'] is None
    assert rec['in_octets'] == 0
    assert rec['out_octets'] == 0
    assert rec['session_time'] == 0


def test_handle_returns_false_for_non_session_event():
    assert acct.handle({'Acct-Status-Type': '7', 'Acct-Session-Id': 'x'}) is False
