import pytest

from ldap3 import ALL_ATTRIBUTES

def test_ldap_connection(mock_connection):
    assert mock_connection.bound is True
    assert mock_connection.server.host == 'my_fake_server'

def test_ldap_search(extended_mock_cn_monitor):
    conn = extended_mock_cn_monitor
    conn.search('cn=monitor', '(objectClass=*)', attributes=ALL_ATTRIBUTES)
    entries = conn.entries
    assert len(entries) > 0

def test_ldap_search_retest(mock_connection):
    conn = mock_connection
    conn.search('cn=monitor', '(objectClass=*)', attributes=ALL_ATTRIBUTES)
    entries = conn.entries
    assert len(entries) == 0


def test_ldap_connection_parameters(mock_connection):
    conn = mock_connection
    assert conn.server.host == 'my_fake_server'
    assert conn.server.port is not None
    assert conn.user == 'cn=admin,dc=example,dc=com'
    assert conn.password == 'password'