import pytest
from ldap3 import Server, Connection, MOCK_SYNC

@pytest.fixture(scope='session')
def basic_ldap_params():
    """Basic parameters for LdapClient initialization."""
    return {
        "host": "my_fake_server",
        "port": 389,
        "user": "cn=admin,dc=example,dc=com",
        "password": "secret"
    }

@pytest.fixture(scope='session')
def mock_server(basic_ldap_params):
    server = Server('my_fake_server', get_info=MOCK_SYNC)
    # server = Server.from_definition(basic_ldap_params["host"], r'tests\ldap_server_info.json', r'tests\ldap_server_schema_ext.json')
    return server

@pytest.fixture(scope='session')
def mock_connection(mock_server, basic_ldap_params):
    connection = Connection(mock_server, 
                            user=basic_ldap_params["user"], 
                            password=basic_ldap_params["password"], 
                            client_strategy=MOCK_SYNC)
    connection.strategy.add_entry(basic_ldap_params['user'], {'userPassword': basic_ldap_params["password"], 'sn': 'Chef', 'revision': 0})
    connection.bind()
    yield connection
    connection.unbind()

@pytest.fixture(scope='session')
def extended_mock_cn_monitor(mock_connection):
    mock_connection.strategy.entries_from_json(r'tests\ldap_dump_cnMonitor.json')
    yield mock_connection  