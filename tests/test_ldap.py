import pytest
from src.ldap_exporter.ldap import LdapClient

@pytest.fixture(name="ldap_params", scope="function")
def ldap_params_fixture(basic_ldap_params, extended_mock_cn_monitor):
    """Fixture to provide LDAP parameters for testing."""
    return {
        **basic_ldap_params,
        "refresh_interval": 30,
        "searchbase": "cn=monitor",
        "searchfilter": "(objectClass=*)",
        "attributes": ['*', '+'],
        "connection": extended_mock_cn_monitor
    }

class TestLdapClientInitialization:
    """Test LdapClient initialization."""

    def test_init_basic(self, basic_ldap_params, mock_connection):
        """Test basic initialization without SSL."""
        connection = mock_connection
        client = LdapClient(host=basic_ldap_params["host"],
                            port=basic_ldap_params["port"],
                            user=basic_ldap_params["user"],
                            password=basic_ldap_params["password"],
                            connection=connection)
        
        assert client.connection.server.host == basic_ldap_params["host"]
        assert client.connection.server.port == basic_ldap_params["port"]
        assert client.connection.bound is True
        assert client.ca_cert is None
        assert client.searchbase is None
        assert client.searchfilter is None
        assert client.attributes is None
        

    def test_init_custom_search_params(self, ldap_params):
        """Test initialization with custom search parameters."""
        client = LdapClient(**ldap_params)
        assert client.connection.server.host == ldap_params["host"]
        assert client.connection.server.port == ldap_params["port"]
        assert client.user == ldap_params["user"]
        assert client.password == ldap_params["password"]
        assert client.ca_cert is None
        assert client.searchbase == ldap_params["searchbase"]
        assert client.searchfilter == ldap_params["searchfilter"]
        assert client.attributes == ldap_params["attributes"]
        assert client.connection.bound is True
        assert client.connection.version == 3
        assert client.get_cached_results() is not None

    def test_get_cached_results(self, ldap_params):
        """Test retrieval of cached LDAP results."""
        client = LdapClient(**ldap_params)
        result = client.get_cached_results()
        assert "Monitor.Connection" in result.keys() # generated value for client
        assert all(not key.startswith("cn=") for key in result.keys())
        assert result is not None

