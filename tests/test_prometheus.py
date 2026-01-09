import pytest
import yaml
# from unittest.mock import MagicMock, Mock, patch
from datetime import datetime, timezone

from src.ldap_exporter.prometheus import LdapCollector
from src.ldap_exporter.ldap import LdapClient

@pytest.fixture(name="ldap_params", scope="session")
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

@pytest.fixture(name="mock_ldap_client", scope="session")
def mock_ldap_client_fixture(ldap_params):
    """Create a mock LDAP client."""
    yield LdapClient(**ldap_params)

@pytest.fixture(name="prometheus_yaml", scope="session")
def prometheus_yaml_str():
    """YAML string for Prometheus configuration."""
    return """prometheus:
  enabled: true
  address: "0.0.0.0"
  port: 9100
  certfile: "./etc/certfile.crt"
  keyfile: "./etc/keyfile.key"
  metrics_path: "/metrics"
  disable_created: false
  include_metrics:
    - Monitor.Agent.Status
    - Monitor.Agent.Partition
    - Monitor.IDM.EngineVersion
    - Monitor.IDM.driverSet_Stats.*
    - Monitor.IDM.job_stats.*
    - Monitor.RecordManager.*
"""    

@pytest.fixture(name="basic_prometheus_config", scope="session")
def basic_prometheus_config_fixture(prometheus_yaml):
    """Basic configuration for testing."""
    config = yaml.safe_load(prometheus_yaml)
    return config['prometheus']

@pytest.fixture(name="mock_ldap_collector", scope="session")
def ldap_collector_fixture(mock_ldap_client, basic_prometheus_config):
    """Fixture for LdapCollector instance."""
    return LdapCollector(mock_ldap_client, metrics=basic_prometheus_config["include_metrics"])

@pytest.fixture(name="mock_metrics", scope="session")
def mock_metrics_fixture(mock_ldap_collector):
    """Fixture for mock metrics."""
    return list(mock_ldap_collector.collect())

class TestLdapCollectorInitialization:
    """Test LdapCollector initialization."""

    def test_init_basic(self, prometheus_yaml, mock_ldap_collector):
        """Test basic initialization."""
        original_metric = yaml.safe_load(prometheus_yaml)["prometheus"]["include_metrics"]
        has_wildcard = any(metric.endswith('*') for metric in original_metric)
        assert mock_ldap_collector.ldap_client == mock_ldap_collector.ldap_client
        if has_wildcard:
            assert len(mock_ldap_collector.metrics) > len(original_metric)
        else:
            assert len(mock_ldap_collector.metrics) == len(original_metric)            


class TestCollectMethod:
    """Test the collect method."""
    
    def test_init_cn_monitor_collector(self, mock_metrics, mock_ldap_collector):
        """Test initialization of cnMonitor collector."""
        assert mock_ldap_collector.ldap_client == mock_ldap_collector.ldap_client
        assert mock_metrics is not None

    def test_collect_yields_collector_info(self, mock_metrics):
        """Test that collect yields collector info metric."""
        # collector_sate = next(iter(mock_metrics))
        name = "cnMonitor_collector"
        metric = [m for m in mock_metrics if m.name == name][0]
        if metric: mock_metrics.remove(metric)
        assert metric.name == name
        assert metric.documentation
        assert metric.samples[0].labels["status"] == "running"

    def test_collect_yields_total_entries(self, mock_metrics):
        """Test that collect yields total entries metric."""
        name = "cnMonitor_entries_total"
        metric = [m for m in mock_metrics if m.name == name][0]
        if metric: mock_metrics.remove(metric)
        assert metric.name == name
        assert metric.documentation
        value = metric.samples[0].value
        assert value is not None
        assert isinstance(value, (int, float))
        assert value > 0

    def test_collect_yields_connection_info(self, mock_metrics, basic_ldap_params):
        """Test that collect yields connection info metric."""
        name = "cnMonitor_Connection"
        metric = [m for m in mock_metrics if m.name == name][0]
        if metric: mock_metrics.remove(metric)
        assert metric.name == "cnMonitor_Connection"
        assert metric.documentation
        assert metric.samples[0].labels["MetricName"] == "Monitor.Connection"
        assert metric.samples[0].labels["hostname"] == basic_ldap_params["host"]
        assert metric.samples[0].labels["bound"]  

    def test_collect_with_driverset_stats(self, mock_metrics, mock_ldap_client):
        # TODO: why are some suffixed with count and some not?
        """Test collect with driverSet stats metrics."""
        names = ['cnMonitor_IDM_driverSet_Stats_numberOfDrivers',
                 'cnMonitor_IDM_driverSet_Stats_starting',
                 'cnMonitor_IDM_driverSet_Stats_stopped',
                 'cnMonitor_IDM_driverSet_Stats_running',
                 'cnMonitor_IDM_driverSet_Stats_shutDownPending',
                 'cnMonitor_IDM_driverSet_Stats_startUpOption_disabled_count',
                 'cnMonitor_IDM_driverSet_Stats_startUpOption_manual_count',
                 'cnMonitor_IDM_driverSet_Stats_startUpOption_auto-start_count',
                 ]
        entry = mock_ldap_client.get_cached_results().get("Monitor.IDM.driverSet_Stats")
        for name in names:
            orig_value = float(entry.get(name.split("cnMonitor_IDM_driverSet_Stats_")[-1]))
            metric = [m for m in mock_metrics if m.name == name][0]
            if metric: mock_metrics.remove(metric)
            assert metric is not None
            assert metric.name == name
            assert metric.documentation
            value = metric.samples[0].value
            assert value is not None
            assert isinstance(value, (int, float))
            assert value == orig_value

    def test_collect_with_driver_metrics(self, mock_metrics):
        """Test collect with individual driver metrics."""
        prefix = 'cnMonitor_IDM_driverSet_Stats_drivers_'
        driver_metrics = [m for m in mock_metrics if m.name.startswith(prefix)]
        for metric in driver_metrics:
            if metric: mock_metrics.remove(metric)
            assert metric is not None
            assert metric.name.startswith(prefix)
            assert metric.documentation

    def test_collect_with_job_stats(self,mock_metrics):
        """Test collect with job stats metrics."""
        prefix = 'cnMonitor_IDM_job_stats'
        job_metrics = [m for m in mock_metrics if m.name.startswith(prefix)]
        for metric in job_metrics:
            if metric: mock_metrics.remove(metric)
            assert metric is not None
            assert metric.name.startswith(prefix)
            assert metric.documentation
        

    def test_collect_with_partition_metrics(self, mock_metrics):
        """Test collect with partition metrics."""
        prefix = 'cnMonitor_Agent_Partition_'
        partition_metrics = [m for m in mock_metrics if m.name.startswith(prefix)]
        for metric in partition_metrics:
            if metric: mock_metrics.remove(metric)
            assert metric is not None
            assert metric.name.startswith(prefix)
            assert metric.documentation


