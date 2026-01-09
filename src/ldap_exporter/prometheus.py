
"""
This module provides a custom Prometheus collector for scraping metrics from an LDAP search.
The `LdapCollector` class is designed to integrate with the Prometheus Python client library
and expose LDAP metrics in a format that Prometheus can scrape. It supports dynamic metric
extension based on wildcard patterns and handles various data types, including integers, floats,
strings, booleans, and timestamps.
Key Features:
- Converts LDAP metrics with units (e.g., KB, MB, seconds) into standardized formats.
- Dynamically extends metrics based on wildcard patterns in the metric names.
- Handles various LDAP data types, including timestamps, durations, and numerical values.
- Provides Prometheus `GaugeMetricFamily` and `InfoMetricFamily` for exposing metrics.
Usage:
- Instantiate the `LdapCollector` with an LDAP client and a list of metrics to monitor.
- Register the collector with the Prometheus client library to expose metrics.
Dependencies:
- `prometheus_client`: Used for creating and exposing Prometheus metrics.
- `datetime`, `re`, `logging`: Used for data parsing, logging, and time handling.
"""
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Union, Optional, List
from prometheus_client.core import GaugeMetricFamily, InfoMetricFamily
from prometheus_client.registry import Collector


# Create a logger for this module
logger = logging.getLogger(__name__)

si_base_units = {
    'time': 'seconds',
    'seconds': 'seconds',
    'ms': 'seconds',
    'milliseconds': 'seconds',
    'byte': 'bytes',
    'bytes': 'bytes',
    'kb': 'bytes',
    'kib': 'bytes',
    'kilobytes': 'bytes',
    'mb': 'bytes',
    'megabytes': 'bytes',
    'gb': 'bytes',
    'gigabytes': 'bytes',
    'tb': 'bytes',
    'terabytes': 'bytes',
}
si_unit_factor = {
    'days': 86400,
    'day': 86400,
    'd': 86400,
    'hours': 3600,
    'hour': 3600,
    'h': 3600,
    'min': 60,
    'minutes': 60,
    'minute': 60,
    's': 1,
    'seconds': 1,
    'second': 1,
    'ms': 0.001,
    'milliseconds': 0.001,
    'millisecond': 0.001,
    'byte': 1,
    'bytes': 1,
    'kb': 1024,
    'kib': 1024,
    'kilobytes': 1024,
    'mb': 1024 * 1024,
    'megabytes': 1024 * 1024,
    'gb': 1024 * 1024 * 1024,
    'gigabytes': 1024 * 1024 * 1024,
    'tb': 1024 * 1024 * 1024 * 1024,
    'terabytes': 1024 * 1024 * 1024 * 1024,
}
driver_states = {
    'unknown': -1,
    'running': 1,
    'stopped': 0,
    'starting': 2,
    'shutting down': 3,
}
start_options = {
    'disabled': 0,
    'manual': 1,
    'autostart': 2,
}
types = {
    'unknown': -1,
    'none': 0,
    'remote': 1,
    'local': 2,
}
job_stats_configurations = {
    'unknown': -1,
    'disabled': 0,
    'enabled': 1,
}
job_stats_states = {
    'unknown': -1,
    'stopped': 0,
    'running': 1,
    'started': 1,
}
jvm_stats_states = {
    'unknown': -1,
    'NEW': 0,
    'TIMED_WAITING':1,
    'WAITING': 2,
    'RUNNABLE': 3
}

class LdapCollector(Collector):
    """
    Custom Prometheus collector that scrapes metrics from an LDAP search.
    """


    def __init__(self, ldap_client, metrics=None):
        logger.debug("Initializing LdapCollector")
        self.ldap_client = ldap_client
        self.metrics = metrics
        self._extend_metrics(ldap_results=ldap_client.get_cached_results())

    def collect(self):
        logger.debug(f"Collecting {len(self.metrics)} metrics from LDAP")
        yield InfoMetricFamily(name='cnMonitor_collector',
                               documentation='Information about the cnMonitor LDAP Collector',
                               value={'status': 'running'})
        # # Example LDAP search (replace with actual implementation)
        ldap_results = self.ldap_client.get_cached_results()

        # # Example metric: total entries found
        total_entries = len(ldap_results)
        g_total = GaugeMetricFamily(name='cnMonitor_entries_total', documentation='Total cnMonitor entries found')
        g_total.add_metric([], total_entries)
        yield g_total

        con_info = ldap_results.get("Monitor.Connection", {"hostname": "n/a", "bound": False, "status": "n/a"})
        yield self._generate_pure_info_metric(
            metric_name="Monitor.Connection",
            typed_entry_dict=self._typed_entries_from_entry_dict(con_info)
        )

        for metric in self.metrics:
            # #  err="unit \"KB\" not a suffix of metric \"cnMonitor_RecordManager_CacheStatistics_CurrentSize_EntryCacheSize\""
            metric_name = metric
            found = ldap_results.get(metric, None)
            if found:
                typed_entry_dict = self._typed_entries_from_entry_dict(entry_dict=found)
                if metric == "Monitor.IDM.driverSet_Stats":
                    yield from self._generate_driverSet_metrics(metric, metric_name, typed_entry_dict)

                elif ("driverSet_Stats.drivers" in metric 
                    and len(metric.split('.')) == 5):
                    yield from self._generate_driver_metrics(metric, metric_name, typed_entry_dict)
                    # continue
                elif ("job_stats" in metric):
                    yield from self._generate_job_stats_metrics(metric, metric_name, typed_entry_dict)
                
                elif (metric == "Monitor.Agent.Partition"):
                    yield from self._generate_partition_metrics(metric, metric_name, typed_entry_dict)

                elif 'Monitor.IDM.jvm_stats.runtime_stats.system_properties' == metric:
                        yield self._generate_pure_info_metric(
                            metric_name=metric,
                            typed_entry_dict=typed_entry_dict
                        )
                else:
                    yield from self._generate_generic_metrics(metric, metric_name, typed_entry_dict)

    def _generate_partition_metrics(self, metric: str, metric_name: str, typed_entry_dict: Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]):
        for key, (val_type, val, *_) in typed_entry_dict.items():
            unit = "seconds" if key.lower() == "maxringdelta" else "total"
            if val_type == 'list' and any('#' in item for item in val):
                for item in val:
                    if '#' in item:
                        parts = item.split('#', 1)
                        partition_name = self._convert_partition_dn(parts[0])
                        partition_value = parts[1]
                        g = GaugeMetricFamily(
                            name=f'cn{metric.replace(".", "_")}_{key}_{partition_name}_{unit}',
                            documentation=f'cnMonitor partition metric for {metric} - {key} - {partition_name}',
                            labels=['MetricName', 'Submetric','Partition']
                        )
                        g.unit = unit
                        g.add_metric(labels=[metric_name, key, partition_name], value=float(partition_value) if partition_value.isdigit() else 0)
                        yield g

    def _generate_generic_metrics(self, metric: str, metric_name: str, typed_entry_dict: Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]):
        non_string_entries = {key: val for key, val in typed_entry_dict.items() if val[0] not in ('str', 'error')}
        for key, (val_type, val, *unit) in non_string_entries.items():
            if unit:
                suffix = f'_{unit[0]}'
            elif key.lower().endswith('count'):
                suffix = ''
            else:
                suffix = '_total'
            g = GaugeMetricFamily(name=f'cn{metric.replace(".", "_")}_{key}{suffix}',
                                    documentation=f'cnMonitor gauge metric for {metric} - {key}',
                                    labels=['MetricName', 'Submetric'])
            g.unit = unit[0] if unit else ''
            g.add_metric(labels=[metric_name, key],
                            value = float(val))
            yield g
        
        string_entries = {key: val for key, (val_type, val, *_) in typed_entry_dict.items() if val_type == 'str'}
        string_entries['MetricName'] = metric_name
        string_entries = dict(sorted(string_entries.items()))
        label_keys = list(string_entries.keys())
        label_values = [string_entries[k] for k in label_keys]
        i = InfoMetricFamily(name=f'cn{metric.replace(".", "_")}',
                                documentation=f'cnMonitor info metric for {metric}',
                                labels=label_keys
                                )
        i.add_metric(labels=label_values,
                        value = {})
        yield i
    
    def _generate_driverSet_metrics(self, metric: str, metric_name: str, typed_entry_dict: Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]):
        non_string_entries = {key: val for key, val in typed_entry_dict.items() if val[0] not in ('str', 'error')}
        driverset_dn = typed_entry_dict.get('driverSetDN', "n/a")[1]
        for key, val in non_string_entries.items():
            
            g = GaugeMetricFamily(name=f'cn{metric.replace(".", "_")}_{key}',
                                    documentation=f'cnMonitor gauge metric for {metric} - {key}',
                                    labels=['MetricName', 'DriverSetDN'])
            g.unit = val[2][0] if len(val) > 2 and val[2] else None
            g.add_metric(labels=[metric_name, driverset_dn],
                            value=float(val[1]))
            yield g


    def _generate_driver_metrics(self, metric: str, metric_name: str, typed_entry_dict: Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]):
        driver_dn = typed_entry_dict.get('DriverDN', "n/a")[1]
        # i = InfoMetricFamily(name=f'cn{metric.replace(".", "_")}',
        #                                     documentation=f'cnMonitor info metric for {metric}',
        #                                     labels=['DriverDN', 'MetricName']
        #                                     )
        # i.add_metric(labels=[typed_entry_dict.get('DriverDN', "n/a")[1], metric_name], value = {})
        # yield i
        for key, (val_type, val, unit) in typed_entry_dict.items():
            if val_type != 'str':
                doc = ""
                match key.lower():
                    case 'startoption':
                        doc += 'Start option as numeric option: '
                        doc += ",".join([f"{k}: {v}" for k, v in start_options.items()])
                    case 'driver-state':
                        doc += 'Driver state as numeric option: '
                        doc += ",".join([f"{k}: {v}" for k, v in driver_states.items()])
                    case 'type':
                        doc += 'Driver type as numeric option: '
                        doc += ",".join([f"{k}: {v}" for k, v in types.items()])
                    case _:
                        doc = f'cnMonitor driver metric for {metric} - {key}'
                suffix = f'{unit[0]}' if unit else 'total'
                g = GaugeMetricFamily(name=f'cn{metric.replace(".", "_")}_{key}_{suffix}',
                                        documentation=f'cnMonitor gauge metric for {metric} - {key} - {doc}',
                                        labels=['MetricName', 'DriverDN'])
                g.unit = unit[0] if unit else ''
                g.add_metric(labels=[metric_name, driver_dn],
                                value=float(val))
                yield g
    
    def _generate_job_stats_metrics(self, metric: str, metric_name: str, typed_entry_dict: Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]):
        job_dn = typed_entry_dict.get('JobDN', "n/a")[1]
        containment = typed_entry_dict.get("containment", "n/a")[1]
        
        # i = InfoMetricFamily(name=f'cn{metric.replace(".", "_")}',
        #                     documentation=f'cnMonitor info metric for {metric}',
        #                     labels=['JobDN', 'MetricName', "Containment"]
        #                     )
        # i.add_metric(labels=[typed_entry_dict.get('JobDN', "n/a")[1], 
        #                     metric_name, typed_entry_dict.get("containment", "n/a")[1]], 
        #             value = {})
        # yield i
        for key, (val_type, val, unit) in typed_entry_dict.items():
            if val_type != 'str':
                doc = ""
                match key.lower():
                    case 'status':
                        doc += 'Job status as numeric option: '
                        doc += ",".join([f"{k}: {v}" for k, v in job_stats_states.items()])
                    case 'configuration':
                        doc += 'Job configuration as numeric option: '
                        doc += ",".join([f"{k}: {v}" for k, v in job_stats_configurations.items()])
                    case _:
                        doc = f'cnMonitor driver metric for {metric} - {key}'
                suffix = f'{unit[0]}' if unit else 'total'
                g = GaugeMetricFamily(name=f'cn{metric.replace(".", "_")}_{key}_{suffix}',
                                    documentation=f'cnMonitor gauge metric for {metric} - {key} - {doc}',
                                    labels=['MetricName', 'JobDN', 'Containment'])
                g.unit = unit[0] if unit else ''
                g.add_metric(labels=[metric_name, job_dn, containment],
                            value=float(val))
                yield g

    def _generate_pure_info_metric(self, metric_name: str, typed_entry_dict: Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]):
        """
        Generate an InfoMetricFamily for pure string entries.

        Args:
            metric_name (str): The base name of the metric.
            entry_dict (Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]): 
                The LDAP result entry as a dictionary.
        Returns:
            InfoMetricFamily: The generated Info metric.
        """
        string_entries = {key: val[1] for key, val in typed_entry_dict.items()}
        string_entries['MetricName'] = metric_name
        string_entries = dict(sorted(string_entries.items()))
        label_keys = list(string_entries.keys())
        label_values = [str(string_entries[k]) for k in label_keys]
        i = InfoMetricFamily(name=f'cn{metric_name.replace(".", "_")}',
                                documentation=f'cnMonitor info metric for {metric_name}',
                                labels=label_keys
                                )
        i.add_metric(labels=label_values,
                        value = {})
        return i

    def _extend_metrics(self, ldap_results):
        """
        For every wildcarded value in configuration 
        extend the metrics list with available metrics from LDAP result

        Args:
            ldap_results (_type_): The LDAP results to extend metrics with.
        """
        logger.debug("Extending metrics based on wildcard patterns")
        for metric in [item for item in self.metrics if item.endswith('.*')]:
            all_metrics = ldap_results.keys()
            extended_metrics = [
                m for m in all_metrics if m.startswith(metric[:-2])]
            # self.metrics.remove(metric)
            if extended_metrics:
                self.metrics.extend(extended_metrics)

    def _typed_entries_from_entry_dict(self, entry_dict) -> Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]:
        """_summary_

        Args:
            entry_dict (_type_Dictionary): The LDAP result entry as a dictionary.

        Returns:
            Dict[str, Tuple[str, Union[int, float, str, bool], Optional[str]]]: 
            A dictionary containing 
            - a type description (str),
            - the value (int, float, str, bool),
            - and an optional unit (str) 
            for each key in the entry_dict.
        """
        
        result = {}
        for key, val in entry_dict.items():
            try:
                if isinstance(val, str):
                    if key == 'eDirectoryAgentVersion':
                        result[key] = ('str', str(val), 'version')
                        continue
                    elif key == 'eDirectoryUpTime':
                        result[key] = ('time', val,"seconds")
                        continue
                    elif key == 'nextScheduledRun':
                        result[key] = ('time', val, "seconds")
                        continue
                    elif key == 'EngineVersion':
                        result[key] = ('str', str(val),'version')
                        continue
                    elif key.endswith('DN'):
                        result[key] = ('str', str(val), 'dn')
                        continue
                    elif isinstance(val, list) and len(val) > 1 and all(isinstance(item, str) for item in val):
                        result[key] = ('list', val)
                        continue
                    ## is float
                    elif re.match(r'^\d+\.\d+$', val):
                        result[key] = ('float', float(val))
                    ## is int
                    elif re.match(r'^\d+$', val):
                        if 'time' in key.lower():
                            result[key] = ('time', val, "seconds")
                        else:
                            result[key] = ('int', int(val))
                    ## number with unit
                    elif ((match := re.match(r'^([-+]?(?:\d+\.\d+|\d+))\s+(\w+)$', val))
                          and match.group(1).count('.') <= 1):
                        # number, unit = self._ground_metrics(float(match.group(1)) if '.' in match.group(1) else int(match.group(1)), match.group(2))
                        number = float(match.group(1)) if '.' in match.group(1) else int(match.group(1))
                        unit = match.group(2)

                        if isinstance(number, float):
                            result[key] = ('float', float(number * si_unit_factor.get(unit.lower(), 1)), 
                                           si_base_units.get(unit.lower(), unit.lower()))
                        elif isinstance(number, int):
                            result[key] = ('int', int(number * si_unit_factor.get(unit.lower(), 1)), 
                                           si_base_units.get(unit.lower(), unit.lower()))
                        # else:
                        #     result[key] = ('str', val, 'unknown')
                    ## is boolean
                    elif (math := re.match(r'^(true|false)$', val, re.IGNORECASE)):
                        result[key] = ('bool', True if math.group(1).lower() == 'true' else False)
                    ## time values
                    elif ("currtime" in key.lower() or "schedule" in key.lower()):
                        if re.match(r'^\d{14}Z$', val):
                            dt = datetime.strptime(val, '%Y%m%d%H%M%SZ')
                            result[f'{key}'] = ('time', int(dt.timestamp()), "seconds")
                        elif re.match(r'^\d+$', val):  # Check if it's a Unix timestamp
                            dt = datetime.fromtimestamp(int(val), timezone.utc)
                            result[f'{key}'] = ('time', int(dt.timestamp()), "seconds")
                    elif ("uptime" == key.lower() or "downtime" == key.lower()):
                        seconds = 0.0
                        pattern = r'(\d+)\s*(days?|hours?|minutes?|seconds?|milliseconds?)'
                        for value, unit in re.findall(pattern, val):
                            seconds += int(value) * si_unit_factor[unit.lower()]
                        result[key] = ('time', seconds, "seconds")
                    elif "driver-state" == key.lower():
                        result[key] = ('int', driver_states.get(val.lower(), -1), "statenum")
                    elif "startoption" == key.lower():
                        result[key] = ('int', start_options.get(val.lower(), -1), "optionnum")
                    elif "type" == key.lower():
                        result[key] = ('int', types.get(val.lower(), -1), "typnum")
                    elif "status" == key.lower():
                        result[key] = ('int', job_stats_states.get(val.lower(), -1), "statenum")
                    elif "configuration" == key.lower():
                        result[key] = ('int', job_stats_configurations.get(val.lower(), -1), "statenum")
                    elif "state" == key.lower():
                        result[key] = ('int', jvm_stats_states.get(val.lower(), -1), "statenum")
                    else:
                        result[key] = ('str', val, 'unknown')
                else:
                    result[key] = (type(val).__name__, val)
            except Exception as e:
                result[key] = ('error', str(e))
        return result

    def _convert_partition_dn(self, dn: str) -> str:
        """
        Convert a partition DN to a metric-friendly format.

        Args:
            dn (str): The partition DN.

        Returns:
            str: The converted partition name.
        """
        # Remove leading dot if present
        ## .CN=driverset0.O=System.T=IAM-BP-Q
        s = dn.lstrip('.')
        ## CN=driverset0.O=System.T=IAM-BP-Q
        s_parts = [p.split('=')[1].replace('-', '') for p in s.split('.') if '=' in p]
        return '_'.join(map(str, s_parts[::-1]))