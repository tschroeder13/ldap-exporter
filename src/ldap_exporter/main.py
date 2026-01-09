import json
import logging
import logging.config
import logging.handlers
import os
import sys
import argparse

import yaml
from prometheus_client import REGISTRY, start_http_server

from .ldap import LdapClient
from .ldap_mock import MockLdapClient
from .prometheus import LdapCollector

APP_NAME = "ldap_exporter"
parser = argparse.ArgumentParser(description="LDAP Exporter")
parser.add_argument('--config', type=str, required=True, help="Path to the configuration file")
args = parser.parse_args()

CONFIG = args.config
logger = logging.getLogger(APP_NAME)
logging.log(logging.DEBUG, "Application Logger created for %s", APP_NAME)

def run_ldap_exporter(ldap_client: LdapClient, prometheus_config: dict):
    ldap_collector = LdapCollector(ldap_client, metrics=prometheus_config["include_metrics"])
    address = str(prometheus_config.get('address', '0.0.0.0'))
    port = int(prometheus_config.get('port', 9100))
    certfile = str(prometheus_config.get('certfile'))
    keyfile = str(prometheus_config.get('keyfile'))
    logger.debug(f"Prometheus exporter will start on address: {address}, port: {port}")
    if (os.path.exists(certfile) 
        and os.path.exists(keyfile)):
        logger.debug("Starting HTTPS Prometheus HTTP server")
        start_http_server(port, addr=address,
                        certfile=certfile,
                        keyfile=keyfile)
    else:
        logger.debug("Starting HTTP Prometheus HTTP server")
        start_http_server(port, addr=address)
    REGISTRY.register(ldap_collector)
    logger.debug("Registered LdapCollector with Prometheus REGISTRY")

def run_mock_ldap_client(mock_config: dict):
    logger.debug("Initialized LdapClient (Mockup)")
    return MockLdapClient(filepath=os.path.abspath(mock_config.get('file', './ldap_results.json')))

def init_ldap_client(ldap_config: dict):
    logger.debug("Initialized LdapClient")
    return LdapClient(host=ldap_config['host'],
                            port=ldap_config['port'],
                            user=ldap_config['bind_dn'],
                            password=ldap_config['bind_pw'],
                            ca_cert=ldap_config['ca_cert'])
    
def write_mock_data(ldap_config: dict, mock_config: dict):
    ldap_client = init_ldap_client(ldap_config)
    result = ldap_client.get_cached_results()  # Initial cache population
    file = mock_config.get('file', './ldap_results.json')
    logger.debug(f"Writing LDAP results to {file}")
    with open(file, 'w', encoding='utf-8') as f:
        f.write(json.dumps(result, indent=4, ensure_ascii=False))
    logger.debug(f"LDAP results have been written to {file}")


def main(config_file):
    config_path = os.path.abspath(config_file)
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    logging.config.dictConfig(config.get('logging', {}))
    logger.debug(f"Loaded configuration: {config_path}")
    
    if config.get('ldap', {}).get('enabled', False) and config.get('mockup', {}).get('enabled', False):
        logger.error("Both LDAP and Mockup modes are enabled. Please enable only one mode at a time.")
        sys.exit(1)
    if config.get('mockup', {}).get('enabled', False):
        mock_config = config['mockup']
        if mock_config.get('mode', 'write') == 'write':
            write_mock_data(ldap_config=config['ldap'], mock_config=mock_config)
            logger.info("Mockup mode: wrote LDAP results to file")
            sys.exit(0)
        else:
            ldap_client = run_mock_ldap_client(mock_config=config['mockup'])
            run_ldap_exporter(ldap_client=ldap_client, prometheus_config=config['prometheus'])
            logger.info("Running in mockup mode with MockLdapClient")
    elif config.get('ldap', {}).get('enabled', False) and config.get('prometheus', {}).get('enabled', False):
        ldap_client = init_ldap_client(config['ldap'])
        run_ldap_exporter(ldap_client=ldap_client, prometheus_config=config['prometheus'])
        logger.info("Running LDAP Prometheus Exporter")
    
    
    # Keep the main thread alive to allow background threads to run
    import time
    while True:
        time.sleep(1)

if __name__ == '__main__':
    # main(r'../etc/cnmonitor_exporter/ldap_exporter_idv1.yaml')
    main(CONFIG)

