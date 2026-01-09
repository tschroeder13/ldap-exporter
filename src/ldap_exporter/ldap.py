import logging
import re
import ssl
import threading
import time
from ldap3 import ALL, SYNC, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

# Create a logger for this module
logger = logging.getLogger(__name__)

class LdapClient:
    """
    This LDAP client is for searching a single LDAP server for meaningful monitoring value
    """
    def __init__(self, host, port, user, password, ca_cert=None, 
                 refresh_interval=60, searchbase=None, 
                 searchfilter=None, attributes=None,
                 connection=None):
        """Create LDAP Client

        Args:
            host (str): hostname
            port (int): port
            user (str): Bind DN to access LDAP server
            password (str): Bind password
            ca_cert (str, optional): public key of CA cert in PEM format. Defaults to None.
            refresh_interval (int, optional): Time in seconds to refresh metrics from directory service. Defaults to None.
            searchbase (str, optional): The base DN for the search. Defaults to None.
            searchfilter (str, optional): The filter to apply to the search. Defaults to None.
            attributes (list, optional): The attributes to retrieve. Defaults to None.
            connection (ldap3.Connection, optional): An existing ldap3 Connection object for testing purpose. Defaults to None.
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.ca_cert = ca_cert
        self.searchbase = searchbase
        self.searchfilter = searchfilter
        self.attributes = attributes
        self._cache = None
        self._cache_lock = threading.Lock()
        if connection is not None and isinstance(connection, Connection):
            self.connection = connection
        else:
            self.connection = self._connect()
        self._refresh_interval = refresh_interval
        self._stop_event = threading.Event()
        self._refresh_thread = threading.Thread(
            target=self._periodic_refresh, daemon=True)
        self._refresh_thread.start()

    def __del__(self):
        try:
            self._stop_event.set()
            if hasattr(self, '_refresh_thread') and self._refresh_thread.is_alive():
                self._refresh_thread.join(timeout=2)
            if hasattr(self, 'connection') and self.connection is not None:
                self.connection.unbind()
            logger.debug("LdapClient cleanup completed successfully")
        except Exception as e:
            logger.exception("Error during LdapClient cleanup")
            raise Exception from e

    def _update_cache(self):
        self.connection.search(search_base=self.searchbase,
                               search_filter=self.searchfilter,
                               attributes=self.attributes)
        new_cache = {}
        hostname = self.connection.server.host
        bound = self.connection.bound
        new_cache["Monitor.Connection"]={"hostname": hostname, "bound": bound}
        for entry in self.connection.entries:
            entry_dict = entry.entry_attributes_as_dict
            self._unravel_values(entry_dict)
            new_cache[self._dn_to_metric_name(entry.entry_dn)] = entry_dict

        with self._cache_lock:
            self._cache = dict(sorted(new_cache.items()))
        logger.debug("LDAP cache updated")
        return new_cache

    def _unravel_values(self, values: dict):
        """Process ldap result for further use in Prometheus exporter.
        unmarshall single value attributes, keep numeric attributes, 
        decode bytes to string, ignore objectclass attribute.

        Args:
            values (dict): _description_
        """
        tmp_dict = {}
        for key, val in values.items():
            ### Skip objectclass attribute
            if key == "objectclass":
                continue
            ### Unravel single value lists
            val = val[0] if isinstance(val, list) and len(val) == 1 else val
            if isinstance(val, str):
                tmp_dict[key] = val
            ### Keep numeric values as is
            elif isinstance(val, (int, float)):
                tmp_dict[key] = val
            ### Decode bytes to utf-8 string
            elif isinstance(val, bytes):
                try:
                    tmp_dict[key] = val.decode('utf-8')
                except UnicodeDecodeError:
                    tmp_dict[key] = val
            ### forward the rest as is - e.g. multivalued attributes
            else:
                tmp_dict[key] = val

        values.clear()
        values.update(tmp_dict)

    def _dn_to_metric_name(self, dn):
        """Convert DN to metric name by reversing the order and replacing spaces with underscores.
        Args:
            dn (str): Distinguished Name
        Returns:
            str: Metric name
        """
        # Split by comma, reverse, and extract the value after '='
        try:
            parts = [re.sub(r'cn=', '', p) for p in dn.split(',')]
        except IndexError as exc:
            raise IndexError(f"Invalid DN format: {dn}") from exc
        parts = parts[::-1]
        # Replace spaces with underscores in each part
        parts = [re.sub(r'\s+', '_', p) for p in parts]
        # Join with dots
        return '.'.join(parts)

    def get_cached_results(self):
        """Get search result from cache

        Returns:
            dictionary: Search result as dictionary
        """
        with self._cache_lock:
            cache = self._cache
        if cache is None:
            cache = self._update_cache()
        return cache

    def _periodic_refresh(self):
        """Refresh cache values according to the refresh interval

        """
        while not self._stop_event.is_set():
            try:
                if self.connection.bound:
                    self._update_cache()
                else:
                    self.connection = self._connect()
                    self._update_cache()
            except Exception:
                pass
            time.sleep(self._refresh_interval)

    def _connect(self):
        """Establish an LDAP Connection

        Raises:
            LDAPException: _description_

        Returns:
            _type_: ldap3.Connection
        """
        try:
            if self.ca_cert is not None:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                ctx.verify_mode = ssl.CERT_REQUIRED
                tls = Tls(ca_certs_data=self.ca_cert,
                        ciphers=('AES256-GCM-SHA384'),
                        validate=ssl.CERT_REQUIRED,
                        version=ssl.PROTOCOL_TLSv1_2)
                s = Server(host=self.host,
                        port=self.port,
                        use_ssl=True,
                        get_info=ALL,
                        tls=tls)
            else:
                s = Server(host=self.host,
                        port=self.port,
                        use_ssl=False,
                        get_info=ALL)
            con = Connection(server=s,
                            user=self.user,
                            password=self.password,
                            auto_bind=True,
                            client_strategy=SYNC)
            return con
        except LDAPException as e:
            self._cache["Monitor.Connection"]={"hostname": s.host, "bound": con.bound if con else False, "msg": str(e)}
            logger.exception("Failed to connect to LDAP server: %s", e)
            raise LDAPException from e
