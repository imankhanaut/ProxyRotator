import json, base64, random, re, sys, threading, time, os, base64, requests
import json, time, socket, socks, shutil, platform, argparse
from urllib.parse import urlparse
from urllib.parse import parse_qs
from urllib.parse import unquote
from subprocess import Popen, PIPE


####################################
# subscription_url = "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt"
subscription_url = "http://37.32.9.181:8000/multiurl.php?urls[]=https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt&urls[]=https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vmess.txt&urls[]=https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/shadowsocks.txt"

listening_socks_port = 7590
subscription_update_time = 3600
####################################
max_samples_batch = 30
min_working_configs = 3
url_test_timeout = 3
config_update_time = 20
apply_fragment = False
####################################
THRD_LOCK = threading.Lock()
INTERRUPT_EVENT = threading.Event()
DEFAULT_PORT = 443
DEFAULT_SECURITY = "auto"
DEFAULT_LEVEL = 8
DEFAULT_NETWORK = "tcp"
DEFAULT_SOCKET = socket.socket
TLS = "tls"
REALITY = "reality"
HTTP = "http"
working_urls_with_pingTime = {}
bestPing = sys.float_info.max
first_time_to_connect = True
listen_to_any = False
treasury_filename = "treasury.db"
use_only_subscription = ""
fragment_interval = "1-5"
fragment_length = "10-50"
fragment_packets = "tlshello"
_black_list = []
####################################
sys.stdin.reconfigure(encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8")


####################################
def is_executable(path):
    """Check if a file is executable (Unix-like systems)."""
    return os.path.isfile(path) and os.access(path, os.X_OK)


def find_xray():
    """Check for 'xray' or 'xray.exe' in local dir or PATH."""
    xray_win = "xray.exe"
    xray_unix = "xray"

    # Check local directory first
    if platform.system() == "Windows":
        if os.path.isfile(xray_win):
            return os.path.abspath(xray_win)
    else:
        if is_executable(xray_unix):
            return os.path.abspath(xray_unix)

    # Check PATH
    for path_dir in os.environ.get("PATH", "").split(os.pathsep):
        if platform.system() == "Windows":
            xray_path = os.path.join(path_dir, xray_win)
            if os.path.isfile(xray_path):
                return xray_path
        else:
            xray_path = os.path.join(path_dir, xray_unix)
            if is_executable(xray_path):
                return xray_path

    return None


from typing import Any, Callable


######################
def run_with_timeout(func: Callable, timeout: float, *args, **kwargs) -> Any:
    """
    Run a function with a timeout. Returns -1 if timeout is reached, else returns the function's result.

    Args:
        func: The function to run.
        timeout: Timeout in seconds.
        *args: Positional arguments to pass to the function.
        **kwargs: Keyword arguments to pass to the function.

    Returns:
        The function's return value or -1 if timeout is reached.
    """
    result = [-1]  # Use a list to allow modification in thread
    event = threading.Event()

    def wrapper():
        try:
            result[0] = func(*args, **kwargs)
        finally:
            event.set()  # Signal that the function has completed

    thread = threading.Thread(target=wrapper)
    thread.daemon = True  # Daemon thread to avoid hanging on exit
    thread.start()

    if not event.wait(timeout):  # Wait for the function to complete or timeout
        return -1
    return result[0]


####################################
import builtins


def print(text):
    try:
        builtins.print(text, flush=True)
    except Exception as e:
        builtins.print(e, flush=True)


####################################
def save_unique_dict_values_to_file(dictionary, filename):
    """
    Save all unique values from a dictionary to a file, checking for existing values.

    Args:
        dictionary (dict): The dictionary whose values should be saved
        filename (str): Path to the file where values should be stored
    """
    global _black_list
    dict_values = set(dictionary.keys())
    existing_values = set()
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            existing_values = set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        pass  # File doesn't exist yet, we'll create it

    new_values = dict_values - existing_values

    if new_values:
        lines = list(new_values)
        lines = [line.strip() for line in lines]
        with open(filename, "a", encoding="utf-8", errors="ignore") as f:
            try:
                _lines = f.readlines()
                _lines = [line.strip() for line in _lines]
                if _lines not in _black_list:
                    lines.extend(_lines)
            except:
                pass
            for item in lines:
                f.write(f"{item}\n")
        _black_list = []
        print(f"Added {len(new_values)} new values to {filename}")
    else:
        print("No new values to add - all values already exist in the file")


###########################
def create_dict_from_file(filename, constant_value=50000):
    """
    Read values from a file and create a dictionary with these values as keys
    and a constant value for all entries.

    Args:
        filename (str): Path to the file containing the values
        constant_value: The constant value to assign to all keys (default 5000)

    Returns:
        dict: Dictionary with file values as keys and constant_value as values
    """
    result_dict = {}

    try:
        with open(filename, "r", errors="ignore") as f:
            for line in f:
                # Strip whitespace and skip empty lines
                value = line.strip()
                if value:
                    result_dict[value] = constant_value

        print(f"Successfully created dictionary with {len(result_dict)} keys")
        return result_dict

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        return {}
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return {}


###########################


class EConfigType:
    class VMESS:
        protocolScheme = "vmess://"
        protocolName = "vmess"

    class CUSTOM:
        protocolScheme = ""
        protocolName = ""

    class SHADOWSOCKS:
        protocolScheme = "ss://"
        protocolName = "ss"

    class SOCKS:
        protocolScheme = "socks://"
        protocolName = "socks"

    class VLESS:
        protocolScheme = "vless://"
        protocolName = "vless"

    class TROJAN:
        protocolScheme = "trojan://"
        protocolName = "trojan"

    class WIREGUARD:
        protocolScheme = "wireguard://"
        protocolName = "wireguard"

    class FREEDOM:
        protocolScheme = "freedom://"
        protocolName = "freedom"

    class BLACKHOLE:
        protocolScheme = "blackhole://"
        protocolName = "blackhole"


class DomainStrategy:
    AsIs = "AsIs"
    UseIp = "UseIp"
    IpIfNonMatch = "IpIfNonMatch"
    IpOnDemand = "IpOnDemand"


class Fingerprint:
    randomized = "randomized"
    randomizedalpn = "randomizedalpn"
    randomizednoalpn = "randomizednoalpn"
    firefox_auto = "firefox_auto"
    chrome_auto = "chrome_auto"
    ios_auto = "ios_auto"
    android_11_okhttp = "android_11_okhttp"
    edge_auto = "edge_auto"
    safari_auto = "safari_auto"
    _360_auto = "360_auto"
    qq_auto = "qq_auto"


class LogBean:
    access: str
    error: str
    loglevel: str
    dnsLog: bool

    def __init__(self, access: str, error: str, loglevel: str, dnsLog: bool) -> None:
        self.access = access
        self.error = error
        self.loglevel = loglevel
        self.dnsLog = dnsLog


class InboundBean:
    class SniffingBean:
        enabled: bool
        destOverride: list[str]  # str
        metadataOnly: bool

        def __init__(
            self, enabled: bool, destOverride: list[str], metadataOnly: bool
        ) -> None:
            self.enabled = enabled
            self.destOverride = destOverride
            self.metadataOnly = metadataOnly

    class InSettingsBean:
        auth: str = None
        udp: bool = None
        userLevel: int = None
        address: str = None
        port: int = None
        network: str = None

        def __init__(
            self,
            auth: str = None,
            udp: bool = None,
            userLevel: int = None,
            address: str = None,
            port: int = None,
            network: str = None,
        ) -> None:
            self.auth = auth
            self.udp = udp
            self.userLevel = userLevel
            self.address = address
            self.port = port
            self.network = network

    tag: str
    port: int
    protocol: str
    listen: str
    settings: any
    sniffing: SniffingBean
    streamSettings: any
    allocate: any

    def __init__(
        self,
        tag: str,
        port: int,
        protocol: str,
        listen: str,
        settings: any,
        sniffing: SniffingBean,
        streamSettings: any,
        allocate: any,
    ) -> None:
        self.tag = tag
        self.port = port
        self.protocol = protocol
        self.listen = listen
        self.settings = settings
        self.sniffing = sniffing
        self.streamSettings = streamSettings
        self.allocate = allocate


class OutboundBean:
    class OutSettingsBean:
        class VnextBean:
            class UsersBean:
                id: str = ""
                alterId: int = None
                security: str = DEFAULT_SECURITY
                level: int = DEFAULT_LEVEL
                encryption: str = ""
                flow: str = ""

                def __init__(
                    self,
                    id: str = "",
                    alterId: int = None,
                    security: str = DEFAULT_SECURITY,
                    level: int = DEFAULT_LEVEL,
                    encryption: str = "",
                    flow: str = "",
                ) -> None:
                    self.id = id
                    self.alterId = alterId
                    self.security = security
                    self.level = level
                    self.encryption = encryption
                    self.flow = flow

            address: str = ""
            port: int = DEFAULT_PORT
            users: list[UsersBean]  # UsersBean

            def __init__(
                self,
                address: str = "",
                port: int = DEFAULT_PORT,
                users: list[UsersBean] = [],
            ) -> None:
                self.address = address
                self.port = port
                self.users = users

        class ServersBean:
            class SocksUsersBean:
                user: str = ""
                # @SerializedName("pass")
                _pass: str = ""
                level: int = DEFAULT_LEVEL

                def __init__(
                    self, user: str = "", _pass: str = "", level: int = DEFAULT_LEVEL
                ) -> None:
                    self.user = user
                    self._pass = _pass
                    self.level = level

            address: str = ""
            method: str = "chacha20-poly1305"
            ota: bool = False
            password: str = ""
            port: int = DEFAULT_PORT
            level: int = DEFAULT_LEVEL
            email: str = None
            flow: str = None
            ivCheck: bool = None
            users: list[SocksUsersBean] = None  # SocksUsersBean

            def __init__(
                self,
                address: str = "",
                method: str = "chacha20-poly1305",
                ota: bool = False,
                password: str = "",
                port: int = DEFAULT_PORT,
                level: int = DEFAULT_LEVEL,
                email: str = None,
                flow: str = None,
                ivCheck: bool = None,
                users: list[SocksUsersBean] = None,
            ) -> None:
                self.address = address
                self.method = method
                self.ota = ota
                self.password = password
                self.port = port
                self.level = level
                self.email = email
                self.flow = flow
                self.ivCheck = ivCheck
                self.users = users

        class Response:
            type: str

            def __init__(self, type: str) -> None:
                self.type = type

        class WireGuardBean:
            publicKey: str = ""
            endpoint: str = ""

            def __init__(self, publicKey: str = "", endpoint: str = "") -> None:
                self.publicKey = publicKey
                self.endpoint = endpoint

        vnext: list[VnextBean] = None  # VnextBean
        servers: list[ServersBean] = None  # ServersBean
        response: Response = None
        network: str = None
        address: str = None
        port: int = None
        domainStrategy: str = None
        redirect: str = None
        userLevel: int = None
        inboundTag: str = None
        secretKey: str = None
        peers: list[WireGuardBean] = None  # WireGuardBean

        def __init__(
            self,
            vnext: list[VnextBean] = None,
            servers: list[ServersBean] = None,
            response: Response = None,
            network: str = None,
            address: str = None,
            port: int = None,
            domainStrategy: str = None,
            redirect: str = None,
            userLevel: int = None,
            inboundTag: str = None,
            secretKey: str = None,
            peers: list[WireGuardBean] = None,
        ) -> None:
            self.vnext = vnext
            self.servers = servers
            self.response = response
            self.network = network
            self.address = address
            self.port = port
            self.domainStrategy = domainStrategy
            self.redirect = redirect
            self.userLevel = userLevel
            self.inboundTag = inboundTag
            self.secretKey = secretKey
            self.peers = peers

    class StreamSettingsBean:

        class TcpSettingsBean:
            class HeaderBean:
                class RequestBean:
                    class HeadersBean:
                        Host: list[str] = []  # str
                        # @SerializedName("User-Agent")
                        userAgent: list[str] = None  # str
                        # @SerializedName("Accept-Encoding")
                        acceptEncoding: list[str] = None  # str
                        Connection: list[str] = None  # str
                        Pragma: str = None

                        def __init__(
                            self,
                            Host: list[str] = [],
                            userAgent: list[str] = None,
                            acceptEncoding: list[str] = None,
                            Connection: list[str] = None,
                            Pragma: str = None,
                        ) -> None:
                            self.Host = Host
                            self.userAgent = userAgent
                            self.acceptEncoding = acceptEncoding
                            self.Connection = Connection
                            self.Pragma = Pragma

                    path: list[str] = []  # str
                    headers: HeadersBean = HeadersBean()
                    version: str = None
                    method: str = None

                    def __init__(
                        self,
                        path: list[str] = [],
                        headers: HeadersBean = HeadersBean(),
                        version: str = None,
                        method: str = None,
                    ) -> None:
                        self.path = path
                        self.headers = headers
                        self.version = version
                        self.method = method

                type: str = "none"
                request: RequestBean = None

                def __init__(
                    self, type: str = "none", request: RequestBean = None
                ) -> None:
                    self.type = type
                    self.request = request

            header: HeaderBean = HeaderBean()
            acceptProxyProtocol: bool = None

            def __init__(
                self,
                header: HeaderBean = HeaderBean(),
                acceptProxyProtocol: bool = None,
            ) -> None:
                self.header = header
                self.acceptProxyProtocol = acceptProxyProtocol

        class KcpSettingsBean:
            class HeaderBean:
                type: str = "none"

                def __init__(self, type: str = "none") -> None:
                    self.type = type

            mtu: int = 1350
            tti: int = 50
            uplinkCapacity: int = 12
            downlinkCapacity: int = 100
            congestion: bool = False
            readBufferSize: int = 1
            writeBufferSize: int = 1
            header: HeaderBean = HeaderBean()
            seed: str = None

            def __init__(
                self,
                mtu: int = 1350,
                tti: int = 50,
                uplinkCapacity: int = 12,
                downlinkCapacity: int = 100,
                congestion: bool = False,
                readBufferSize: int = 1,
                writeBufferSize: int = 1,
                header: HeaderBean = HeaderBean(),
                seed: str = None,
            ) -> None:
                self.mtu = mtu
                self.tti = tti
                self.uplinkCapacity = uplinkCapacity
                self.downlinkCapacity = downlinkCapacity
                self.congestion = congestion
                self.readBufferSize = readBufferSize
                self.writeBufferSize = writeBufferSize
                self.header = header
                self.seed = seed

        class WsSettingsBean:
            class HeadersBean:
                Host: str = ""

                def __init__(self, Host: str = "") -> None:
                    self.Host = Host

            path: str = ""
            headers: HeadersBean = HeadersBean()
            maxEarlyData: int = None
            useBrowserForwarding: bool = None
            acceptProxyProtocol: bool = None

            def __init__(
                self,
                path: str = "",
                headers: HeadersBean = HeadersBean(),
                maxEarlyData: int = None,
                useBrowserForwarding: bool = None,
                acceptProxyProtocol: bool = None,
            ) -> None:
                self.path = path
                self.headers = headers
                self.maxEarlyData = maxEarlyData
                self.useBrowserForwarding = useBrowserForwarding
                self.acceptProxyProtocol = acceptProxyProtocol

        class HttpSettingsBean:
            host: list[str] = []  # str
            path: str = ""

            def __init__(self, host: list[str] = [], path: str = "") -> None:
                self.host = host
                self.path = path

        class TlsSettingsBean:
            allowInsecure: bool = False
            serverName: str = ""
            alpn: list[str] = None  # str
            minVersion: str = None
            maxVersion: str = None
            preferServerCipherSuites: bool = None
            cipherSuites: str = None
            fingerprint: str = None
            certificates: list[any] = None  # any
            disableSystemRoot: bool = None
            enableSessionResumption: bool = None
            show: bool = False
            publicKey: str = None
            shortId: str = None
            spiderX: str = None

            def __init__(
                self,
                allowInsecure: bool = False,
                serverName: str = "",
                alpn: list[str] = None,
                minVersion: str = None,
                maxVersion: str = None,
                preferServerCipherSuites: bool = None,
                cipherSuites: str = None,
                fingerprint: str = None,
                certificates: list[any] = None,
                disableSystemRoot: bool = None,
                enableSessionResumption: bool = None,
                show: bool = False,
                publicKey: str = None,
                shortId: str = None,
                spiderX: str = None,
            ) -> None:
                self.allowInsecure = allowInsecure
                self.serverName = serverName
                self.alpn = alpn
                self.minVersion = minVersion
                self.maxVersion = maxVersion
                self.preferServerCipherSuites = preferServerCipherSuites
                self.cipherSuites = cipherSuites
                self.fingerprint = fingerprint
                self.certificates = certificates
                self.disableSystemRoot = disableSystemRoot
                self.enableSessionResumption = enableSessionResumption
                self.show = show
                self.publicKey = publicKey
                self.shortId = shortId
                self.spiderX = spiderX

        class QuicSettingBean:
            class HeaderBean:
                type: str = "none"

                def __init__(self, type: str = "none") -> None:
                    self.type = type

            security: str = "none"
            key: str = ""
            header: HeaderBean = HeaderBean()

            def __init__(
                self,
                security: str = "none",
                key: str = "",
                header: HeaderBean = HeaderBean(),
            ) -> None:
                self.security = security
                self.key = key
                self.header = header

        class GrpcSettingsBean:
            serviceName: str = ""
            multiMode: bool = None

            def __init__(self, serviceName: str = "", multiMode: bool = None) -> None:
                self.serviceName = serviceName
                self.multiMode = multiMode

        network: str = DEFAULT_NETWORK
        security: str = ""
        tcpSettings: TcpSettingsBean = None
        kcpSettings: KcpSettingsBean = None
        wsSettings: WsSettingsBean = None
        httpSettings: HttpSettingsBean = None
        tlsSettings: TlsSettingsBean = None
        quicSettings: QuicSettingBean = None
        realitySettings: TlsSettingsBean = None
        grpcSettings: GrpcSettingsBean = None
        dsSettings: any = None
        sockopt: any = None

        def __init__(
            self,
            network: str = DEFAULT_NETWORK,
            security: str = "",
            tcpSettings: TcpSettingsBean = None,
            kcpSettings: KcpSettingsBean = None,
            wsSettings: WsSettingsBean = None,
            httpSettings: HttpSettingsBean = None,
            tlsSettings: TlsSettingsBean = None,
            quicSettings: QuicSettingBean = None,
            realitySettings: TlsSettingsBean = None,
            grpcSettings: GrpcSettingsBean = None,
            dsSettings: any = None,
            sockopt: any = None,
        ) -> None:
            self.network = network
            self.security = security
            self.tcpSettings = tcpSettings
            self.kcpSettings = kcpSettings
            self.wsSettings = wsSettings
            self.httpSettings = httpSettings
            self.tlsSettings = tlsSettings
            self.quicSettings = quicSettings
            self.realitySettings = realitySettings
            self.grpcSettings = grpcSettings
            self.dsSettings = dsSettings
            self.sockopt = sockopt

        def populateTransportSettings(
            self,
            transport: str,
            headerType: str,
            host: str,
            path: str,
            seed: str,
            quicSecurity: str,
            key: str,
            mode: str,
            serviceName: str,
        ) -> str:
            sni = ""
            self.network = transport
            if self.network == "tcp":
                tcpSetting = self.TcpSettingsBean()
                if headerType == HTTP:
                    tcpSetting.header.type = HTTP
                    if host != "" or path != "":
                        requestObj = self.TcpSettingsBean.HeaderBean.RequestBean()
                        requestObj.headers.Host = (
                            "" if host == None else host.split(",")
                        )
                        requestObj.path = "" if path == None else path.split(",")
                        tcpSetting.header.request = requestObj
                        sni = (
                            requestObj.headers.Host[0]
                            if len(requestObj.headers.Host) > 0
                            else sni
                        )
                else:
                    tcpSetting.header.type = "none"
                    sni = host if host != "" else ""
                self.tcpSetting = tcpSetting

            elif self.network == "kcp":
                kcpsetting = self.KcpSettingsBean()
                kcpsetting.header.type = headerType if headerType != None else "none"
                if seed == None or seed == "":
                    kcpsetting.seed = None
                else:
                    kcpsetting.seed = seed
                self.kcpSettings = kcpsetting

            elif self.network == "ws":
                wssetting = self.WsSettingsBean()
                wssetting.headers.Host = host if host != None else ""
                sni = wssetting.headers.Host
                wssetting.path = path if path != None else "/"
                self.wsSettings = wssetting

            elif self.network == "h2" or self.network == "http":
                network = "h2"
                h2Setting = self.HttpSettingsBean()
                h2Setting.host = "" if host == None else host.split(",")
                sni = h2Setting.host[0] if len(h2Setting.host) > 0 else sni
                h2Setting.path = path if path != None else "/"
                self.httpSettings = h2Setting

            elif self.network == "quic":
                quicsetting = self.QuicSettingBean()
                quicsetting.security = quicSecurity if quicSecurity != None else "none"
                quicsetting.key = key if key != None else ""
                quicsetting.header.type = headerType if headerType != None else "none"
                self.quicSettings = quicsetting

            elif self.network == "grpc":
                grpcSetting = self.GrpcSettingsBean()
                grpcSetting.multiMode = mode == "multi"
                grpcSetting.serviceName = serviceName if serviceName != None else ""
                sni = host if host != None else ""
                self.grpcSettings = grpcSetting

            return sni

        def populateTlsSettings(
            self,
            streamSecurity: str,
            allowInsecure: bool,
            sni: str,
            fingerprint: str,
            alpns: str,
            publicKey: str,
            shortId: str,
            spiderX: str,
        ):
            self.security = streamSecurity
            tlsSetting = self.TlsSettingsBean(
                allowInsecure=allowInsecure,
                serverName=sni,
                fingerprint=fingerprint,
                alpn=None if alpns == None or alpns == "" else alpns.split(","),
                publicKey=publicKey,
                shortId=shortId,
                spiderX=spiderX,
            )

            if self.security == TLS:
                self.tlsSettings = tlsSetting
                self.realitySettings = None
            elif self.security == REALITY:
                self.tlsSettings = None
                self.realitySettings = tlsSetting

    class MuxBean:
        enabled: bool
        concurrency: int

        def __init__(self, enabled: bool, concurrency: int = 8):
            self.enabled = enabled
            self.concurrency = concurrency

    tag: str = "proxy"
    protocol: str
    settings: OutSettingsBean = None
    streamSettings: StreamSettingsBean = None
    proxySettings: any = None
    sendThrough: str = None
    mux: MuxBean = MuxBean(False)

    def __init__(
        self,
        tag: str = "proxy",
        protocol: str = None,
        settings: OutSettingsBean = None,
        streamSettings: StreamSettingsBean = None,
        proxySettings: any = None,
        sendThrough: str = None,
        mux: MuxBean = MuxBean(enabled=False),
    ):
        self.tag = tag
        self.protocol = protocol
        self.settings = settings
        self.streamSettings = streamSettings
        self.proxySettings = proxySettings
        self.sendThrough = sendThrough
        self.mux = mux


class DnsBean:
    class ServersBean:
        address: str = ""
        port: int = None
        domains: list[str] = None  # str
        expectIPs: list[str] = None  # str
        clientIp: str = None

        def __init__(
            self,
            address: str = "",
            port: int = None,
            domains: list[str] = None,
            expectIPs: list[str] = None,
            clientIp: str = None,
        ) -> None:
            self.address = address
            self.port = port
            self.domains = domains
            self.expectIPs = expectIPs
            self.clientIp = clientIp

    servers: list[any] = None  # any
    hosts: list = None  # map(str, any)
    clientIp: str = None
    disableCache: bool = None
    queryStrategy: str = None
    tag: str = None

    def __init__(
        self,
        servers: list[any] = None,
        hosts: list = None,
        clientIp: str = None,
        disableCache: bool = None,
        queryStrategy: str = None,
        tag: str = None,
    ) -> None:
        self.servers = servers
        self.hosts = hosts
        self.clientIp = clientIp
        self.disableCache = disableCache
        self.queryStrategy = queryStrategy
        self.tag = tag


class RoutingBean:
    class RulesBean:
        type: str = ""
        ip: list[str] = None  # str
        domain: list[str] = None  # str
        outboundTag: str = ""
        balancerTag: str = None
        port: str = None
        sourcePort: str = None
        network: str = None
        source: list[str] = None  # str
        user: list[str] = None  # str
        inboundTag: list[str] = None  # str
        protocol: list[str] = None  # str
        attrs: str = None
        domainMatcher: str = None

        def __init__(
            self,
            type: str = "",
            ip: list[str] = None,
            domain: list[str] = None,
            outboundTag: str = "",
            balancerTag: str = None,
            port: str = None,
            sourcePort: str = None,
            network: str = None,
            source: list[str] = None,
            user: list[str] = None,
            inboundTag: list[str] = None,
            protocol: list[str] = None,
            attrs: str = None,
            domainMatcher: str = None,
        ) -> None:
            self.type = type
            self.ip = ip
            self.domain = domain
            self.outboundTag = outboundTag
            self.balancerTag = balancerTag
            self.port = port
            self.sourcePort = sourcePort
            self.network = network
            self.source = source
            self.user = user
            self.inboundTag = inboundTag
            self.protocol = protocol
            self.attrs = attrs
            self.domainMatcher = domainMatcher

    domainStrategy: str
    domainMatcher: str = None
    rules: list[RulesBean]  # RulesBean
    balancers: list[any]  # any

    def __init__(
        self,
        domainStrategy: str,
        domainMatcher: str = None,
        rules: list[RulesBean] = [],
        balancers: list[any] = [],
    ) -> None:
        self.domainStrategy = domainStrategy
        self.domainMatcher = domainMatcher
        self.rules = rules
        self.balancers = balancers


class FakednsBean:
    ipPool: str = "198.18.0.0/15"
    poolSize: int = 10000

    def __init__(self, ipPool: str = "198.18.0.0/15", poolSize: int = 10000) -> None:
        self.ipPool = ipPool
        self.poolSize = poolSize


class PolicyBean:
    class LevelBean:
        handshake: int = None
        connIdle: int = None
        uplinkOnly: int = None
        downlinkOnly: int = None
        statsUserUplink: bool = None
        statsUserDownlink: bool = None
        bufferSize: int = None

        def __init__(
            self,
            handshake: int = None,
            connIdle: int = None,
            uplinkOnly: int = None,
            downlinkOnly: int = None,
            statsUserUplink: bool = None,
            statsUserDownlink: bool = None,
            bufferSize: int = None,
        ) -> None:
            self.handshake = handshake
            self.connIdle = connIdle
            self.uplinkOnly = uplinkOnly
            self.downlinkOnly = downlinkOnly
            self.statsUserUplink = statsUserUplink
            self.statsUserDownlink = statsUserDownlink
            self.bufferSize = bufferSize

    levels: list  # map(str, LevelBean)
    system: any = None

    def __init__(self, levels: list, system: any = None) -> None:
        self.levels = levels
        self.system = system


class Comment:
    remark: str = None

    def __init__(self, remark: str = None) -> None:
        self.remark = remark


class V2rayConfig:
    _comment: Comment = None
    stats: any = None
    log: LogBean
    policy: PolicyBean
    inbounds: list[InboundBean]  # InboundBean
    outbounds: list[OutboundBean]  # OutboundBean
    dns: DnsBean
    routing: RoutingBean
    api: any = None
    transport: any = None
    reverse: any = None
    fakedns: any = None
    browserForwarder: any = None

    def __init__(
        self,
        _comment: Comment = None,
        stats: any = None,
        log: LogBean = None,
        policy: PolicyBean = None,
        inbounds: list = None,
        outbounds: list = None,
        dns: DnsBean = None,
        routing: RoutingBean = None,
        api: any = None,
        transport: any = None,
        reverse: any = None,
        fakedns: any = None,
        browserForwarder: any = None,
    ) -> None:
        self.stats = stats
        self._comment = _comment
        self.log = log
        self.policy = policy
        self.inbounds = inbounds
        self.outbounds = outbounds
        self.dns = dns
        self.routing = routing
        self.api = api
        self.transport = transport
        self.reverse = reverse
        self.fakedns = fakedns
        self.browserForwarder = browserForwarder


class VmessQRCode:
    v: str = ""
    ps: str = ""
    add: str = ""
    port: str = ""
    id: str = ""
    aid: str = "0"
    scy: str = ""
    net: str = ""
    type: str = ""
    host: str = ""
    path: str = ""
    tls: str = ""
    sni: str = ""
    alpn: str = ""
    allowInsecure: str = ""

    def __init__(
        self,
        v: str = "",
        ps: str = "",
        add: str = "",
        port: str = "",
        id: str = "",
        aid: str = "0",
        scy: str = "",
        net: str = "",
        type: str = "",
        host: str = "",
        path: str = "",
        tls: str = "",
        sni: str = "",
        alpn: str = "",
        allowInsecure: str = "",
        fp: str = "",
    ):
        self.v = v
        self.ps = ps
        self.add = add
        self.port = port
        self.id = id
        self.aid = aid
        self.scy = scy
        self.net = net
        self.type = type
        self.host = host
        self.path = path
        self.tls = tls
        self.sni = sni
        self.alpn = alpn
        self.allowInsecure = allowInsecure
        self.fp = fp


def remove_nulls(d):
    if isinstance(d, dict):
        for k, v in list(d.items()):
            if v is None:
                del d[k]
            else:
                remove_nulls(v)
    if isinstance(d, list):
        for v in d:
            remove_nulls(v)
    return d


def get_log():
    log = LogBean(access="", error="", loglevel="error", dnsLog=False)
    return log


def get_inbound(port):
    inbound = InboundBean(
        tag="in_proxy",
        port=port,
        protocol=EConfigType.SOCKS.protocolName,
        listen="127.0.0.1" if not listen_to_any else "0.0.0.0",
        settings=InboundBean.InSettingsBean(
            auth="noauth",
            udp=True,
            userLevel=8,
        ),
        sniffing=InboundBean.SniffingBean(
            enabled=False,
            destOverride=None,
            metadataOnly=None,
        ),
        streamSettings=None,
        allocate=None,
    )
    return inbound


def get_outbound_vmess():
    outbound = OutboundBean(
        protocol=EConfigType.VMESS.protocolName,
        settings=OutboundBean.OutSettingsBean(
            vnext=[
                OutboundBean.OutSettingsBean.VnextBean(
                    users=[OutboundBean.OutSettingsBean.VnextBean.UsersBean()],
                ),
            ]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_vless():
    outbound = OutboundBean(
        protocol=EConfigType.VLESS.protocolName,
        settings=OutboundBean.OutSettingsBean(
            vnext=[
                OutboundBean.OutSettingsBean.VnextBean(
                    users=[OutboundBean.OutSettingsBean.VnextBean.UsersBean()],
                ),
            ]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_trojan():
    outbound = OutboundBean(
        protocol=EConfigType.TROJAN.protocolName,
        settings=OutboundBean.OutSettingsBean(
            servers=[OutboundBean.OutSettingsBean.ServersBean()]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def get_outbound_ss():
    outbound = OutboundBean(
        protocol="shadowsocks",
        settings=OutboundBean.OutSettingsBean(
            servers=[OutboundBean.OutSettingsBean.ServersBean()]
        ),
        streamSettings=OutboundBean.StreamSettingsBean(),
    )
    return outbound


def try_resolve_resolve_sip002(str: str, config: OutboundBean):
    try:
        uri = urlparse(str)
        config.remarks = unquote(uri.fragment or "")

        if ":" in uri.username:
            arr_user_info = list(map(str.strip, uri.username.split(":")))
            if len(arr_user_info) != 2:
                return False
            method = arr_user_info[0]
            password = unquote(arr_user_info[1])
        else:
            base64_decode = base64.b64decode(uri.username).decode(
                encoding="utf-8", errors="ignore"
            )
            arr_user_info = list(map(str.strip, base64_decode.split(":")))
            if len(arr_user_info) < 2:
                return False
            method = arr_user_info[0]
            password = base64_decode.split(":", 1)[1]

        server = config.outbound_bean.settings.servers[0]
        server.address = uri.hostname
        server.port = uri.port
        server.password = password
        server.method = method

        return True
    except Exception as e:
        return False


def get_outbound1():
    global apply_fragment, fragment_interval, fragment_length, fragment_packets
    settings = OutboundBean.OutSettingsBean(
        domainStrategy=DomainStrategy.UseIp,
    )
    if apply_fragment:
        settings.fragment = {
            "interval": fragment_interval,
            "length": fragment_length,
            "packets": fragment_packets,
        }
    outbound1 = OutboundBean(
        tag="direct",
        protocol=EConfigType.FREEDOM.protocolName,
        settings=settings,
        mux=None,
    )
    return outbound1


def get_outbound2():
    outbound2 = OutboundBean(
        tag="blackhole",
        protocol=EConfigType.BLACKHOLE.protocolName,
        settings=OutboundBean.OutSettingsBean(),
        mux=None,
    )
    return outbound2


def get_dns(dns_list=["8.8.8.8"]):
    if isinstance(dns_list, str):
        if "," in dns_list:
            dns_list = dns_list.split(",")

    dns = DnsBean(servers=dns_list)
    return dns


def get_routing():
    routing = RoutingBean(domainStrategy=DomainStrategy.UseIp)
    return routing


def generateConfig(config: str, dns_list=["8.8.8.8"], inbound_port=10800):
    allowInsecure = True

    temp = config.split("://")
    protocol = temp[0]
    raw_config = temp[1]

    if protocol == EConfigType.VMESS.protocolName:
        _len = len(raw_config)
        if _len % 4 > 0:
            raw_config += "=" * (4 - _len % 4)

        b64decode = base64.b64decode(raw_config).decode(
            encoding="utf-8", errors="ignore"
        )
        _json = json.loads(b64decode, strict=False)

        vmessQRCode_attributes = list(VmessQRCode.__dict__["__annotations__"].keys())
        for key in list(_json.keys()):
            if key not in vmessQRCode_attributes:
                del _json[key]

        vmessQRCode = VmessQRCode(**_json)

        outbound = get_outbound_vmess()

        vnext = outbound.settings.vnext[0]
        vnext.address = vmessQRCode.add
        vnext.port = (
            int(vmessQRCode.port) if vmessQRCode.port.isdigit() else DEFAULT_PORT
        )

        user = vnext.users[0]
        user.id = vmessQRCode.id
        user.security = vmessQRCode.scy if vmessQRCode.scy != "" else DEFAULT_SECURITY
        user.alterId = int(vmessQRCode.aid) if vmessQRCode.aid.isdigit() else None

        streamSetting = outbound.streamSettings

        sni = streamSetting.populateTransportSettings(
            transport=vmessQRCode.net,
            headerType=vmessQRCode.type,
            host=vmessQRCode.host,
            path=vmessQRCode.path,
            seed=vmessQRCode.path,
            quicSecurity=vmessQRCode.host,
            key=vmessQRCode.path,
            mode=vmessQRCode.type,
            serviceName=vmessQRCode.path,
        )

        fingerprint = (
            vmessQRCode.fp
            if vmessQRCode.fp
            else (
                streamSetting.tlsSettings.fingerprint
                if streamSetting.tlsSettings
                else None
            )
        )

        streamSetting.populateTlsSettings(
            streamSecurity=vmessQRCode.tls,
            allowInsecure=allowInsecure,
            sni=sni if vmessQRCode.sni == "" else vmessQRCode.sni,
            fingerprint=fingerprint,
            alpns=vmessQRCode.alpn,
            publicKey=None,
            shortId=None,
            spiderX=None,
        )

        v2rayConfig = V2rayConfig(
            _comment=Comment(remark=vmessQRCode.ps),
            log=get_log(),
            inbounds=[get_inbound(port=inbound_port)],
            outbounds=[outbound, get_outbound1(), get_outbound2()],
            dns=get_dns(dns_list=dns_list),
            routing=get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.VLESS.protocolName:
        parsed_url = urlparse(config)
        _netloc = parsed_url.netloc.split("@")

        name = parsed_url.fragment
        uid = _netloc[0]
        hostname = _netloc[1].rsplit(":", 1)[0]
        port = int(_netloc[1].rsplit(":", 1)[1])

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        outbound = get_outbound_vless()

        streamSetting = outbound.streamSettings
        fingerprint = (
            netquery.get("fp")
            if "fp" in netquery
            else (
                streamSetting.tlsSettings.fingerprint
                if streamSetting.tlsSettings
                else None
            )
        )

        vnext = outbound.settings.vnext[0]
        vnext.address = hostname
        vnext.port = port

        user = vnext.users[0]
        user.id = uid
        user.encryption = netquery.get("encryption", "none")
        user.flow = netquery.get("flow", "")

        sni = streamSetting.populateTransportSettings(
            transport=netquery.get("type", "tcp"),
            headerType=netquery.get("headerType", None),
            host=netquery.get("host", None),
            path=netquery.get("path", None),
            seed=netquery.get("seed", None),
            quicSecurity=netquery.get("quicSecurity", None),
            key=netquery.get("key", None),
            mode=netquery.get("mode", None),
            serviceName=netquery.get("serviceName", None),
        )
        streamSetting.populateTlsSettings(
            streamSecurity=netquery.get("security", ""),
            allowInsecure=allowInsecure,
            sni=sni if netquery.get("sni", None) == None else netquery.get("sni", None),
            fingerprint=fingerprint,
            alpns=netquery.get("alpn", None),
            publicKey=netquery.get("pbk", ""),
            shortId=netquery.get("sid", ""),
            spiderX=netquery.get("spx", ""),
        )

        v2rayConfig = V2rayConfig(
            _comment=Comment(remark=name),
            log=get_log(),
            inbounds=[get_inbound(port=inbound_port)],
            outbounds=[outbound, get_outbound1(), get_outbound2()],
            dns=get_dns(dns_list=dns_list),
            routing=get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.TROJAN.protocolName:
        parsed_url = urlparse(config)
        _netloc = parsed_url.netloc.split("@")

        name = parsed_url.fragment
        uid = _netloc[0]
        hostname = _netloc[1].rsplit(":", 1)[0]
        port = int(_netloc[1].rsplit(":", 1)[1])

        netquery = dict(
            (k, v if len(v) > 1 else v[0])
            for k, v in parse_qs(parsed_url.query).items()
        )

        outbound = get_outbound_trojan()

        streamSetting = outbound.streamSettings

        flow = ""
        fingerprint = (
            streamSetting.tlsSettings.fingerprint
            if streamSetting.tlsSettings != None
            else Fingerprint.randomized
        )

        if len(netquery) > 0:
            sni = streamSetting.populateTransportSettings(
                transport=netquery.get("type", "tcp"),
                headerType=netquery.get("headerType", None),
                host=netquery.get("host", None),
                path=netquery.get("path", None),
                seed=netquery.get("seed", None),
                quicSecurity=netquery.get("quicSecurity", None),
                key=netquery.get("key", None),
                mode=netquery.get("mode", None),
                serviceName=netquery.get("serviceName", None),
            )

            streamSetting.populateTlsSettings(
                streamSecurity=netquery.get("security", TLS),
                allowInsecure=allowInsecure,
                sni=(
                    sni
                    if netquery.get("sni", None) == None
                    else netquery.get("sni", None)
                ),
                fingerprint=fingerprint,
                alpns=netquery.get("alpn", None),
                publicKey=None,
                shortId=None,
                spiderX=None,
            )

            flow = netquery.get("flow", "")

        else:
            streamSetting.populateTlsSettings(
                streamSecurity=TLS,
                allowInsecure=allowInsecure,
                sni="",
                fingerprint=fingerprint,
                alpns=None,
                publicKey=None,
                shortId=None,
                spiderX=None,
            )

        server = outbound.settings.servers[0]
        server.address = hostname
        server.port = port
        server.password = uid
        server.flow = flow

        v2rayConfig = V2rayConfig(
            _comment=Comment(remark=name),
            log=get_log(),
            inbounds=[get_inbound(port=inbound_port)],
            outbounds=[outbound, get_outbound1(), get_outbound2()],
            dns=get_dns(dns_list=dns_list),
            routing=get_routing(),
        )

        v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)

    elif protocol == EConfigType.SHADOWSOCKS.protocolName:
        outbound = get_outbound_ss()
        if not try_resolve_resolve_sip002(raw_config, outbound):
            result = raw_config.replace(EConfigType.SHADOWSOCKS.protocolScheme, "")
            index_split = result.find("#")
            if index_split > 0:
                try:
                    outbound.remarks = unquote(result[index_split + 1 :])
                except Exception as e:
                    None  # print(e)

                result = result[:index_split]

            # part decode
            index_s = result.find("@")
            result = (
                base64.b64decode(result[:index_s]).decode(
                    encoding="utf-8", errors="ignore"
                )
                + result[index_s:]
                if index_s > 0
                else base64.b64decode(result).decode(encoding="utf-8", errors="ignore")
            )

            legacy_pattern = re.compile(r"^(.+?):(.*)@(.+):(\d+)\/?.*$")
            match = legacy_pattern.match(result)

            if not match:
                raise Exception("Incorrect protocol")

            server = outbound.settings.servers[0]
            server.address = match.group(3).strip("[]")
            server.port = int(match.group(4))
            server.password = match.group(2)
            server.method = match.group(1).lower()

            v2rayConfig = V2rayConfig(
                _comment=Comment(remark=outbound.remarks),
                log=get_log(),
                inbounds=[get_inbound(port=inbound_port)],
                outbounds=[outbound, get_outbound1(), get_outbound2()],
                dns=get_dns(dns_list=dns_list),
                routing=get_routing(),
            )

            v2rayConfig_str_json = json.dumps(v2rayConfig, default=vars)

        res = json.loads(v2rayConfig_str_json)
        res = remove_nulls(res)

        return json.dumps(res)


def decode_if_base64(content):
    try:
        # Try to decode as base64
        decoded = base64.b64decode(content).decode("utf-8")
        return decoded
    except:
        # If it fails, return original content
        return content


def get_content_from_url(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
        }
        response = requests.get(url, timeout=5, headers=headers)
        response.raise_for_status()
        content = response.text
        return decode_if_base64(content)
    except Exception as e:
        print(f"Error fetching content from {url}: {e}")
        return None


def is_port_free(port):
    """Check if a port is free by trying to bind to it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("", port))  # Try to bind to all interfaces
            return True
        except socket.error:
            return False


def get_random_free_port(min_port=1024, max_port=65535):
    """Get a random free port between min_port and max_port."""
    while True:
        port = random.randint(min_port, max_port)
        if is_port_free(port):
            return port


def httping_via_socks(
    url="http://www.msftconnecttest.com/connecttest.txt",
    proxy_host="127.0.0.1",
    proxy_port=10800,
    proxy_type="socks5",
    count=1,
    timeout=url_test_timeout,
) -> int:

    if proxy_type.lower() == "socks4":
        socks_proto = socks.SOCKS4
    elif proxy_type.lower() == "socks5":
        socks_proto = socks.SOCKS5
    elif proxy_type.lower() == "http":
        socks_proto = socks.HTTP
    else:
        raise ValueError("Proxy type must be 'socks4', 'socks5', or 'http'")

    socks.set_default_proxy(socks_proto, proxy_host, proxy_port)
    socket.socket = socks.socksocket

    total_time = 0
    success_count = 0

    for i in range(1, count + 1):
        try:
            start_time = time.time()
            response = requests.get(url, timeout=timeout)
            elapsed = (time.time() - start_time) * 1000  # Convert to milliseconds

            if response.status_code == 200:
                success_count += 1
                total_time += elapsed
                socket.socket = DEFAULT_SOCKET
                return elapsed

            else:
                socket.socket = DEFAULT_SOCKET
                return -1

        except Exception as e:
            socket.socket = DEFAULT_SOCKET
            return -1


def test_socks_connection(
    socks_proxy_host="127.0.0.1", port=10800, timeout=url_test_timeout
):

    url = "https://www.youtube.com"
    proxy_url = (
        f"socks5h://{socks_proxy_host}:{port}"  # Use socks5h for remote DNS resolution
    )

    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }

    try:
        response = requests.get(url, proxies=proxies, timeout=timeout)
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        # expected_content = "Microsoft Connect Test"
        expected_content = "google"
        if expected_content in response.text:
            return True
        else:
            return False

    except:
        return False


new_urls_with_pingTimes = {}


def extract_working_urls(subscription_url):
    global working_urls_with_pingTime, connection_count, do_not_save_configs
    while True:
        new_urls_with_pingTimes.clear()
        content = get_content_from_url(subscription_url)
        if content is None:
            print("Failed to get content from subscription URL, retrying...")
            time.sleep(2)
            continue

        # Step 2: Process each line containing "config url"
        print("Searching for working url config inside all configs.")
        list_of_lines = content.splitlines()
        list_of_lines = [item for item in list_of_lines if item]
        number_of_config_url = len(list_of_lines)
        list_of_lines = random.sample(
            list_of_lines, min(max_samples_batch, len(list_of_lines))
        )

        cnt = 0
        connection_count = 0
        for config in list_of_lines:
            cnt += 1
            print(
                f"Testing config number {cnt} out of {len(list_of_lines)} random configs of {number_of_config_url} total."
            )
            thread = threading.Thread(
                target=test_config_url,
                args=(config,),
            )
            thread.start()
            time.sleep(0.05)
        ######Urgently update the first
        while connection_count < 1:
            time.sleep(0.5)
        with THRD_LOCK:
            update_sort_dict(working_urls_with_pingTime, new_urls_with_pingTimes)
        #######update others gently
        while connection_count < len(list_of_lines):
            time.sleep(0.5)
        with THRD_LOCK:
            update_sort_dict(working_urls_with_pingTime, new_urls_with_pingTimes)
            if not do_not_save_configs:
                save_unique_dict_values_to_file(
                    working_urls_with_pingTime, treasury_filename
                )
        #####
        if len(new_urls_with_pingTimes) >= 1:
            print(
                f"Found new {len(new_urls_with_pingTimes)} working URLs in subscription."
            )
            print(
                f"Number of all the working configs are {len(working_urls_with_pingTime)}."
            )
        if len(new_urls_with_pingTimes) < min_working_configs:
            time.sleep(1)
        else:
            print(f"Waiting for {subscription_update_time} seconds to referesh URL.")
            sleepInterrupt(subscription_update_time)


def update_sort_dict(working_urls_with_pingTime, new_urls_with_pingTimes):
    working_urls_with_pingTime.update(new_urls_with_pingTimes)
    working_urls_with_pingTime = sort_configs_by_ping(
        working_urls_with_pingTime
    )  # if interrupt, then wake from sleep


def sleepInterrupt(seconds):
    global INTERRUPT_EVENT
    for i in range(0, seconds):  # Check if interrupted
        if INTERRUPT_EVENT.is_set():
            INTERRUPT_EVENT = threading.Event()
            INTERRUPT_EVENT.clear()
            break
        INTERRUPT_EVENT.wait(1)  # Sleep but check for interruption


class BreakOuterLoop(Exception):
    pass


def connect_to_working_urls(inbound_port):
    global bestPing, first_time_to_connect, working_urls_with_pingTime, config_update_time
    global INTERRUPT_EVENT, _black_list
    current_process = None
    # seconds
    while len(working_urls_with_pingTime) < 1:
        time.sleep(1)
    play_firstTime_sound()
    while True:
        try:
            while len(working_urls_with_pingTime) >= 1:
                with THRD_LOCK:
                    working_urls_with_pingTime = sort_configs_by_ping(
                        working_urls_with_pingTime
                    )
                # print("list of configs::")
                # print(working_urls_with_pingTime)
                config_to_connect, bestPing = next(
                    iter(working_urls_with_pingTime.items())
                )
                configJSON = generateConfig(
                    config_to_connect, inbound_port=inbound_port
                )
                current_process = openXray_waitToConnect(
                    inbound_port, current_process, configJSON
                )

                while True:
                    pingTime = httping_via_socks(proxy_port=inbound_port)
                    update_sort_dict(
                        working_urls_with_pingTime, {config_to_connect: pingTime}
                    )
                    config_to_connect, bestPing = next(
                        iter(working_urls_with_pingTime.items())
                    )
                    # print(
                    #     f"Best ping in list is : {bestPing} and current ping is {pingTime}."
                    # )
                    if pingTime - bestPing > 500:
                        print(
                            f"Better connection found with ping {bestPing}  - moving to it {config_to_connect[:20]}!"
                        )
                        break
                    if test_socks_connection(port=inbound_port) and pingTime > 0:
                        print(
                            f"Connection working with {config_to_connect[:20]} and ping time is {pingTime:.3f} - will check again in {config_update_time} seconds"
                        )
                        time.sleep(config_update_time)  # Wait 20 seconds

                    else:
                        print(
                            f"Connection failed with {config_to_connect[:20]}  - moving to next config"
                        )
                        working_urls_with_pingTime.pop(
                            config_to_connect, "Config Not Found!"
                        )
                        _black_list.extend(config_to_connect)
                        if len(working_urls_with_pingTime) == 0:
                            print(
                                "Interrupting other thread to restart URL fetching and waiting for 3 seconds..."
                            )
                            INTERRUPT_EVENT.set()  # Signal interruption
                        time.sleep(3)
                        break
        except BreakOuterLoop:
            pass  # going to second upper loop
        except Exception as e:
            print(f"Error occurred: {e}")
            if current_process:
                current_process.terminate()
                current_process.wait(timeout=0.5)
                print("Xray process terminated")

        time.sleep(1)


def openXray_waitToConnect(inbound_port, current_process: Popen, configJSON):
    nt_unix = "" if os.name == "nt" else "./"
    with open(f"slprj/.sb-{inbound_port}.json", "w") as f:
        f.write(configJSON)
    if current_process:
        current_process.terminate()
        current_process.wait(timeout=0.5)
    current_process = Popen(
        [f"{nt_unix}xray", "run", "-c", f"slprj/.sb-{inbound_port}.json"],
        stdout=PIPE,
        stderr=PIPE,
    )
    result = run_with_timeout(
        read_alive_message_from_xray, timeout=url_test_timeout, process=current_process
    )
    # read_alive_message_from_xray(current_process)
    time.sleep(0.1)
    if result == -1:
        raise Exception("Timeout reading xray output in command line.")
    return current_process


def run_config_calculate_ping(url) -> float:
    port = get_random_free_port()
    current_process = None
    try:
        config = generateConfig(url, inbound_port=port)
    except:
        return -1
    if not config:
        return -1
    tmpName = f"slprj/.sb-{port}.json"
    with open(tmpName, "w") as f:
        f.write(config)
    nt_unix = "" if os.name == "nt" else "./"
    current_process = Popen(
        [f"{nt_unix}xray", "run", "-c", tmpName], stdout=PIPE, stderr=PIPE
    )

    result = run_with_timeout(
        read_alive_message_from_xray, timeout=url_test_timeout, process=current_process
    )

    if result == -1:
        print("Reading xray output timeout reached!")
        current_process.terminate()
        remove_file(tmpName)
        return -1

    pingtime = httping_via_socks(proxy_port=port)
    test_conn = test_socks_connection(port=port)
    current_process.terminate()
    time.sleep(0.1)
    remove_file(tmpName)
    if not test_conn:
        return -1
    return pingtime


def read_alive_message_from_xray(process):
    for line in iter(process.stdout.readline, ""):
        if "Reading config" in line.decode("utf-8").strip():
            break
    return 0


def play_firstTime_sound():
    global first_time_to_connect
    try:  # connected sound
        if first_time_to_connect:
            import winsound

            winsound.MessageBeep()
            first_time_to_connect = False
    except Exception as e:
        print(f"err {e}")


def sort_configs_by_ping(configs):
    configs = {k: v for k, v in configs.items() if v >= 0}
    configs = dict(sorted(configs.items(), key=lambda item: item[1]))
    # print(configs)
    return configs


def test_config_url(url):
    global new_urls_with_pingTimes, connection_count

    pingtime = run_with_timeout(
        run_config_calculate_ping, timeout=url_test_timeout, url=url
    )

    # pingtime = run_config_calculate_ping(url)
    connection_count += 1
    if pingtime > 0:
        with THRD_LOCK:
            new_urls_with_pingTimes[url] = pingtime
            # print(f"new url with ping time {url} : {pingtime}")
    else:
        return False
    return True


def remove_file(file_path="working_urls.txt"):
    try:
        os.remove(file_path)
    except:
        pass


def clear_files_in_slprj(folder_path):

    if os.path.exists(folder_path):
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(
                        file_path
                    )  # Remove this line if you want to keep subfolders
            except Exception as e:
                print(f"Failed to delete {file_path}: {e}")
        print(f"All files in {folder_path} have been removed.")
    else:
        print(f"The folder {folder_path} does not exist.")


######################################
def check_init_files():
    if not find_xray():
        print("Please copy xray and make it executable inside the path.")
        exit()
    #########
    clear_files_in_slprj(folder_path="slprj")
    if not os.path.exists("slprj"):
        os.mkdir("slprj")


def run_Main_Threads():
    thread1 = threading.Thread(target=extract_working_urls, args=(subscription_url,))
    thread2 = threading.Thread(
        target=connect_to_working_urls, args=(listening_socks_port,)
    )
    thread1.daemon = True
    thread2.daemon = True

    thread1.start()
    thread2.start()
    # Wait for both threads to complete
    thread1.join()
    thread2.join()


def arguments_Check():
    global subscription_url, listening_socks_port, apply_fragment, treasury_filename
    global working_urls_with_pingTime, listen_to_any, do_not_save_configs, THRD_LOCK
    parser = argparse.ArgumentParser(
        description="A lightweight and efficient tool designed to manage and rotate through proxy configurations. It automatically fetches subscription URLs, decodes them (handling both raw text and Base64 encoded formats), and tests the proxies to save only the working ones for fast and reliable internet connectivity.",
        epilog="Example: python ProxyRotator.py -u <URL> -p <inbound port>",
    )
    parser.add_argument(
        "--URL", "-u", default=subscription_url, help="Subscription URL."
    )

    parser.add_argument(
        "--Fragment",
        action="store_true",
        default=apply_fragment,
        help="Enable fFagment.",
    )
    parser.add_argument(
        "--Port",
        "-p",
        type=int,
        default=listening_socks_port,
        help="Socks Listening Port.",
    )
    parser.add_argument(
        "--NoMemory", action="store_true", help="Do not use the saved configs."
    )
    parser.add_argument(
        "--AnyLan", action="store_true", help="Listen to any inbound connection."
    )
    parser.add_argument("--NoSave", action="store_true", help="Do not save confgis.")
    ##
    args = parser.parse_args()
    listen_to_any = args.AnyLan
    listening_socks_port = args.Port
    do_not_save_configs = args.NoSave
    subscription_url = args.URL
    apply_fragment = args.Fragment
    #######
    if listen_to_any:
        print("Listening to 0.0.0.0")
    if apply_fragment:
        print("Fragment activated.")

    print(f"Listening port is {listening_socks_port}")
    print(f"URL received: {subscription_url}")

    if do_not_save_configs:
        print("Not saving configs.")

    if not args.NoMemory:
        print("Using saved configs to speed up!")
        temp = create_dict_from_file(treasury_filename)
        keys_random = random.sample(list(temp.keys()), len(temp))
        with THRD_LOCK:
            working_urls_with_pingTime = {key: temp[key] for key in keys_random}
    else:
        print("Not using saved configs from last execution.")


if __name__ == "__main__":
    arguments_Check()
    check_init_files()
    run_Main_Threads()
