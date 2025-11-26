"""
信息收集模块

功能特性：
1. NmapScanner：端口和服务扫描
2. DVWACollector：DVWA专属信息收集
3. PathScanner：基础路径扫描
4. InfoGatheringManager：统一管理所有收集功能

使用示例：
    from src.modules.info_gathering import NmapScanner, PortInfo
    
    scanner = NmapScanner()
    ports = scanner.scan_web_ports("192.168.1.100")
    for port in ports:
        print(f"端口 {port.port} 状态: {port.state}, 服务: {port.service}")
"""

import re
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Union, Set
from pathlib import Path
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, Future

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    nmap = None

try:
    from src.utils.logger import get_logger
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    get_logger = lambda name: logging.getLogger(name)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False
    BeautifulSoup = None


@dataclass
class PortInfo:
    """
    端口信息数据类
    
    属性：
        port: 端口号
        state: 端口状态 (open, closed, filtered)
        service: 服务名称
        version: 服务版本信息
        product: 产品名称
        extra_info: 额外信息
        is_web_service: 是否为Web服务
        web_server: str - Web服务器类型（Apache, Nginx, IIS等）
        framework: str - 框架类型（WordPress, Django, Spring等）
        middleware: str - 中间件信息
        risk_level: str - 风险级别（high, medium, low, none）
        known_vulnerabilities: List[str] - 已知漏洞列表
        security_recommendations: List[str] - 安全建议列表
    """
    port: int
    state: str = "unknown"
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""
    is_web_service: bool = False
    web_server: str = ""
    framework: str = ""
    middleware: str = ""
    risk_level: str = "none"
    known_vulnerabilities: List[str] = field(default_factory=list)
    security_recommendations: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """初始化后处理，自动判断是否为Web服务"""
        if not self.is_web_service:
            self.is_web_service = self._detect_web_service()
    
    def _detect_web_service(self) -> bool:
        """
        检测是否为Web服务
        
        Returns:
            如果是Web服务返回True，否则返回False
        """
        # 常见Web端口
        web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000}
        
        # 检查端口号
        if self.port in web_ports:
            return True
        
        # 检查服务名称
        service_lower = self.service.lower()
        web_keywords = ['http', 'https', 'apache', 'nginx', 'iis', 'tomcat', 'jetty', 'web']
        if any(keyword in service_lower for keyword in web_keywords):
            return True
        
        # 检查产品名称
        product_lower = self.product.lower()
        if any(keyword in product_lower for keyword in web_keywords):
            return True
        
        return False
    
    def to_dict(self) -> Dict:
        """
        转换为字典格式
        
        Returns:
            端口信息字典
        """
        return {
            'port': self.port,
            'state': self.state,
            'service': self.service,
            'version': self.version,
            'product': self.product,
            'extra_info': self.extra_info,
            'is_web_service': self.is_web_service,
            'web_server': self.web_server,
            'framework': self.framework,
            'middleware': self.middleware,
            'risk_level': self.risk_level,
            'known_vulnerabilities': self.known_vulnerabilities,
            'security_recommendations': self.security_recommendations
        }
    
    def __repr__(self) -> str:
        return (
            f"PortInfo(port={self.port}, state={self.state}, "
            f"service={self.service}, is_web={self.is_web_service})"
        )


class NmapScannerError(Exception):
    """Nmap扫描器异常基类"""
    pass


class NmapNotInstalledError(NmapScannerError):
    """Nmap未安装异常"""
    pass


class NmapScanError(NmapScannerError):
    """Nmap扫描错误异常"""
    pass


class NmapScanner:
    """
    Nmap端口扫描器类
    
    功能特性：
    1. 使用python-nmap库进行端口扫描
    2. 扫描常见Web端口
    3. 获取端口状态、服务版本、操作系统信息
    4. 支持自定义端口范围和扫描参数
    5. 结果标准化输出
    6. 支持扫描进度回调
    7. 性能优化（避免重复扫描）
    8. 详细的错误处理和日志记录
    """
    
    # 常见Web端口列表
    WEB_PORTS = [80, 8080, 443, 8443, 8000, 3000, 5000]
    
    # Web服务关键词
    WEB_SERVICE_KEYWORDS = ['http', 'https', 'apache', 'nginx', 'iis', 'tomcat', 'jetty']
    
    def __init__(
        self,
        scan_timeout: int = 300,
        scan_delay: float = 0.0,
        max_retries: int = 3,
        enable_os_detection: bool = True,
        enable_version_detection: bool = True
    ):
        """
        初始化NmapScanner
        
        Args:
            scan_timeout: 扫描超时时间（秒），默认300秒
            scan_delay: 扫描延迟（秒），默认0.0秒
            max_retries: 最大重试次数，默认3次
            enable_os_detection: 是否启用操作系统检测，默认True
            enable_version_detection: 是否启用版本检测，默认True
        """
        self.scan_timeout = scan_timeout
        self.scan_delay = scan_delay
        self.max_retries = max_retries
        self.enable_os_detection = enable_os_detection
        self.enable_version_detection = enable_version_detection
        
        # 日志记录器
        self.logger = get_logger(__name__)
        
        # 缓存已扫描的目标，避免重复扫描
        self._scan_cache: Dict[str, List[PortInfo]] = {}
        
        # 检查python-nmap库是否安装
        if not HAS_NMAP:
            self.logger.warning(
                "python-nmap库未安装，请使用 'pip install python-nmap' 安装。"
                "将尝试使用系统nmap命令作为备选方案。"
            )
        
        # 初始化nmap扫描器
        self._nmap_scanner = None
        if HAS_NMAP:
            try:
                self._nmap_scanner = nmap.PortScanner()
                self.logger.info("Nmap扫描器初始化成功")
            except Exception as e:
                self.logger.error(f"Nmap扫描器初始化失败: {e}")
                raise NmapNotInstalledError(f"无法初始化Nmap扫描器: {e}")
        else:
            # 检查系统是否安装了nmap命令
            if not self._check_nmap_command():
                raise NmapNotInstalledError(
                    "python-nmap库未安装且系统未找到nmap命令。"
                    "请安装python-nmap库或系统nmap工具。"
                )
            self.logger.info("将使用系统nmap命令进行扫描")
    
    def _check_nmap_command(self) -> bool:
        """
        检查系统是否安装了nmap命令
        
        Returns:
            如果找到nmap命令返回True，否则返回False
        """
        import shutil
        return shutil.which('nmap') is not None
    
    def scan_web_ports(self, target_ip: str, progress_callback: Optional[Callable[[str, float], None]] = None) -> List[PortInfo]:
        """
        扫描常见Web端口
        
        Args:
            target_ip: 目标IP地址或域名
            progress_callback: 进度回调函数，参数为(消息, 进度百分比)
            
        Returns:
            端口信息列表
            
        Raises:
            NmapScanError: 扫描失败时抛出
        """
        self.logger.info(f"开始扫描Web端口: {target_ip}")
        
        # 检查缓存
        cache_key = f"{target_ip}_web"
        if cache_key in self._scan_cache:
            self.logger.info(f"使用缓存结果: {target_ip}")
            if progress_callback:
                progress_callback("使用缓存结果", 100.0)
            return self._scan_cache[cache_key]
        
        try:
            # 转换端口列表为字符串格式
            ports_str = ','.join(map(str, self.WEB_PORTS))
            
            if progress_callback:
                progress_callback(f"开始扫描 {len(self.WEB_PORTS)} 个Web端口", 0.0)
            
            # 执行扫描
            port_infos = self._execute_scan(
                target_ip=target_ip,
                ports=ports_str,
                scan_type="web",
                progress_callback=progress_callback
            )
            
            # 缓存结果
            self._scan_cache[cache_key] = port_infos
            
            self.logger.info(f"Web端口扫描完成: {target_ip}, 发现 {len(port_infos)} 个开放端口")
            
            if progress_callback:
                progress_callback("Web端口扫描完成", 100.0)
            
            return port_infos
            
        except Exception as e:
            error_msg = f"Web端口扫描失败: {target_ip} - {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            if progress_callback:
                progress_callback(f"扫描失败: {str(e)}", 0.0)
            raise NmapScanError(error_msg) from e
    
    def scan_custom_ports(
        self,
        target_ip: str,
        ports: Union[str, List[int], int],
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> List[PortInfo]:
        """
        扫描自定义端口范围
        
        Args:
            target_ip: 目标IP地址或域名
            ports: 端口范围，可以是：
                  - 字符串: "80,443,8080" 或 "80-100" 或 "80,443,8080-8090"
                  - 整数列表: [80, 443, 8080]
                  - 单个整数: 80
            progress_callback: 进度回调函数，参数为(消息, 进度百分比)
            
        Returns:
            端口信息列表
            
        Raises:
            NmapScanError: 扫描失败时抛出
        """
        self.logger.info(f"开始自定义端口扫描: {target_ip}, 端口: {ports}")
        
        # 标准化端口字符串
        if isinstance(ports, int):
            ports_str = str(ports)
        elif isinstance(ports, list):
            ports_str = ','.join(map(str, ports))
        else:
            ports_str = str(ports)
        
        # 检查缓存
        cache_key = f"{target_ip}_{ports_str}"
        if cache_key in self._scan_cache:
            self.logger.info(f"使用缓存结果: {target_ip}")
            if progress_callback:
                progress_callback("使用缓存结果", 100.0)
            return self._scan_cache[cache_key]
        
        try:
            if progress_callback:
                progress_callback(f"开始扫描端口: {ports_str}", 0.0)
            
            # 执行扫描
            port_infos = self._execute_scan(
                target_ip=target_ip,
                ports=ports_str,
                scan_type="custom",
                progress_callback=progress_callback
            )
            
            # 缓存结果
            self._scan_cache[cache_key] = port_infos
            
            self.logger.info(f"自定义端口扫描完成: {target_ip}, 发现 {len(port_infos)} 个开放端口")
            
            if progress_callback:
                progress_callback("端口扫描完成", 100.0)
            
            return port_infos
            
        except Exception as e:
            error_msg = f"自定义端口扫描失败: {target_ip} - {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            if progress_callback:
                progress_callback(f"扫描失败: {str(e)}", 0.0)
            raise NmapScanError(error_msg) from e
    
    def get_service_banner(self, port_info: PortInfo, target_ip: Optional[str] = None) -> str:
        """
        获取服务Banner信息
        
        Args:
            port_info: 端口信息对象
            target_ip: 目标IP地址（可选，用于通过socket获取banner）
            
        Returns:
            Banner字符串
        """
        try:
            # 如果已有版本信息，直接返回
            if port_info.version or port_info.product:
                banner_parts = []
                if port_info.product:
                    banner_parts.append(port_info.product)
                if port_info.version:
                    banner_parts.append(port_info.version)
                if port_info.extra_info:
                    banner_parts.append(port_info.extra_info)
                banner = " ".join(banner_parts)
                if banner:
                    return banner
            
            # 如果提供了目标IP，尝试通过socket连接获取banner
            if target_ip and port_info.state == "open":
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((target_ip, port_info.port))
                    
                    if result == 0:
                        # 尝试接收banner
                        try:
                            # 发送HTTP请求获取banner（如果是Web服务）
                            if port_info.is_web_service:
                                sock.send(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n\r\n")
                            
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            if banner:
                                sock.close()
                                return banner
                        except:
                            pass
                    
                    sock.close()
                except Exception as e:
                    self.logger.debug(f"通过socket获取Banner失败 (端口 {port_info.port}): {e}")
            
            return ""
            
        except Exception as e:
            self.logger.warning(f"获取服务Banner时出错: {e}")
            return ""
    
    def detect_os(self, target_ip: str) -> str:
        """
        检测目标操作系统
        
        Args:
            target_ip: 目标IP地址或域名
            
        Returns:
            操作系统信息字符串，如果检测失败返回空字符串
        """
        self.logger.info(f"开始操作系统检测: {target_ip}")
        
        if not self.enable_os_detection:
            self.logger.info("操作系统检测已禁用")
            return ""
        
        if not HAS_NMAP or not self._nmap_scanner:
            self.logger.warning("无法进行操作系统检测：python-nmap未安装")
            return ""
        
        try:
            # 执行OS检测扫描
            scan_result = self._nmap_scanner.scan(
                hosts=target_ip,
                arguments='-O --osscan-guess',
                timeout=self.scan_timeout
            )
            
            if target_ip not in scan_result['scan']:
                self.logger.warning(f"未找到目标 {target_ip} 的扫描结果")
                return ""
            
            host_result = scan_result['scan'][target_ip]
            
            # 提取OS信息
            os_info_parts = []
            
            if 'osmatch' in host_result:
                for osmatch in host_result['osmatch']:
                    if 'name' in osmatch:
                        os_info_parts.append(osmatch['name'])
                    if 'accuracy' in osmatch:
                        os_info_parts.append(f"(准确度: {osmatch['accuracy']}%)")
            
            if 'osclass' in host_result:
                for osclass in host_result['osclass']:
                    if 'type' in osclass:
                        os_info_parts.append(f"类型: {osclass['type']}")
                    if 'vendor' in osclass:
                        os_info_parts.append(f"厂商: {osclass['vendor']}")
            
            os_info = " ".join(os_info_parts) if os_info_parts else ""
            
            if os_info:
                self.logger.info(f"操作系统检测成功: {target_ip} - {os_info}")
            else:
                self.logger.warning(f"未检测到操作系统信息: {target_ip}")
            
            return os_info
            
        except Exception as e:
            error_msg = f"操作系统检测失败: {target_ip} - {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return ""
    
    def _execute_scan(
        self,
        target_ip: str,
        ports: str,
        scan_type: str = "custom",
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> List[PortInfo]:
        """
        执行Nmap扫描
        
        Args:
            target_ip: 目标IP地址或域名
            ports: 端口字符串
            scan_type: 扫描类型（web/custom）
            progress_callback: 进度回调函数
            
        Returns:
            端口信息列表
        """
        port_infos = []
        
        # 构建扫描参数
        scan_args_parts = []
        
        if self.enable_version_detection:
            scan_args_parts.append('-sV')  # 版本检测
        
        if self.scan_delay > 0:
            scan_args_parts.append(f'--scan-delay {self.scan_delay}')
        
        scan_args = ' '.join(scan_args_parts) if scan_args_parts else '-sV'
        
        retries = 0
        last_error = None
        
        while retries < self.max_retries:
            try:
                if progress_callback:
                    progress_callback(f"正在扫描 {target_ip}:{ports}", 30.0)
                
                if HAS_NMAP and self._nmap_scanner:
                    # 使用python-nmap库
                    self.logger.debug(f"使用python-nmap扫描: {target_ip}:{ports}")
                    scan_result = self._nmap_scanner.scan(
                        hosts=target_ip,
                        ports=ports,
                        arguments=scan_args,
                        timeout=self.scan_timeout
                    )
                    
                    if progress_callback:
                        progress_callback("解析扫描结果", 70.0)
                    
                    port_infos = self._parse_nmap_result(scan_result, target_ip)
                    
                else:
                    # 使用系统nmap命令（备选方案）
                    self.logger.debug(f"使用系统nmap命令扫描: {target_ip}:{ports}")
                    port_infos = self._scan_with_command(target_ip, ports, scan_args, progress_callback)
                
                # 扫描成功，跳出重试循环
                break
                
            except nmap.PortScannerError as e:
                last_error = e
                retries += 1
                self.logger.warning(f"扫描失败 (尝试 {retries}/{self.max_retries}): {e}")
                if retries < self.max_retries:
                    if progress_callback:
                        progress_callback(f"重试扫描 ({retries}/{self.max_retries})", 0.0)
                    continue
                else:
                    raise NmapScanError(f"扫描失败，已重试 {self.max_retries} 次: {e}") from e
                    
            except Exception as e:
                last_error = e
                retries += 1
                self.logger.error(f"扫描异常 (尝试 {retries}/{self.max_retries}): {e}", exc_info=True)
                if retries < self.max_retries:
                    if progress_callback:
                        progress_callback(f"重试扫描 ({retries}/{self.max_retries})", 0.0)
                    continue
                else:
                    raise NmapScanError(f"扫描异常，已重试 {self.max_retries} 次: {e}") from e
        
        if progress_callback:
            progress_callback("扫描完成", 100.0)
        
        return port_infos
    
    def _parse_nmap_result(self, scan_result: Dict, target_ip: str) -> List[PortInfo]:
        """
        解析Nmap扫描结果
        
        Args:
            scan_result: Nmap扫描结果字典
            target_ip: 目标IP地址
            
        Returns:
            端口信息列表
        """
        port_infos = []
        
        try:
            if target_ip not in scan_result['scan']:
                self.logger.warning(f"未找到目标 {target_ip} 的扫描结果")
                return port_infos
            
            host_result = scan_result['scan'][target_ip]
            
            if 'tcp' not in host_result:
                self.logger.info(f"目标 {target_ip} 未发现TCP端口")
                return port_infos
            
            for port_num, port_data in host_result['tcp'].items():
                try:
                    port_num = int(port_num)
                    
                    port_info = PortInfo(
                        port=port_num,
                        state=port_data.get('state', 'unknown'),
                        service=port_data.get('name', ''),
                        version=port_data.get('version', ''),
                        product=port_data.get('product', ''),
                        extra_info=port_data.get('extrainfo', '')
                    )
                    
                    # 进行指纹识别和风险评估
                    port_info = self.identify_service_fingerprint(port_info)
                    port_info = self.assess_security_risk(port_info)
                    
                    port_infos.append(port_info)
                    
                except (ValueError, KeyError) as e:
                    self.logger.warning(f"解析端口信息失败: {e}")
                    continue
            
            self.logger.debug(f"解析完成，共 {len(port_infos)} 个端口")
            
        except Exception as e:
            self.logger.error(f"解析Nmap结果时出错: {e}", exc_info=True)
            raise NmapScanError(f"解析扫描结果失败: {e}") from e
        
        return port_infos
    
    def _scan_with_command(
        self,
        target_ip: str,
        ports: str,
        scan_args: str,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> List[PortInfo]:
        """
        使用系统nmap命令进行扫描（备选方案）
        
        Args:
            target_ip: 目标IP地址
            ports: 端口字符串
            scan_args: 扫描参数
            progress_callback: 进度回调函数
            
        Returns:
            端口信息列表
        """
        import subprocess
        import json
        
        port_infos = []
        
        try:
            # 构建nmap命令
            cmd = ['nmap', '-sV', '-p', ports, '-oJ', '-', target_ip]
            
            if progress_callback:
                progress_callback("执行nmap命令", 50.0)
            
            # 执行命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.scan_timeout
            )
            
            if result.returncode != 0:
                raise NmapScanError(f"nmap命令执行失败: {result.stderr}")
            
            # 解析JSON输出
            if progress_callback:
                progress_callback("解析nmap输出", 80.0)
            
            # nmap的JSON输出可能包含多行，每行一个JSON对象
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    if 'ports' in data:
                        for port_data in data['ports']:
                            if 'portid' in port_data and 'state' in port_data['state']:
                                port_num = int(port_data['portid'])
                                state = port_data['state']['state']
                                
                                service = port_data.get('service', {})
                                service_name = service.get('name', '')
                                product = service.get('product', '')
                                version = service.get('version', '')
                                extra_info = service.get('extrainfo', '')
                                
                                port_info = PortInfo(
                                    port=port_num,
                                    state=state,
                                    service=service_name,
                                    version=version,
                                    product=product,
                                    extra_info=extra_info
                                )
                                
                                # 进行指纹识别和风险评估
                                port_info = self.identify_service_fingerprint(port_info)
                                port_info = self.assess_security_risk(port_info)
                                
                                port_infos.append(port_info)
                except json.JSONDecodeError:
                    continue
            
        except subprocess.TimeoutExpired:
            raise NmapScanError(f"nmap命令执行超时: {self.scan_timeout}秒")
        except FileNotFoundError:
            raise NmapNotInstalledError("未找到nmap命令，请确保已安装nmap")
        except Exception as e:
            raise NmapScanError(f"执行nmap命令时出错: {e}") from e
        
        return port_infos
    
    def clear_cache(self, target_ip: Optional[str] = None):
        """
        清除扫描缓存
        
        Args:
            target_ip: 如果指定，只清除该目标的缓存；如果为None，清除所有缓存
        """
        if target_ip:
            # 清除指定目标的缓存
            keys_to_remove = [key for key in self._scan_cache.keys() if key.startswith(target_ip)]
            for key in keys_to_remove:
                del self._scan_cache[key]
            self.logger.info(f"已清除目标 {target_ip} 的扫描缓存")
        else:
            # 清除所有缓存
            self._scan_cache.clear()
            self.logger.info("已清除所有扫描缓存")
    
    def get_cache_size(self) -> int:
        """
        获取缓存大小
        
        Returns:
            缓存条目数量
        """
        return len(self._scan_cache)
    
    # ==================== 高级功能：服务指纹识别 ====================
    
    # Web服务器识别模式
    WEB_SERVER_PATTERNS = {
        'Apache': [r'apache[/\s](\d+\.\d+(?:\.\d+)?)', r'httpd[/\s](\d+\.\d+(?:\.\d+)?)'],
        'Nginx': [r'nginx[/\s](\d+\.\d+(?:\.\d+)?)'],
        'IIS': [r'iis[/\s](\d+\.\d+(?:\.\d+)?)', r'microsoft-iis[/\s](\d+\.\d+(?:\.\d+)?)'],
        'Tomcat': [r'tomcat[/\s](\d+\.\d+(?:\.\d+)?)', r'apache-tomcat[/\s](\d+\.\d+(?:\.\d+)?)'],
        'Jetty': [r'jetty[/\s](\d+\.\d+(?:\.\d+)?)'],
    }
    
    # 框架识别模式
    FRAMEWORK_PATTERNS = {
        'WordPress': [r'wordpress', r'wp-content', r'wp-includes'],
        'Django': [r'django', r'csrfmiddlewaretoken'],
        'Spring': [r'spring', r'springframework'],
        'Laravel': [r'laravel', r'laravel_session'],
        'Flask': [r'flask', r'werkzeug'],
        'Express': [r'express', r'x-powered-by.*express'],
        'Rails': [r'rails', r'x-rails'],
    }
    
    # 高危服务版本数据库（简化版，实际应使用CVE数据库）
    VULNERABLE_VERSIONS = {
        'Apache': {
            '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
            '2.4.48': ['CVE-2021-41773'],
            '2.4.46': ['CVE-2021-41773'],
        },
        'Nginx': {
            '1.18.0': ['CVE-2021-23017'],
            '1.19.6': ['CVE-2021-23017'],
        },
        'IIS': {
            '10.0': ['CVE-2020-0646'],
        },
        'Tomcat': {
            '9.0.0': ['CVE-2020-1938'],
            '8.5.0': ['CVE-2020-1938'],
        },
    }
    
    def identify_service_fingerprint(self, port_info: PortInfo) -> PortInfo:
        """
        识别服务指纹（Web服务器、框架、中间件）
        
        Args:
            port_info: 端口信息对象
            
        Returns:
            更新后的端口信息对象
        """
        if port_info.state != "open":
            return port_info
        
        # 组合所有可用的信息
        info_text = f"{port_info.product} {port_info.version} {port_info.service} {port_info.extra_info}".lower()
        
        # 识别Web服务器
        port_info.web_server = self._identify_web_server(info_text, port_info)
        
        # 识别框架
        port_info.framework = self._identify_framework(info_text, port_info)
        
        # 识别中间件
        port_info.middleware = self._identify_middleware(info_text, port_info)
        
        return port_info
    
    def _identify_web_server(self, info_text: str, port_info: PortInfo) -> str:
        """识别Web服务器类型"""
        for server_name, patterns in self.WEB_SERVER_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, info_text, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else ""
                    return f"{server_name} {version}".strip()
        
        # 通过端口推断
        if port_info.is_web_service:
            if port_info.port in [80, 443, 8080, 8443]:
                return "Unknown Web Server"
        
        return ""
    
    def _identify_framework(self, info_text: str, port_info: PortInfo) -> str:
        """识别框架类型"""
        for framework_name, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, info_text, re.IGNORECASE):
                    return framework_name
        
        return ""
    
    def _identify_middleware(self, info_text: str, port_info: PortInfo) -> str:
        """识别中间件"""
        middleware_keywords = {
            'Redis': ['redis'],
            'Memcached': ['memcached'],
            'RabbitMQ': ['rabbitmq'],
            'Kafka': ['kafka'],
            'Elasticsearch': ['elasticsearch'],
            'MongoDB': ['mongodb'],
            'MySQL': ['mysql', 'mariadb'],
            'PostgreSQL': ['postgresql', 'postgres'],
        }
        
        for middleware_name, keywords in middleware_keywords.items():
            for keyword in keywords:
                if keyword in info_text:
                    return middleware_name
        
        return ""
    
    # ==================== 高级功能：安全风险评估 ====================
    
    def assess_security_risk(self, port_info: PortInfo) -> PortInfo:
        """
        评估安全风险
        
        Args:
            port_info: 端口信息对象
            
        Returns:
            更新后的端口信息对象
        """
        if port_info.state != "open":
            port_info.risk_level = "none"
            return port_info
        
        vulnerabilities = []
        recommendations = []
        risk_score = 0
        
        # 检查高危服务版本
        if port_info.web_server:
            server_name = port_info.web_server.split()[0] if port_info.web_server else ""
            if server_name in self.VULNERABLE_VERSIONS:
                version = port_info.version or ""
                for vuln_version, cves in self.VULNERABLE_VERSIONS[server_name].items():
                    if vuln_version in version:
                        vulnerabilities.extend(cves)
                        risk_score += 10
                        recommendations.append(f"升级 {server_name} 到最新版本以修复已知漏洞")
        
        # 检查默认端口上的服务
        default_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            27017: 'MongoDB',
        }
        
        if port_info.port in default_ports:
            service_name = default_ports[port_info.port]
            if not port_info.version:
                recommendations.append(f"检测到 {service_name} 服务，建议确认版本并检查安全配置")
                risk_score += 2
        
        # 检查未加密的服务
        if port_info.port in [21, 23, 80, 3306, 5432, 6379, 27017]:
            if port_info.port not in [80, 443]:  # HTTP/HTTPS除外
                recommendations.append(f"端口 {port_info.port} 使用未加密协议，建议使用加密连接")
                risk_score += 3
        
        # 检查开放的管理端口
        admin_ports = [8080, 8443, 9000, 9090]
        if port_info.port in admin_ports:
            recommendations.append(f"端口 {port_info.port} 可能是管理端口，建议限制访问")
            risk_score += 5
        
        # 确定风险级别
        if risk_score >= 10:
            port_info.risk_level = "high"
        elif risk_score >= 5:
            port_info.risk_level = "medium"
        elif risk_score > 0:
            port_info.risk_level = "low"
        else:
            port_info.risk_level = "none"
        
        port_info.known_vulnerabilities = vulnerabilities
        port_info.security_recommendations = recommendations
        
        return port_info
    
    # ==================== 高级功能：并行扫描优化 ====================
    
    def scan_ports_parallel(
        self,
        target_ip: str,
        ports: List[int],
        max_workers: int = 5,
        progress_callback: Optional[Callable[[str, float], None]] = None
    ) -> List[PortInfo]:
        """
        并行扫描多个端口（性能优化）
        
        Args:
            target_ip: 目标IP地址
            ports: 端口列表
            max_workers: 最大并发线程数
            progress_callback: 进度回调函数
            
        Returns:
            端口信息列表
        """
        self.logger.info(f"开始并行扫描 {len(ports)} 个端口: {target_ip}")
        
        # 检查缓存
        ports_str = ','.join(map(str, sorted(ports)))
        cache_key = f"{target_ip}_{ports_str}"
        if cache_key in self._scan_cache:
            self.logger.info(f"使用缓存结果: {target_ip}")
            if progress_callback:
                progress_callback("使用缓存结果", 100.0)
            return self._scan_cache[cache_key]
        
        # 将端口分组，每组最多10个端口
        port_groups = []
        group_size = 10
        for i in range(0, len(ports), group_size):
            port_groups.append(ports[i:i + group_size])
        
        all_results = []
        completed = 0
        total = len(port_groups)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_group = {
                executor.submit(self._scan_port_group, target_ip, group): group
                for group in port_groups
            }
            
            # 收集结果
            for future in as_completed(future_to_group):
                group = future_to_group[future]
                completed += 1
                
                try:
                    results = future.result()
                    all_results.extend(results)
                    
                    if progress_callback:
                        progress = (completed / total) * 100
                        progress_callback(f"扫描进度: {completed}/{total} 组", progress)
                    
                except Exception as e:
                    self.logger.error(f"扫描端口组 {group} 时出错: {e}", exc_info=True)
        
        # 对结果进行指纹识别和风险评估
        for port_info in all_results:
            port_info = self.identify_service_fingerprint(port_info)
            port_info = self.assess_security_risk(port_info)
        
        # 缓存结果
        self._scan_cache[cache_key] = all_results
        
        self.logger.info(f"并行扫描完成: {target_ip}, 发现 {len(all_results)} 个开放端口")
        
        if progress_callback:
            progress_callback("并行扫描完成", 100.0)
        
        return all_results
    
    def _scan_port_group(self, target_ip: str, ports: List[int]) -> List[PortInfo]:
        """扫描一组端口"""
        ports_str = ','.join(map(str, ports))
        try:
            return self.scan_custom_ports(target_ip, ports_str)
        except Exception as e:
            self.logger.warning(f"扫描端口组失败: {ports} - {e}")
            return []
    
    # ==================== 高级功能：智能超时控制 ====================
    
    def _calculate_smart_timeout(self, port_count: int) -> int:
        """
        根据端口数量智能计算超时时间
        
        Args:
            port_count: 端口数量
            
        Returns:
            超时时间（秒）
        """
        # 基础超时时间
        base_timeout = 30
        
        # 每个端口增加2秒
        port_timeout = port_count * 2
        
        # 最大超时时间限制
        max_timeout = 600  # 10分钟
        
        calculated_timeout = min(base_timeout + port_timeout, max_timeout)
        
        return calculated_timeout
    
    # ==================== 高级功能：报告生成 ====================
    
    def generate_scan_summary(self, port_infos: List[PortInfo]) -> Dict:
        """
        生成端口扫描摘要
        
        Args:
            port_infos: 端口信息列表
            
        Returns:
            摘要字典
        """
        open_ports = [p for p in port_infos if p.state == "open"]
        
        # 统计信息
        summary = {
            'total_ports': len(port_infos),
            'open_ports': len(open_ports),
            'closed_ports': len([p for p in port_infos if p.state == "closed"]),
            'filtered_ports': len([p for p in port_infos if p.state == "filtered"]),
            'web_services': len([p for p in open_ports if p.is_web_service]),
            'risk_distribution': {
                'high': len([p for p in open_ports if p.risk_level == "high"]),
                'medium': len([p for p in open_ports if p.risk_level == "medium"]),
                'low': len([p for p in open_ports if p.risk_level == "low"]),
                'none': len([p for p in open_ports if p.risk_level == "none"]),
            },
            'vulnerable_services': len([p for p in open_ports if p.known_vulnerabilities]),
            'web_servers': {},
            'frameworks': {},
            'middleware': {},
        }
        
        # 统计Web服务器
        for port_info in open_ports:
            if port_info.web_server:
                server = port_info.web_server.split()[0]
                summary['web_servers'][server] = summary['web_servers'].get(server, 0) + 1
            
            if port_info.framework:
                summary['frameworks'][port_info.framework] = summary['frameworks'].get(port_info.framework, 0) + 1
            
            if port_info.middleware:
                summary['middleware'][port_info.middleware] = summary['middleware'].get(port_info.middleware, 0) + 1
        
        return summary
    
    def generate_formatted_report(self, port_infos: List[PortInfo], target_ip: str) -> str:
        """
        生成格式化文本报告
        
        Args:
            port_infos: 端口信息列表
            target_ip: 目标IP地址
            
        Returns:
            格式化报告字符串
        """
        open_ports = [p for p in port_infos if p.state == "open"]
        summary = self.generate_scan_summary(port_infos)
        
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(f"端口扫描报告 - {target_ip}")
        report_lines.append("=" * 80)
        report_lines.append("")
        
        # 摘要信息
        report_lines.append("## 扫描摘要")
        report_lines.append(f"总端口数: {summary['total_ports']}")
        report_lines.append(f"开放端口: {summary['open_ports']}")
        report_lines.append(f"关闭端口: {summary['closed_ports']}")
        report_lines.append(f"过滤端口: {summary['filtered_ports']}")
        report_lines.append(f"Web服务: {summary['web_services']}")
        report_lines.append("")
        
        # 风险分布
        report_lines.append("## 风险分布")
        report_lines.append(f"高危: {summary['risk_distribution']['high']}")
        report_lines.append(f"中危: {summary['risk_distribution']['medium']}")
        report_lines.append(f"低危: {summary['risk_distribution']['low']}")
        report_lines.append(f"无风险: {summary['risk_distribution']['none']}")
        report_lines.append("")
        
        # 开放端口详情
        report_lines.append("## 开放端口详情")
        report_lines.append("-" * 80)
        for port_info in sorted(open_ports, key=lambda x: x.port):
            report_lines.append(f"\n端口: {port_info.port}")
            report_lines.append(f"  状态: {port_info.state}")
            report_lines.append(f"  服务: {port_info.service}")
            if port_info.product:
                report_lines.append(f"  产品: {port_info.product}")
            if port_info.version:
                report_lines.append(f"  版本: {port_info.version}")
            if port_info.web_server:
                report_lines.append(f"  Web服务器: {port_info.web_server}")
            if port_info.framework:
                report_lines.append(f"  框架: {port_info.framework}")
            if port_info.middleware:
                report_lines.append(f"  中间件: {port_info.middleware}")
            report_lines.append(f"  风险级别: {port_info.risk_level.upper()}")
            
            if port_info.known_vulnerabilities:
                report_lines.append(f"  已知漏洞: {', '.join(port_info.known_vulnerabilities)}")
            
            if port_info.security_recommendations:
                report_lines.append("  安全建议:")
                for rec in port_info.security_recommendations:
                    report_lines.append(f"    - {rec}")
        
        report_lines.append("")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)
    
    def export_to_json(self, port_infos: List[PortInfo], file_path: Optional[str] = None) -> str:
        """
        导出扫描结果到JSON格式
        
        Args:
            port_infos: 端口信息列表
            file_path: 文件路径（可选，如果提供则保存到文件）
            
        Returns:
            JSON字符串
        """
        import json
        
        # 转换为字典列表
        data = {
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self.generate_scan_summary(port_infos),
            'ports': [port_info.to_dict() for port_info in port_infos]
        }
        
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        
        # 如果提供了文件路径，保存到文件
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(json_str)
            self.logger.info(f"扫描结果已导出到: {file_path}")
        
        return json_str


class DVWACollectorError(Exception):
    """DVWA收集器异常基类"""
    pass


class DVWANotFoundError(DVWACollectorError):
    """DVWA未找到异常"""
    pass


class DVWATokenError(DVWACollectorError):
    """DVWA Token提取失败异常"""
    pass


class DVWACollector:
    """
    DVWA专属信息收集类
    
    功能特性：
    1. 自动发现DVWA登录页面
    2. 提取CSRF token（user_token）
    3. 获取安全级别配置
    4. 识别DVWA版本和模块
    5. 使用BeautifulSoup解析HTML
    6. 使用requests.Session保持会话
    7. 自动处理重定向和认证
    8. 支持代理配置
    """
    
    # DVWA常见页面路径
    DVWA_PAGES = {
        'login': '/login.php',
        'index': '/index.php',
        'security': '/security.php',
        'setup': '/setup.php',
        'about': '/about.php',
        'instructions': '/instructions.php',
        'vulnerabilities': '/vulnerabilities/',
    }
    
    # 可能的CSRF token字段名
    TOKEN_FIELD_NAMES = [
        'user_token',
        'csrf_token',
        '_token',
        'token',
        'csrf',
        '_csrf'
    ]
    
    # DVWA版本识别模式
    VERSION_PATTERNS = [
        r'DVWA\s+v?(\d+\.\d+(?:\.\d+)?)',
        r'Version\s+(\d+\.\d+(?:\.\d+)?)',
        r'v(\d+\.\d+(?:\.\d+)?)',
        r'(\d+\.\d+(?:\.\d+)?)\s+\(.*?DVWA',
    ]
    
    def __init__(
        self,
        base_url: str,
        timeout: int = 30,
        verify_ssl: bool = False,
        proxy: Optional[Union[str, Dict[str, str]]] = None,
        user_agent: Optional[str] = None,
        follow_redirects: bool = True
    ):
        """
        初始化DVWACollector
        
        Args:
            base_url: DVWA基础URL（如 http://192.168.1.100/dvwa）
            timeout: 请求超时时间（秒），默认30秒
            verify_ssl: 是否验证SSL证书，默认False（DVWA通常使用自签名证书）
            proxy: 代理配置，可以是字符串或字典
            user_agent: 自定义User-Agent，默认使用requests默认值
            follow_redirects: 是否自动跟随重定向，默认True
        """
        # 规范化base_url
        if not base_url.endswith('/'):
            base_url = base_url.rstrip('/')
        self.base_url = base_url
        
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        
        # 日志记录器
        self.logger = get_logger(__name__)
        
        # 检查依赖
        if not HAS_REQUESTS:
            raise DVWACollectorError("requests库未安装，请使用 'pip install requests' 安装")
        
        if not HAS_BS4:
            self.logger.warning(
                "BeautifulSoup4未安装，HTML解析功能将受限。"
                "请使用 'pip install beautifulsoup4' 安装。"
            )
        
        # 创建Session
        self.session = requests.Session()
        self.session.max_redirects = 10 if follow_redirects else 0
        
        # 配置请求头
        default_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if user_agent:
            default_headers['User-Agent'] = user_agent
        else:
            default_headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )
        
        self.session.headers.update(default_headers)
        
        # 配置SSL验证
        self.session.verify = verify_ssl
        
        # 配置代理
        if proxy:
            if isinstance(proxy, str):
                self.session.proxies = {
                    'http': proxy,
                    'https': proxy
                }
            else:
                self.session.proxies = proxy
            self.logger.info(f"已配置代理: {proxy}")
        
        # 禁用SSL警告（如果verify_ssl=False）
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # 缓存
        self._cached_pages: Dict[str, Dict[str, str]] = {}
        self._cached_tokens: Dict[str, Optional[str]] = {}
        self._cached_security_level: Optional[str] = None
        self._cached_version: Optional[str] = None
    
    def _make_request(
        self,
        url: str,
        method: str = 'GET',
        **kwargs
    ) -> requests.Response:
        """
        发送HTTP请求（带错误处理）
        
        Args:
            url: 请求URL
            method: HTTP方法（GET/POST等）
            **kwargs: 其他requests参数
            
        Returns:
            Response对象
            
        Raises:
            DVWACollectorError: 请求失败时抛出
        """
        try:
            # 确保URL完整
            if not url.startswith('http'):
                url = urljoin(self.base_url, url)
            
            self.logger.debug(f"发送{method}请求: {url}")
            
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                **kwargs
            )
            
            response.raise_for_status()
            
            return response
            
        except requests.exceptions.Timeout as e:
            error_msg = f"请求超时: {url} (超时时间: {self.timeout}秒)"
            self.logger.error(error_msg)
            raise DVWACollectorError(error_msg) from e
            
        except requests.exceptions.ConnectionError as e:
            error_msg = f"连接失败: {url} - {str(e)}"
            self.logger.error(error_msg)
            raise DVWACollectorError(error_msg) from e
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP错误: {url} - {e.response.status_code} {e.response.reason}"
            self.logger.error(error_msg)
            raise DVWACollectorError(error_msg) from e
            
        except requests.exceptions.RequestException as e:
            error_msg = f"请求异常: {url} - {str(e)}"
            self.logger.error(error_msg)
            raise DVWACollectorError(error_msg) from e
    
    def _parse_html(self, html: str) -> Optional[BeautifulSoup]:
        """
        解析HTML内容
        
        Args:
            html: HTML字符串
            
        Returns:
            BeautifulSoup对象，如果解析失败返回None
        """
        if not HAS_BS4:
            self.logger.warning("BeautifulSoup4未安装，无法解析HTML")
            return None
        
        try:
            return BeautifulSoup(html, 'html.parser')
        except Exception as e:
            self.logger.warning(f"HTML解析失败: {e}")
            return None
    
    def discover_dvwa_pages(self, base_url: Optional[str] = None) -> Dict[str, str]:
        """
        自动发现DVWA页面
        
        Args:
            base_url: 基础URL，如果为None则使用初始化时的base_url
            
        Returns:
            字典，键为页面名称，值为页面URL
            
        Raises:
            DVWANotFoundError: 如果未找到DVWA时抛出
        """
        if base_url is None:
            base_url = self.base_url
        
        self.logger.info(f"开始发现DVWA页面: {base_url}")
        
        discovered_pages = {}
        
        # 检查缓存
        cache_key = f"pages_{base_url}"
        if cache_key in self._cached_pages:
            self.logger.debug("使用缓存的页面发现结果")
            return self._cached_pages[cache_key].copy()
        
        # 尝试访问常见DVWA页面
        for page_name, page_path in self.DVWA_PAGES.items():
            try:
                full_url = urljoin(base_url, page_path)
                self.logger.debug(f"尝试访问: {full_url}")
                
                response = self._make_request(full_url)
                
                # 检查响应内容是否包含DVWA特征
                if self._is_dvwa_page(response.text):
                    discovered_pages[page_name] = full_url
                    self.logger.info(f"发现DVWA页面: {page_name} -> {full_url}")
                else:
                    self.logger.debug(f"页面 {full_url} 不是DVWA页面")
                    
            except DVWACollectorError:
                # 页面不存在或无法访问，继续尝试下一个
                self.logger.debug(f"无法访问页面: {page_path}")
                continue
            except Exception as e:
                self.logger.warning(f"检查页面 {page_path} 时出错: {e}")
                continue
        
        # 如果未发现任何页面，尝试访问根路径
        if not discovered_pages:
            try:
                response = self._make_request(base_url)
                if self._is_dvwa_page(response.text):
                    discovered_pages['root'] = base_url
                    self.logger.info(f"发现DVWA根页面: {base_url}")
            except Exception as e:
                self.logger.debug(f"无法访问根路径: {e}")
        
        if not discovered_pages:
            error_msg = f"未发现DVWA页面，请确认URL是否正确: {base_url}"
            self.logger.error(error_msg)
            raise DVWANotFoundError(error_msg)
        
        # 缓存结果
        self._cached_pages[cache_key] = discovered_pages.copy()
        
        self.logger.info(f"共发现 {len(discovered_pages)} 个DVWA页面")
        return discovered_pages
    
    def _is_dvwa_page(self, html: str) -> bool:
        """
        判断是否为DVWA页面
        
        Args:
            html: HTML内容
            
        Returns:
            如果是DVWA页面返回True，否则返回False
        """
        dvwa_indicators = [
            'DVWA',
            'Damn Vulnerable Web Application',
            'login.php',
            'security.php',
            'setup.php',
            'vulnerabilities/',
            'user_token',
        ]
        
        html_lower = html.lower()
        found_indicators = sum(1 for indicator in dvwa_indicators if indicator.lower() in html_lower)
        
        # 如果找到至少2个指标，认为是DVWA页面
        return found_indicators >= 2
    
    def extract_login_token(self, login_url: Optional[str] = None) -> str:
        """
        提取登录页面的CSRF token（user_token）
        
        Args:
            login_url: 登录页面URL，如果为None则自动发现
            
        Returns:
            CSRF token字符串
            
        Raises:
            DVWATokenError: 如果无法提取token时抛出
        """
        # 检查缓存
        if login_url:
            cache_key = f"token_{login_url}"
        else:
            cache_key = "token_default"
        
        if cache_key in self._cached_tokens and self._cached_tokens[cache_key]:
            self.logger.debug("使用缓存的token")
            return self._cached_tokens[cache_key]
        
        # 如果没有提供登录URL，尝试自动发现
        if login_url is None:
            try:
                pages = self.discover_dvwa_pages()
                if 'login' in pages:
                    login_url = pages['login']
                elif 'index' in pages:
                    login_url = pages['index']
                else:
                    # 尝试直接访问登录页面
                    login_url = urljoin(self.base_url, self.DVWA_PAGES['login'])
            except DVWANotFoundError:
                # 如果无法发现页面，尝试默认路径
                login_url = urljoin(self.base_url, self.DVWA_PAGES['login'])
        
        self.logger.info(f"开始提取登录token: {login_url}")
        
        try:
            # 获取登录页面
            response = self._make_request(login_url)
            html = response.text
            
            # 使用BeautifulSoup解析
            soup = self._parse_html(html)
            if soup:
                # 方法1: 使用BeautifulSoup查找
                token = self._extract_token_from_soup(soup)
                if token:
                    self.logger.info(f"成功提取token: {token[:20]}...")
                    self._cached_tokens[cache_key] = token
                    return token
            
            # 方法2: 使用正则表达式查找
            token = self._extract_token_from_regex(html)
            if token:
                self.logger.info(f"成功提取token (正则): {token[:20]}...")
                self._cached_tokens[cache_key] = token
                return token
            
            # 如果都失败，抛出异常
            error_msg = f"无法从登录页面提取token: {login_url}"
            self.logger.error(error_msg)
            raise DVWATokenError(error_msg)
            
        except DVWATokenError:
            raise
        except Exception as e:
            error_msg = f"提取token时出错: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise DVWATokenError(error_msg) from e
    
    def _extract_token_from_soup(self, soup: BeautifulSoup) -> Optional[str]:
        """
        从BeautifulSoup对象中提取token
        
        Args:
            soup: BeautifulSoup对象
            
        Returns:
            token字符串，如果未找到返回None
        """
        if not soup:
            return None
        
        # 尝试所有可能的字段名
        for field_name in self.TOKEN_FIELD_NAMES:
            # 查找 <input type="hidden" name="user_token" value="...">
            input_tag = soup.find('input', {
                'type': 'hidden',
                'name': field_name
            })
            
            if input_tag and input_tag.get('value'):
                token = input_tag.get('value')
                if token and len(token) > 0:
                    self.logger.debug(f"从BeautifulSoup提取到token (字段: {field_name})")
                    return token
        
        return None
    
    def _extract_token_from_regex(self, html: str) -> Optional[str]:
        """
        使用正则表达式从HTML中提取token
        
        Args:
            html: HTML字符串
            
        Returns:
            token字符串，如果未找到返回None
        """
        # 尝试所有可能的字段名
        for field_name in self.TOKEN_FIELD_NAMES:
            # 模式1: <input type="hidden" name="user_token" value="...">
            pattern1 = rf'<input[^>]*type=["\']hidden["\'][^>]*name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)["\']'
            match = re.search(pattern1, html, re.IGNORECASE)
            if match:
                token = match.group(1)
                if token and len(token) > 0:
                    self.logger.debug(f"从正则表达式提取到token (字段: {field_name}, 模式1)")
                    return token
            
            # 模式2: <input type="hidden" value="..." name="user_token">
            pattern2 = rf'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\'][^>]*name=["\']{re.escape(field_name)}["\']'
            match = re.search(pattern2, html, re.IGNORECASE)
            if match:
                token = match.group(1)
                if token and len(token) > 0:
                    self.logger.debug(f"从正则表达式提取到token (字段: {field_name}, 模式2)")
                    return token
        
        return None
    
    def get_security_level(self, session: Optional[requests.Session] = None, base_url: Optional[str] = None) -> str:
        """
        获取DVWA安全级别配置
        
        Args:
            session: 可选的Session对象，如果为None则使用内部session
            base_url: 基础URL，如果为None则使用初始化时的base_url
            
        Returns:
            安全级别字符串（如 "low", "medium", "high", "impossible"）
            
        Raises:
            DVWACollectorError: 如果无法获取安全级别时抛出
        """
        # 使用提供的session或内部session
        if session is None:
            session = self.session
        
        if base_url is None:
            base_url = self.base_url
        
        # 检查缓存
        if self._cached_security_level:
            self.logger.debug("使用缓存的安全级别")
            return self._cached_security_level
        
        self.logger.info("开始获取DVWA安全级别")
        
        try:
            # 尝试访问安全设置页面
            security_url = urljoin(base_url, self.DVWA_PAGES['security'])
            
            response = self._make_request(security_url)
            html = response.text
            
            # 使用BeautifulSoup解析
            soup = self._parse_html(html)
            if soup:
                # 查找安全级别选择框
                select_tag = soup.find('select', {'name': 'security'})
                if select_tag:
                    # 查找选中的选项
                    selected_option = select_tag.find('option', selected=True)
                    if selected_option:
                        security_level = selected_option.get('value', '').lower()
                        if security_level:
                            self.logger.info(f"获取到安全级别: {security_level}")
                            self._cached_security_level = security_level
                            return security_level
            
            # 使用正则表达式查找
            patterns = [
                r'<select[^>]*name=["\']security["\'][^>]*>.*?<option[^>]*value=["\']([^"\']+)["\'][^>]*selected',
                r'<option[^>]*value=["\']([^"\']+)["\'][^>]*selected[^>]*>.*?Security Level',
                r'Security Level[^<]*<option[^>]*value=["\']([^"\']+)["\'][^>]*selected',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
                if match:
                    security_level = match.group(1).lower()
                    if security_level in ['low', 'medium', 'high', 'impossible']:
                        self.logger.info(f"获取到安全级别 (正则): {security_level}")
                        self._cached_security_level = security_level
                        return security_level
            
            # 如果都失败，返回默认值
            self.logger.warning("无法获取安全级别，返回默认值 'unknown'")
            return 'unknown'
            
        except Exception as e:
            error_msg = f"获取安全级别时出错: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            raise DVWACollectorError(error_msg) from e
    
    def detect_dvwa_version(self, base_url: Optional[str] = None) -> str:
        """
        识别DVWA版本和模块
        
        Args:
            base_url: 基础URL，如果为None则使用初始化时的base_url
            
        Returns:
            版本字符串（如 "1.10", "2.0"），如果无法识别返回 "unknown"
        """
        if base_url is None:
            base_url = self.base_url
        
        # 检查缓存
        if self._cached_version:
            self.logger.debug("使用缓存的版本信息")
            return self._cached_version
        
        self.logger.info("开始检测DVWA版本")
        
        try:
            # 尝试多个页面查找版本信息
            pages_to_check = ['index', 'about', 'instructions', 'setup']
            
            for page_name in pages_to_check:
                try:
                    page_url = urljoin(base_url, self.DVWA_PAGES.get(page_name, '/'))
                    response = self._make_request(page_url)
                    html = response.text
                    
                    # 使用正则表达式匹配版本
                    for pattern in self.VERSION_PATTERNS:
                        match = re.search(pattern, html, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            self.logger.info(f"检测到DVWA版本: {version} (从页面: {page_name})")
                            self._cached_version = version
                            return version
                    
                    # 使用BeautifulSoup查找
                    soup = self._parse_html(html)
                    if soup:
                        # 查找包含版本信息的文本
                        text_content = soup.get_text()
                        for pattern in self.VERSION_PATTERNS:
                            match = re.search(pattern, text_content, re.IGNORECASE)
                            if match:
                                version = match.group(1)
                                self.logger.info(f"检测到DVWA版本: {version} (从文本内容)")
                                self._cached_version = version
                                return version
                
                except Exception as e:
                    self.logger.debug(f"检查页面 {page_name} 时出错: {e}")
                    continue
            
            # 如果都失败，返回unknown
            self.logger.warning("无法检测DVWA版本")
            return 'unknown'
            
        except Exception as e:
            self.logger.warning(f"检测版本时出错: {e}")
            return 'unknown'
    
    def clear_cache(self):
        """清除所有缓存"""
        self._cached_pages.clear()
        self._cached_tokens.clear()
        self._cached_security_level = None
        self._cached_version = None
        self.logger.info("已清除所有缓存")
    
    def close(self):
        """关闭Session"""
        if self.session:
            self.session.close()
            self.logger.info("Session已关闭")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()


@dataclass
class PathResult:
    """
    路径扫描结果数据类
    
    属性：
        url: 完整URL
        status_code: HTTP状态码
        content_type: 内容类型
        content_length: 内容长度（字节）
        exists: 路径是否存在
        is_directory: 是否为目录
        title: HTML页面标题
        description: 路径描述
        has_directory_listing: 是否存在目录列表漏洞
        response_time: 响应时间（毫秒）
    """
    url: str
    status_code: int = 0
    content_type: str = ""
    content_length: int = 0
    exists: bool = False
    is_directory: bool = False
    title: str = ""
    description: str = ""
    has_directory_listing: bool = False
    response_time: float = 0.0
    
    def to_dict(self) -> Dict:
        """
        转换为字典格式
        
        Returns:
            路径结果字典
        """
        return {
            'url': self.url,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'content_length': self.content_length,
            'exists': self.exists,
            'is_directory': self.is_directory,
            'title': self.title,
            'description': self.description,
            'has_directory_listing': self.has_directory_listing,
            'response_time': self.response_time
        }
    
    def __repr__(self) -> str:
        return (
            f"PathResult(url={self.url}, status={self.status_code}, "
            f"exists={self.exists}, is_dir={self.is_directory})"
        )


class PathScannerError(Exception):
    """路径扫描器异常基类"""
    pass


class PathScanner:
    """
    基础路径扫描类
    
    功能特性：
    1. 验证DVWA核心目录的可达性
    2. 支持自定义路径列表扫描
    3. 检测目录和文件的存在
    4. 记录HTTP状态码和响应信息
    5. 支持并发扫描提高效率
    6. 包含超时控制
    7. 自动识别目录列表漏洞
    8. 集成到统一的信息收集流程
    """
    
    # DVWA核心路径列表
    DVWA_CORE_PATHS = {
        '/vulnerabilities/': '漏洞模块入口',
        '/hackable/': '可上传目录',
        '/config/': '配置文件目录',
        '/docs/': '文档目录',
        '/external/': '外部资源',
        '/login.php': '登录页面',
        '/setup.php': '设置页面',
        '/security.php': '安全级别设置页面',
    }
    
    # 目录列表漏洞特征
    DIRECTORY_LISTING_INDICATORS = [
        'Index of',
        'Directory Listing',
        'Directory of',
        'Parent Directory',
        'Last modified',
        'Size',
        'Name',
        '<title>Index of',
        'Apache/2',
        'nginx',
        'IIS',
    ]
    
    # 目录特征
    DIRECTORY_INDICATORS = [
        'Directory Listing',
        'Index of',
        'Parent Directory',
        '</a></td>',  # 目录列表中的链接格式
    ]
    
    def __init__(
        self,
        timeout: int = 10,
        max_workers: int = 10,
        verify_ssl: bool = False,
        proxy: Optional[Union[str, Dict[str, str]]] = None,
        user_agent: Optional[str] = None,
        follow_redirects: bool = True,
        enable_directory_listing_detection: bool = True
    ):
        """
        初始化PathScanner
        
        Args:
            timeout: 请求超时时间（秒），默认10秒
            max_workers: 并发线程数，默认10
            verify_ssl: 是否验证SSL证书，默认False
            proxy: 代理配置，可以是字符串或字典
            user_agent: 自定义User-Agent
            follow_redirects: 是否自动跟随重定向，默认True
            enable_directory_listing_detection: 是否启用目录列表漏洞检测，默认True
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.enable_directory_listing_detection = enable_directory_listing_detection
        
        # 日志记录器
        self.logger = get_logger(__name__)
        
        # 检查依赖
        if not HAS_REQUESTS:
            raise PathScannerError("requests库未安装，请使用 'pip install requests' 安装")
        
        if not HAS_BS4:
            self.logger.warning(
                "BeautifulSoup4未安装，HTML解析功能将受限。"
                "请使用 'pip install beautifulsoup4' 安装。"
            )
        
        # 创建Session
        self.session = requests.Session()
        self.session.max_redirects = 10 if follow_redirects else 0
        
        # 配置请求头
        default_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        if user_agent:
            default_headers['User-Agent'] = user_agent
        else:
            default_headers['User-Agent'] = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                '(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            )
        
        self.session.headers.update(default_headers)
        
        # 配置SSL验证
        self.session.verify = verify_ssl
        
        # 配置代理
        if proxy:
            if isinstance(proxy, str):
                self.session.proxies = {
                    'http': proxy,
                    'https': proxy
                }
            else:
                self.session.proxies = proxy
            self.logger.info(f"已配置代理: {proxy}")
        
        # 禁用SSL警告（如果verify_ssl=False）
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def scan_dvwa_paths(
        self,
        base_url: str,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> List[PathResult]:
        """
        扫描DVWA核心路径
        
        Args:
            base_url: 基础URL（如 http://192.168.1.100/dvwa）
            progress_callback: 进度回调函数，参数为(当前路径, 已完成数, 总数)
            
        Returns:
            路径扫描结果列表
        """
        self.logger.info(f"开始扫描DVWA核心路径: {base_url}")
        
        paths = list(self.DVWA_CORE_PATHS.keys())
        descriptions = list(self.DVWA_CORE_PATHS.values())
        
        return self.scan_custom_paths(
            base_url=base_url,
            paths=paths,
            descriptions=descriptions,
            progress_callback=progress_callback
        )
    
    def scan_custom_paths(
        self,
        base_url: str,
        paths: List[str],
        descriptions: Optional[List[str]] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> List[PathResult]:
        """
        扫描自定义路径列表
        
        Args:
            base_url: 基础URL
            paths: 路径列表（相对路径）
            descriptions: 路径描述列表（可选，与paths一一对应）
            progress_callback: 进度回调函数，参数为(当前路径, 已完成数, 总数)
            
        Returns:
            路径扫描结果列表
        """
        self.logger.info(f"开始扫描自定义路径: {base_url}, 共 {len(paths)} 个路径")
        
        if descriptions is None:
            descriptions = [''] * len(paths)
        
        if len(descriptions) != len(paths):
            self.logger.warning("描述列表长度与路径列表不匹配，将使用空描述")
            descriptions = [''] * len(paths)
        
        # 构建完整URL列表
        url_descriptions = []
        for path, desc in zip(paths, descriptions):
            full_url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
            url_descriptions.append((full_url, desc))
        
        # 并发扫描
        results = []
        completed = 0
        total = len(url_descriptions)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # 提交所有任务
            future_to_url = {
                executor.submit(self.check_path_accessibility, url, desc): url
                for url, desc in url_descriptions
            }
            
            # 收集结果
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if progress_callback:
                        progress_callback(url, completed, total)
                    
                    self.logger.debug(
                        f"路径扫描完成 [{completed}/{total}]: {url} - "
                        f"状态码: {result.status_code}, 存在: {result.exists}"
                    )
                    
                except Exception as e:
                    self.logger.error(f"扫描路径 {url} 时出错: {e}", exc_info=True)
                    # 创建错误结果
                    # 查找对应的描述
                    desc = ''
                    for u, d in url_descriptions:
                        if u == url:
                            desc = d
                            break
                    
                    error_result = PathResult(
                        url=url,
                        status_code=0,
                        exists=False,
                        description=desc
                    )
                    results.append(error_result)
                    
                    if progress_callback:
                        progress_callback(url, completed, total)
        
        # 按URL排序结果
        results.sort(key=lambda x: x.url)
        
        self.logger.info(
            f"路径扫描完成: {base_url}, "
            f"共扫描 {len(results)} 个路径, "
            f"发现 {sum(1 for r in results if r.exists)} 个存在的路径"
        )
        
        return results
    
    def check_path_accessibility(
        self,
        url: str,
        description: str = ""
    ) -> PathResult:
        """
        检查单个路径的可达性
        
        Args:
            url: 完整URL
            description: 路径描述
            
        Returns:
            PathResult对象
        """
        start_time = time.time()
        
        try:
            # 发送HEAD请求（更快，不下载内容）
            try:
                response = self.session.head(
                    url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
                use_head = True
            except requests.exceptions.RequestException:
                # 如果HEAD失败，尝试GET请求
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    stream=True  # 流式下载，只读取头部
                )
                use_head = False
            
            response_time = (time.time() - start_time) * 1000  # 转换为毫秒
            
            # 获取基本信息
            status_code = response.status_code
            content_type = response.headers.get('Content-Type', '')
            content_length = int(response.headers.get('Content-Length', 0))
            
            # 判断路径是否存在（2xx和3xx状态码认为存在）
            exists = 200 <= status_code < 400
            
            # 判断是否为目录（通过URL和Content-Type）
            is_directory = self._detect_directory(url, content_type, response)
            
            # 提取页面标题（如果是HTML）
            title = ""
            has_directory_listing = False
            
            if exists and 'text/html' in content_type.lower():
                # 需要获取完整内容来解析标题和检测目录列表
                if use_head:
                    # HEAD请求没有内容，需要发送GET请求
                    get_response = self.session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects
                    )
                    html_content = get_response.text
                else:
                    html_content = response.text
                
                # 提取标题
                title = self._extract_title(html_content)
                
                # 检测目录列表漏洞
                if self.enable_directory_listing_detection:
                    has_directory_listing = self._detect_directory_listing(html_content)
            
            result = PathResult(
                url=url,
                status_code=status_code,
                content_type=content_type,
                content_length=content_length,
                exists=exists,
                is_directory=is_directory,
                title=title,
                description=description,
                has_directory_listing=has_directory_listing,
                response_time=response_time
            )
            
            return result
            
        except requests.exceptions.Timeout:
            response_time = (time.time() - start_time) * 1000
            self.logger.warning(f"路径扫描超时: {url} (超时时间: {self.timeout}秒)")
            return PathResult(
                url=url,
                status_code=0,
                exists=False,
                description=description,
                response_time=response_time
            )
            
        except requests.exceptions.ConnectionError as e:
            response_time = (time.time() - start_time) * 1000
            self.logger.warning(f"路径扫描连接失败: {url} - {str(e)}")
            return PathResult(
                url=url,
                status_code=0,
                exists=False,
                description=description,
                response_time=response_time
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.logger.error(f"路径扫描异常: {url} - {str(e)}", exc_info=True)
            return PathResult(
                url=url,
                status_code=0,
                exists=False,
                description=description,
                response_time=response_time
            )
    
    def _detect_directory(
        self,
        url: str,
        content_type: str,
        response: requests.Response
    ) -> bool:
        """
        检测是否为目录
        
        Args:
            url: URL
            content_type: Content-Type响应头
            response: Response对象
            
        Returns:
            如果是目录返回True，否则返回False
        """
        # 方法1: 检查URL是否以/结尾
        if url.rstrip('/').endswith('/') or url.endswith('/'):
            return True
        
        # 方法2: 检查Content-Type
        if 'text/html' in content_type.lower():
            # 可能是目录列表页面
            return True
        
        # 方法3: 检查响应头中的Content-Type是否为text/html且URL看起来像目录
        parsed_url = urlparse(url)
        if parsed_url.path.endswith('/'):
            return True
        
        return False
    
    def _extract_title(self, html_content: str) -> str:
        """
        从HTML内容中提取页面标题
        
        Args:
            html_content: HTML内容
            
        Returns:
            页面标题，如果未找到返回空字符串
        """
        if not HAS_BS4:
            # 使用正则表达式提取
            match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                # 清理标题中的换行和多余空格
                title = re.sub(r'\s+', ' ', title)
                return title
            return ""
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text().strip()
                # 清理标题中的换行和多余空格
                title = re.sub(r'\s+', ' ', title)
                return title
        except Exception as e:
            self.logger.debug(f"提取标题时出错: {e}")
        
        return ""
    
    def _detect_directory_listing(self, html_content: str) -> bool:
        """
        检测是否存在目录列表漏洞
        
        Args:
            html_content: HTML内容
            
        Returns:
            如果存在目录列表漏洞返回True，否则返回False
        """
        html_lower = html_content.lower()
        
        # 检查目录列表特征
        found_indicators = 0
        
        for indicator in self.DIRECTORY_LISTING_INDICATORS:
            if indicator.lower() in html_lower:
                found_indicators += 1
        
        # 检查目录列表的HTML结构特征
        directory_patterns = [
            r'<a\s+href=["\']\.\./["\']',  # Parent Directory链接
            r'<a\s+href=["\'][^"\']+["\']>\s*\.\./',  # Parent Directory链接（另一种格式）
            r'<table[^>]*>.*?<a\s+href',  # 表格中的链接（目录列表常见格式）
        ]
        
        for pattern in directory_patterns:
            if re.search(pattern, html_content, re.IGNORECASE | re.DOTALL):
                found_indicators += 1
                break
        
        # 如果找到至少2个指标，认为存在目录列表漏洞
        return found_indicators >= 2
    
    def close(self):
        """关闭Session"""
        if self.session:
            self.session.close()
            self.logger.info("Session已关闭")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()


# 占位类，待实现
class InfoGatheringManager:
    """统一管理所有收集功能（待实现）"""
    pass

