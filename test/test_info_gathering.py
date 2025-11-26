"""
信息收集模块测试套件

使用pytest框架进行测试，包含NmapScanner、DVWACollector、PathScanner的完整测试
"""

import pytest
import sys
import json
import time
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from typing import Dict, List

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.info_gathering import (
    PortInfo,
    NmapScanner,
    NmapScannerError,
    NmapNotInstalledError,
    NmapScanError,
    DVWACollector,
    DVWACollectorError,
    DVWANotFoundError,
    DVWATokenError,
    PathResult,
    PathScanner,
    PathScannerError,
    InfoGatheringManager
)

try:
    import requests_mock
    HAS_REQUESTS_MOCK = True
except ImportError:
    HAS_REQUESTS_MOCK = False
    requests_mock = None

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False
    nmap = None


# ==================== Fixtures ====================

@pytest.fixture
def mock_nmap_scanner():
    """创建模拟的nmap扫描器"""
    mock_scanner = MagicMock()
    return mock_scanner


@pytest.fixture
def sample_nmap_result():
    """示例nmap扫描结果"""
    return {
        'scan': {
            '127.0.0.1': {
                'tcp': {
                    '80': {
                        'state': 'open',
                        'name': 'http',
                        'product': 'Apache httpd',
                        'version': '2.4.49',
                        'extrainfo': 'Ubuntu'
                    },
                    '443': {
                        'state': 'open',
                        'name': 'https',
                        'product': 'nginx',
                        'version': '1.18.0',
                        'extrainfo': ''
                    },
                    '22': {
                        'state': 'open',
                        'name': 'ssh',
                        'product': 'OpenSSH',
                        'version': '8.2p1',
                        'extrainfo': 'Ubuntu-4ubuntu0.5'
                    },
                    '3306': {
                        'state': 'closed',
                        'name': 'mysql',
                        'product': '',
                        'version': '',
                        'extrainfo': ''
                    }
                }
            }
        }
    }


@pytest.fixture
def sample_port_infos():
    """示例端口信息列表"""
    return [
        PortInfo(
            port=80,
            state='open',
            service='http',
            version='2.4.49',
            product='Apache httpd',
            extra_info='Ubuntu',
            is_web_service=True
        ),
        PortInfo(
            port=443,
            state='open',
            service='https',
            version='1.18.0',
            product='nginx',
            extra_info='',
            is_web_service=True
        ),
        PortInfo(
            port=22,
            state='open',
            service='ssh',
            version='8.2p1',
            product='OpenSSH',
            extra_info='Ubuntu-4ubuntu0.5',
            is_web_service=False
        )
    ]


@pytest.fixture
def dvwa_login_html():
    """DVWA登录页面HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login :: Damn Vulnerable Web Application</title>
    </head>
    <body>
        <form method="post" action="login.php">
            <input type="hidden" name="user_token" value="abc123def456ghi789">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """


@pytest.fixture
def dvwa_security_html():
    """DVWA安全级别页面HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>DVWA Security</title>
    </head>
    <body>
        <form method="post" action="security.php">
            <select name="security">
                <option value="low" selected>Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="impossible">Impossible</option>
            </select>
            <button type="submit">Submit</button>
        </form>
    </body>
    </html>
    """


@pytest.fixture
def directory_listing_html():
    """目录列表页面HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Index of /hackable/</title>
    </head>
    <body>
        <h1>Index of /hackable/</h1>
        <table>
            <tr><td><a href="../">Parent Directory</a></td></tr>
            <tr><td><a href="uploads/">uploads/</a></td></tr>
            <tr><td><a href="images/">images/</a></td></tr>
        </table>
    </body>
    </html>
    """


# ==================== NmapScanner 测试 ====================

class TestNmapScanner:
    """NmapScanner测试类"""
    
    def test_nmap_scanner_init(self):
        """测试NmapScanner初始化"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner(
                    scan_timeout=100,
                    scan_delay=1.0,
                    max_retries=2
                )
                
                assert scanner.scan_timeout == 100
                assert scanner.scan_delay == 1.0
                assert scanner.max_retries == 2
                assert scanner._nmap_scanner is not None
    
    def test_nmap_scanner_init_no_nmap(self):
        """测试NmapScanner初始化（无nmap）"""
        with patch('src.modules.info_gathering.HAS_NMAP', False):
            with patch('src.modules.info_gathering.NmapScanner._check_nmap_command', return_value=False):
                with pytest.raises(NmapNotInstalledError):
                    NmapScanner()
    
    def test_parse_nmap_result(self, sample_nmap_result):
        """测试解析nmap扫描结果"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                port_infos = scanner._parse_nmap_result(sample_nmap_result, '127.0.0.1')
                
                assert len(port_infos) == 4
                assert port_infos[0].port == 80
                assert port_infos[0].state == 'open'
                assert port_infos[0].service == 'http'
                assert port_infos[0].product == 'Apache httpd'
                assert port_infos[0].version == '2.4.49'
    
    def test_scan_web_ports(self, sample_nmap_result):
        """测试扫描Web端口"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                ports = scanner.scan_web_ports('127.0.0.1')
                
                assert len(ports) > 0
                assert all(isinstance(p, PortInfo) for p in ports)
    
    def test_scan_custom_ports(self, sample_nmap_result):
        """测试扫描自定义端口"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                ports = scanner.scan_custom_ports('127.0.0.1', [80, 443])
                
                assert len(ports) > 0
    
    def test_scan_custom_ports_with_list(self, sample_nmap_result):
        """测试扫描自定义端口（列表格式）"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                ports = scanner.scan_custom_ports('127.0.0.1', [22, 80, 443])
                
                assert isinstance(ports, list)
    
    def test_scan_custom_ports_with_range(self, sample_nmap_result):
        """测试扫描自定义端口（范围格式）"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                ports = scanner.scan_custom_ports('127.0.0.1', '80-100')
                
                assert isinstance(ports, list)
    
    def test_get_service_banner(self, sample_port_infos):
        """测试获取服务Banner"""
        scanner = NmapScanner()
        port_info = sample_port_infos[0]
        
        # 测试从已有信息提取banner
        banner = scanner.get_service_banner(port_info)
        assert isinstance(banner, str)
    
    def test_detect_os(self, sample_nmap_result):
        """测试操作系统检测"""
        os_result = {
            'scan': {
                '127.0.0.1': {
                    'osmatch': [
                        {'name': 'Linux 5.4', 'accuracy': '95'}
                    ],
                    'osclass': [
                        {'type': 'general purpose', 'vendor': 'Linux'}
                    ]
                }
            }
        }
        
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = os_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner(enable_os_detection=True)
                os_info = scanner.detect_os('127.0.0.1')
                
                assert isinstance(os_info, str)
    
    def test_identify_service_fingerprint(self, sample_port_infos):
        """测试服务指纹识别"""
        scanner = NmapScanner()
        port_info = sample_port_infos[0]  # Apache
        
        result = scanner.identify_service_fingerprint(port_info)
        
        assert result.web_server != ""
        assert 'Apache' in result.web_server
    
    def test_assess_security_risk(self, sample_port_infos):
        """测试安全风险评估"""
        scanner = NmapScanner()
        port_info = sample_port_infos[0]  # Apache 2.4.49 (高危版本)
        
        result = scanner.assess_security_risk(port_info)
        
        assert result.risk_level in ['high', 'medium', 'low', 'none']
        if result.risk_level == 'high':
            assert len(result.known_vulnerabilities) > 0
    
    def test_scan_ports_parallel(self, sample_nmap_result):
        """测试并行扫描"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                ports = scanner.scan_ports_parallel('127.0.0.1', [80, 443, 8080], max_workers=2)
                
                assert isinstance(ports, list)
    
    def test_generate_scan_summary(self, sample_port_infos):
        """测试生成扫描摘要"""
        scanner = NmapScanner()
        summary = scanner.generate_scan_summary(sample_port_infos)
        
        assert 'total_ports' in summary
        assert 'open_ports' in summary
        assert 'risk_distribution' in summary
        assert summary['total_ports'] == len(sample_port_infos)
    
    def test_generate_formatted_report(self, sample_port_infos):
        """测试生成格式化报告"""
        scanner = NmapScanner()
        report = scanner.generate_formatted_report(sample_port_infos, '127.0.0.1')
        
        assert isinstance(report, str)
        assert '127.0.0.1' in report
        assert '端口' in report or 'Port' in report
    
    def test_export_to_json(self, sample_port_infos, tmp_path):
        """测试导出JSON格式"""
        scanner = NmapScanner()
        json_file = tmp_path / 'test_scan.json'
        
        json_str = scanner.export_to_json(sample_port_infos, str(json_file))
        
        assert isinstance(json_str, str)
        assert json_file.exists()
        
        # 验证JSON内容
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        assert 'scan_time' in data
        assert 'summary' in data
        assert 'ports' in data
        assert len(data['ports']) == len(sample_port_infos)
    
    def test_cache_mechanism(self, sample_nmap_result):
        """测试缓存机制"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner()
                
                # 第一次扫描
                ports1 = scanner.scan_web_ports('127.0.0.1')
                cache_size1 = scanner.get_cache_size()
                
                # 第二次扫描（应该使用缓存）
                ports2 = scanner.scan_web_ports('127.0.0.1')
                cache_size2 = scanner.get_cache_size()
                
                assert cache_size1 == cache_size2
                assert len(ports1) == len(ports2)
                
                # 清除缓存
                scanner.clear_cache('127.0.0.1')
                assert scanner.get_cache_size() == 0
    
    def test_clear_cache(self):
        """测试清除缓存"""
        scanner = NmapScanner()
        scanner._scan_cache['test_key'] = []
        
        scanner.clear_cache()
        assert scanner.get_cache_size() == 0
    
    def test_error_handling_scan_failure(self):
        """测试扫描失败错误处理"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.side_effect = Exception("Scan failed")
                mock_port_scanner.return_value = mock_scanner
                
                scanner = NmapScanner(max_retries=1)
                
                with pytest.raises(NmapScanError):
                    scanner.scan_web_ports('127.0.0.1')


# ==================== DVWACollector 测试 ====================

@pytest.mark.skipif(not HAS_REQUESTS_MOCK, reason="requests_mock not installed")
class TestDVWACollector:
    """DVWACollector测试类"""
    
    def test_dvwacollector_init(self):
        """测试DVWACollector初始化"""
        collector = DVWACollector(
            base_url="http://192.168.1.100/dvwa",
            timeout=30,
            verify_ssl=False
        )
        
        assert collector.base_url == "http://192.168.1.100/dvwa"
        assert collector.timeout == 30
        assert collector.verify_ssl is False
        assert collector.session is not None
        
        collector.close()
    
    def test_extract_login_token(self, dvwa_login_html):
        """测试提取登录token"""
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/login.php', text=dvwa_login_html)
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            token = collector.extract_login_token()
            
            assert token == "abc123def456ghi789"
            collector.close()
    
    def test_extract_login_token_not_found(self):
        """测试提取token失败"""
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/login.php', text="<html><body>No token</body></html>")
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            
            with pytest.raises(DVWATokenError):
                collector.extract_login_token()
            
            collector.close()
    
    def test_get_security_level(self, dvwa_security_html):
        """测试获取安全级别"""
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/security.php', text=dvwa_security_html)
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            security_level = collector.get_security_level()
            
            assert security_level == "low"
            collector.close()
    
    def test_discover_dvwa_pages(self):
        """测试发现DVWA页面"""
        dvwa_index_html = """
        <html>
        <head><title>DVWA</title></head>
        <body>
            <h1>Damn Vulnerable Web Application</h1>
            <a href="login.php">Login</a>
            <a href="security.php">Security</a>
        </body>
        </html>
        """
        
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/login.php', text=dvwa_index_html)
            m.get('http://192.168.1.100/dvwa/index.php', text=dvwa_index_html)
            m.get('http://192.168.1.100/dvwa/security.php', text=dvwa_index_html)
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            pages = collector.discover_dvwa_pages()
            
            assert isinstance(pages, dict)
            assert len(pages) > 0
            collector.close()
    
    def test_discover_dvwa_pages_not_found(self):
        """测试未找到DVWA页面"""
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/login.php', status_code=404)
            m.get('http://192.168.1.100/dvwa/index.php', status_code=404)
            m.get('http://192.168.1.100/dvwa', status_code=404)
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            
            with pytest.raises(DVWANotFoundError):
                collector.discover_dvwa_pages()
            
            collector.close()
    
    def test_detect_dvwa_version(self):
        """测试检测DVWA版本"""
        about_html = """
        <html>
        <head><title>About DVWA</title></head>
        <body>
            <h1>DVWA v1.10</h1>
            <p>Version 1.10</p>
        </body>
        </html>
        """
        
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/index.php', text=about_html)
            m.get('http://192.168.1.100/dvwa/about.php', text=about_html)
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            version = collector.detect_dvwa_version()
            
            assert isinstance(version, str)
            collector.close()
    
    def test_cache_mechanism(self, dvwa_login_html):
        """测试缓存机制"""
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/login.php', text=dvwa_login_html)
            
            collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False)
            
            # 第一次提取
            token1 = collector.extract_login_token()
            
            # 第二次提取（应该使用缓存）
            token2 = collector.extract_login_token()
            
            assert token1 == token2
            assert m.call_count == 1  # 只请求一次
            
            collector.close()
    
    def test_context_manager(self, dvwa_login_html):
        """测试上下文管理器"""
        with requests_mock.Mocker() as m:
            m.get('http://192.168.1.100/dvwa/login.php', text=dvwa_login_html)
            
            with DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False) as collector:
                token = collector.extract_login_token()
                assert token == "abc123def456ghi789"
    
    def test_error_handling_connection_error(self):
        """测试连接错误处理"""
        collector = DVWACollector(base_url="http://192.168.1.100/dvwa", verify_ssl=False, timeout=1)
        
        with pytest.raises(DVWACollectorError):
            collector.extract_login_token()
        
        collector.close()


# ==================== PathScanner 测试 ====================

@pytest.mark.skipif(not HAS_REQUESTS_MOCK, reason="requests_mock not installed")
class TestPathScanner:
    """PathScanner测试类"""
    
    def test_path_scanner_init(self):
        """测试PathScanner初始化"""
        scanner = PathScanner(
            timeout=10,
            max_workers=5,
            verify_ssl=False
        )
        
        assert scanner.timeout == 10
        assert scanner.max_workers == 5
        assert scanner.verify_ssl is False
        assert scanner.session is not None
        
        scanner.close()
    
    def test_check_path_accessibility(self):
        """测试检查路径可达性"""
        with requests_mock.Mocker() as m:
            m.head('http://192.168.1.100/dvwa/vulnerabilities/', status_code=200, headers={
                'Content-Type': 'text/html',
                'Content-Length': '1024'
            })
            
            scanner = PathScanner(verify_ssl=False)
            result = scanner.check_path_accessibility('http://192.168.1.100/dvwa/vulnerabilities/')
            
            assert isinstance(result, PathResult)
            assert result.exists is True
            assert result.status_code == 200
            assert result.content_type == 'text/html'
            
            scanner.close()
    
    def test_scan_dvwa_paths(self):
        """测试扫描DVWA路径"""
        with requests_mock.Mocker() as m:
            # Mock多个路径
            paths = [
                '/vulnerabilities/',
                '/hackable/',
                '/config/',
                '/login.php',
                '/setup.php',
                '/security.php'
            ]
            
            for path in paths:
                m.head(f'http://192.168.1.100/dvwa{path}', status_code=200)
            
            scanner = PathScanner(verify_ssl=False, max_workers=3)
            results = scanner.scan_dvwa_paths('http://192.168.1.100/dvwa')
            
            assert len(results) > 0
            assert all(isinstance(r, PathResult) for r in results)
            
            scanner.close()
    
    def test_scan_custom_paths(self):
        """测试扫描自定义路径"""
        with requests_mock.Mocker() as m:
            m.head('http://192.168.1.100/dvwa/admin/', status_code=200)
            m.head('http://192.168.1.100/dvwa/backup/', status_code=404)
            m.head('http://192.168.1.100/dvwa/config.php', status_code=200)
            
            scanner = PathScanner(verify_ssl=False)
            results = scanner.scan_custom_paths(
                'http://192.168.1.100/dvwa',
                ['/admin/', '/backup/', '/config.php']
            )
            
            assert len(results) == 3
            assert results[0].exists is True
            assert results[1].exists is False
            assert results[2].exists is True
            
            scanner.close()
    
    def test_detect_directory_listing(self, directory_listing_html):
        """测试检测目录列表漏洞"""
        with requests_mock.Mocker() as m:
            m.head('http://192.168.1.100/dvwa/hackable/', status_code=200, headers={
                'Content-Type': 'text/html'
            })
            m.get('http://192.168.1.100/dvwa/hackable/', text=directory_listing_html)
            
            scanner = PathScanner(verify_ssl=False, enable_directory_listing_detection=True)
            result = scanner.check_path_accessibility('http://192.168.1.100/dvwa/hackable/')
            
            assert result.has_directory_listing is True
            scanner.close()
    
    def test_extract_title(self):
        """测试提取页面标题"""
        html = """
        <html>
        <head>
            <title>Test Page Title</title>
        </head>
        <body>Content</body>
        </html>
        """
        
        with requests_mock.Mocker() as m:
            m.head('http://192.168.1.100/dvwa/test.html', status_code=200, headers={
                'Content-Type': 'text/html'
            })
            m.get('http://192.168.1.100/dvwa/test.html', text=html)
            
            scanner = PathScanner(verify_ssl=False)
            result = scanner.check_path_accessibility('http://192.168.1.100/dvwa/test.html')
            
            assert 'Test Page Title' in result.title
            scanner.close()
    
    def test_parallel_scanning(self):
        """测试并发扫描"""
        with requests_mock.Mocker() as m:
            # Mock多个路径
            for i in range(10):
                m.head(f'http://192.168.1.100/dvwa/path{i}/', status_code=200)
            
            scanner = PathScanner(verify_ssl=False, max_workers=5)
            paths = [f'/path{i}/' for i in range(10)]
            results = scanner.scan_custom_paths('http://192.168.1.100/dvwa', paths)
            
            assert len(results) == 10
            assert all(r.exists for r in results)
            
            scanner.close()
    
    def test_error_handling_timeout(self):
        """测试超时错误处理"""
        scanner = PathScanner(timeout=1, verify_ssl=False)
        
        # 模拟超时（使用一个不存在的域名，但会超时）
        result = scanner.check_path_accessibility('http://192.168.255.255/test')
        
        assert result.exists is False
        assert result.status_code == 0
        
        scanner.close()
    
    def test_context_manager(self):
        """测试上下文管理器"""
        with requests_mock.Mocker() as m:
            m.head('http://192.168.1.100/dvwa/test/', status_code=200)
            
            with PathScanner(verify_ssl=False) as scanner:
                result = scanner.check_path_accessibility('http://192.168.1.100/dvwa/test/')
                assert result.exists is True


# ==================== InfoGatheringManager 测试 ====================

class TestInfoGatheringManager:
    """InfoGatheringManager测试类"""
    
    def test_info_gathering_manager_init(self):
        """测试InfoGatheringManager初始化"""
        # 由于InfoGatheringManager是占位类，测试基本结构
        manager = InfoGatheringManager()
        assert manager is not None
    
    def test_info_gathering_manager_exists(self):
        """测试InfoGatheringManager类存在"""
        assert InfoGatheringManager is not None
        assert hasattr(InfoGatheringManager, '__init__')


# ==================== PortInfo 测试 ====================

class TestPortInfo:
    """PortInfo数据类测试"""
    
    def test_port_info_init(self):
        """测试PortInfo初始化"""
        port_info = PortInfo(
            port=80,
            state='open',
            service='http',
            version='2.4.49',
            product='Apache httpd'
        )
        
        assert port_info.port == 80
        assert port_info.state == 'open'
        assert port_info.service == 'http'
        assert port_info.is_web_service is True
    
    def test_port_info_to_dict(self):
        """测试PortInfo转换为字典"""
        port_info = PortInfo(
            port=80,
            state='open',
            service='http'
        )
        
        data = port_info.to_dict()
        
        assert isinstance(data, dict)
        assert data['port'] == 80
        assert data['state'] == 'open'
        assert data['service'] == 'http'
    
    def test_port_info_detect_web_service(self):
        """测试自动检测Web服务"""
        # Web端口
        port_info = PortInfo(port=80, service='unknown')
        assert port_info.is_web_service is True
        
        # 非Web端口
        port_info = PortInfo(port=22, service='ssh')
        assert port_info.is_web_service is False
        
        # Web服务名称
        port_info = PortInfo(port=8080, service='http')
        assert port_info.is_web_service is True


# ==================== PathResult 测试 ====================

class TestPathResult:
    """PathResult数据类测试"""
    
    def test_path_result_init(self):
        """测试PathResult初始化"""
        result = PathResult(
            url='http://192.168.1.100/test',
            status_code=200,
            exists=True,
            is_directory=False
        )
        
        assert result.url == 'http://192.168.1.100/test'
        assert result.status_code == 200
        assert result.exists is True
        assert result.is_directory is False
    
    def test_path_result_to_dict(self):
        """测试PathResult转换为字典"""
        result = PathResult(
            url='http://192.168.1.100/test',
            status_code=200,
            exists=True
        )
        
        data = result.to_dict()
        
        assert isinstance(data, dict)
        assert data['url'] == 'http://192.168.1.100/test'
        assert data['status_code'] == 200
        assert data['exists'] is True


# ==================== 集成测试 ====================

@pytest.mark.skipif(not HAS_REQUESTS_MOCK, reason="requests_mock not installed")
class TestIntegration:
    """集成测试"""
    
    def test_nmap_and_path_scanner_integration(self, sample_nmap_result):
        """测试NmapScanner和PathScanner集成"""
        with patch('src.modules.info_gathering.HAS_NMAP', True):
            with patch('src.modules.info_gathering.nmap.PortScanner') as mock_port_scanner:
                mock_scanner = MagicMock()
                mock_scanner.scan.return_value = sample_nmap_result
                mock_port_scanner.return_value = mock_scanner
                
                # 扫描端口
                nmap_scanner = NmapScanner()
                ports = nmap_scanner.scan_web_ports('127.0.0.1')
                
                # 扫描路径
                with requests_mock.Mocker() as m:
                    m.head('http://127.0.0.1/', status_code=200)
                    
                    path_scanner = PathScanner(verify_ssl=False)
                    paths = path_scanner.scan_custom_paths('http://127.0.0.1', ['/'])
                    
                    assert len(ports) > 0
                    assert len(paths) > 0
                    
                    path_scanner.close()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

