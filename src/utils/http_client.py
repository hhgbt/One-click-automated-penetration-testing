"""
HTTP客户端工具模块

功能特性：
1. 支持GET/POST/PUT/DELETE等常用HTTP方法
2. 自动处理Cookie持久化（使用requests.Session）
3. 超时重试机制（默认3次，可配置）
4. 异常捕获和友好错误提示
5. 统一的请求头管理
6. 自动提取CSRF Token
7. 支持代理配置
8. 支持SSL证书验证跳过
9. 请求/响应拦截器
10. 连接池优化

使用示例：
    from src.utils.http_client import HttpClient
    
    client = HttpClient()
    response = client.get('https://example.com')
    print(response.text)
"""

import re
import time
import requests
from typing import Optional, Dict, Any, Callable, Union, List
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import (
    RequestException, Timeout, ConnectionError as RequestsConnectionError,
    HTTPError, TooManyRedirects, ConnectTimeout, ReadTimeout
)

try:
    from src.utils.logger import get_logger
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    get_logger = lambda name: logging.getLogger(name)


# ==================== 异常类定义 ====================

class HttpClientError(Exception):
    """HTTP客户端基础异常类"""
    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.url = url
        self.status_code = status_code


class NetworkError(HttpClientError):
    """网络异常（可重试）
    
    包括连接超时、读取超时、连接错误等网络相关问题
    """
    def __init__(self, message: str, url: Optional[str] = None, original_exception: Optional[Exception] = None):
        super().__init__(message, url=url)
        self.original_exception = original_exception
        self.retryable = True


class ClientError(HttpClientError):
    """客户端错误（4xx，通常不重试）
    
    包括400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found等
    注意：429 Too Many Requests是特殊情况，可以重试
    """
    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None):
        super().__init__(message, url=url, status_code=status_code)
        self.retryable = status_code == 429  # 429可以重试


class ServerError(HttpClientError):
    """服务器错误（5xx，可重试）
    
    包括500 Internal Server Error, 502 Bad Gateway, 503 Service Unavailable等
    """
    def __init__(self, message: str, url: Optional[str] = None, status_code: Optional[int] = None):
        super().__init__(message, url=url, status_code=status_code)
        self.retryable = True


class BusinessLogicError(HttpClientError):
    """业务逻辑异常（不重试）
    
    请求成功但业务逻辑失败，通常不需要重试
    """
    def __init__(self, message: str, url: Optional[str] = None, response: Optional[requests.Response] = None):
        super().__init__(message, url=url)
        self.response = response
        self.retryable = False


class HttpClient:
    """
    HTTP客户端类
    
    提供完整的HTTP请求功能，包括Cookie管理、重试机制、代理支持等
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        retry_backoff_factor: float = 0.3,
        max_backoff_time: float = 60.0,
        verify_ssl: bool = True,
        proxy: Optional[Union[str, Dict[str, str]]] = None,
        default_headers: Optional[Dict[str, str]] = None,
        enable_csrf: bool = True,
        csrf_token_field_name: Optional[str] = None,
        csrf_refresh_strategy: str = 'auto',
        retry_on_timeout: bool = True,
        retry_on_5xx: bool = True,
        retry_on_429: bool = True,
        custom_retry_condition: Optional[Callable[[requests.Response, Exception], bool]] = None,
        pool_connections: int = 10,
        pool_maxsize: int = 20
    ):
        """
        初始化HTTP客户端
        
        Args:
            base_url: 基础URL，所有请求会基于此URL
            timeout: 请求超时时间（秒），默认30秒
            max_retries: 最大重试次数，默认3次
            retry_backoff_factor: 重试退避因子，默认0.3
            max_backoff_time: 最大退避时间（秒），默认60秒
            verify_ssl: 是否验证SSL证书，默认True
            proxy: 代理配置，可以是字符串或字典
            default_headers: 默认请求头
            enable_csrf: 是否启用CSRF Token自动提取，默认True
            csrf_token_field_name: 自定义CSRF Token字段名（用于表单提交），默认None（自动检测）
            csrf_refresh_strategy: Token刷新策略
                - 'auto': 每次响应时自动刷新（默认）
                - 'manual': 手动刷新
                - 'on_error': 仅在401/403错误时刷新
            retry_on_timeout: 是否在超时时重试，默认True
            retry_on_5xx: 是否在5xx错误时重试，默认True
            retry_on_429: 是否在429错误时重试，默认True
            custom_retry_condition: 自定义重试条件回调函数
                - 函数签名: (response: requests.Response, exception: Exception) -> bool
                - 返回True表示应该重试，False表示不重试
            pool_connections: 连接池大小，默认10
            pool_maxsize: 连接池最大连接数，默认20
        """
        self.base_url = base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff_factor = retry_backoff_factor
        self.max_backoff_time = max_backoff_time
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.enable_csrf = enable_csrf
        self.csrf_token_field_name = csrf_token_field_name
        self.csrf_refresh_strategy = csrf_refresh_strategy
        self.retry_on_timeout = retry_on_timeout
        self.retry_on_5xx = retry_on_5xx
        self.retry_on_429 = retry_on_429
        self.custom_retry_condition = custom_retry_condition
        self.csrf_token = None
        self.csrf_token_name = None
        self.csrf_token_source = None  # 记录Token来源：'html', 'header', 'cookie'
        
        # 创建Session，自动管理Cookie
        self.session = requests.Session()
        
        # 设置默认请求头
        default_headers = default_headers or {}
        default_headers.setdefault('User-Agent', 
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        self.session.headers.update(default_headers)
        
        # 配置连接池
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=Retry(
                total=max_retries,
                backoff_factor=retry_backoff_factor,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
            )
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # 设置代理
        if proxy:
            self.set_proxy(proxy)
        
        # 设置SSL验证
        self.session.verify = verify_ssl
        
        # 请求/响应拦截器
        self.request_interceptors: List[Callable] = []
        self.response_interceptors: List[Callable] = []
        
        # 日志记录器
        self.logger = get_logger(__name__)
    
    def set_proxy(self, proxy: Union[str, Dict[str, str]]):
        """
        设置代理
        
        Args:
            proxy: 代理配置
                - 字符串格式: 'http://proxy.example.com:8080'
                - 字典格式: {'http': 'http://proxy.example.com:8080', 'https': 'https://proxy.example.com:8080'}
        """
        if isinstance(proxy, str):
            self.proxy = {'http': proxy, 'https': proxy}
        else:
            self.proxy = proxy
        self.session.proxies.update(self.proxy)
        self.logger.debug(f"代理已设置: {self.proxy}")
    
    def set_default_headers(self, headers: Dict[str, str]):
        """
        设置默认请求头
        
        Args:
            headers: 请求头字典
        """
        self.session.headers.update(headers)
        self.logger.debug(f"默认请求头已更新: {headers}")
    
    def add_request_interceptor(self, interceptor: Callable):
        """
        添加请求拦截器
        
        Args:
            interceptor: 拦截器函数，接收(kwargs)参数，可以修改请求参数
        """
        self.request_interceptors.append(interceptor)
        self.logger.debug("请求拦截器已添加")
    
    def add_response_interceptor(self, interceptor: Callable):
        """
        添加响应拦截器
        
        Args:
            interceptor: 拦截器函数，接收(response)参数，可以处理响应
        """
        self.response_interceptors.append(interceptor)
        self.logger.debug("响应拦截器已添加")
    
    def _extract_csrf_token_from_html(self, html: str) -> Optional[tuple]:
        """
        从HTML中提取CSRF Token
        
        Args:
            html: HTML内容
            
        Returns:
            (token, token_name, source) 元组，如果未找到返回None
            source: 'html_input' 或 'html_meta'
        """
        if not html:
            return None
        
        # 模式1: <input type="hidden" name="csrf_token" value="xxx">
        # 支持多种常见的字段名
        input_patterns = [
            # name在前，value在后
            (r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](csrf_token)["\'][^>]*value=["\']([^"\']+)["\']', 'csrf_token', 2),
            (r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](_token)["\'][^>]*value=["\']([^"\']+)["\']', '_token', 2),
            (r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](csrf)["\'][^>]*value=["\']([^"\']+)["\']', 'csrf', 2),
            (r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](_csrf)["\'][^>]*value=["\']([^"\']+)["\']', '_csrf', 2),
            # value在前，name在后
            (r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\'][^>]*name=["\'](csrf_token)["\']', 'csrf_token', 1),
            (r'<input[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\'][^>]*name=["\'](_token)["\']', '_token', 1),
        ]
        
        for pattern, field_name, token_group in input_patterns:
            match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if match:
                # 提取token值（根据模式确定是哪个分组）
                token = match.group(token_group)
                if token and len(token) > 0:
                    self.logger.debug(f"从HTML input提取到CSRF Token: {token[:20]}... (字段名: {field_name})")
                    return (token, field_name, 'html_input')
        
        # 模式2: <meta name="csrf-token" content="xxx">
        meta_patterns = [
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']csrf-token["\']',
            r'<meta[^>]*name=["\']_csrf["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf_token["\'][^>]*content=["\']([^"\']+)["\']',
        ]
        
        for pattern in meta_patterns:
            match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
            if match:
                token = match.group(1)
                if len(token) > 0:
                    self.logger.debug(f"从HTML meta提取到CSRF Token: {token[:20]}...")
                    return (token, 'csrf-token', 'html_meta')
        
        return None
    
    def _extract_csrf_token_from_headers(self, headers: Dict[str, str]) -> Optional[str]:
        """
        从响应头中提取CSRF Token
        
        Args:
            headers: 响应头字典
            
        Returns:
            CSRF Token字符串，如果未找到返回None
        """
        # 常见的响应头字段名
        header_names = [
            'X-CSRF-Token',
            'X-CSRF-TOKEN',
            'X-XSRF-Token',
            'X-XSRF-TOKEN',
            'CSRF-Token',
            'CSRF-TOKEN',
        ]
        
        for header_name in header_names:
            # 尝试直接匹配
            if header_name in headers:
                token = headers[header_name]
                if token:
                    self.logger.debug(f"从响应头 {header_name} 提取到CSRF Token: {token[:20]}...")
                    return token
            
            # 尝试不区分大小写匹配
            for key, value in headers.items():
                if key.upper() == header_name.upper() and value:
                    self.logger.debug(f"从响应头 {key} 提取到CSRF Token: {value[:20]}...")
                    return value
        
        return None
    
    def _extract_csrf_token_from_cookies(self, cookies: Dict[str, str]) -> Optional[str]:
        """
        从Cookie中提取CSRF Token
        
        Args:
            cookies: Cookie字典
            
        Returns:
            CSRF Token字符串，如果未找到返回None
        """
        # 常见的Cookie字段名
        cookie_names = [
            'csrftoken',
            'csrf_token',
            'XSRF-TOKEN',
            'xsrf-token',
            '_csrf',
            'csrf',
        ]
        
        for cookie_name in cookie_names:
            # 尝试直接匹配
            if cookie_name in cookies:
                token = cookies[cookie_name]
                if token:
                    self.logger.debug(f"从Cookie {cookie_name} 提取到CSRF Token: {token[:20]}...")
                    return token
            
            # 尝试不区分大小写匹配
            for key, value in cookies.items():
                if key.lower() == cookie_name.lower() and value:
                    self.logger.debug(f"从Cookie {key} 提取到CSRF Token: {value[:20]}...")
                    return value
        
        return None
    
    def _extract_csrf_token(self, response: requests.Response) -> Optional[tuple]:
        """
        从响应中提取CSRF Token（综合多种来源）
        
        Args:
            response: Response对象
            
        Returns:
            (token, token_name, source) 元组，如果未找到返回None
        """
        if not self.enable_csrf:
            return None
        
        # 优先级1: 从响应头提取
        token = self._extract_csrf_token_from_headers(dict(response.headers))
        if token:
            return (token, 'X-CSRF-Token', 'header')
        
        # 优先级2: 从Cookie提取
        cookies = dict(response.cookies)
        token = self._extract_csrf_token_from_cookies(cookies)
        if token:
            return (token, 'X-CSRF-Token', 'cookie')
        
        # 优先级3: 从HTML提取
        if response.text:
            result = self._extract_csrf_token_from_html(response.text)
            if result:
                return result
        
        return None
    
    def _should_refresh_csrf_token(self, response: requests.Response) -> bool:
        """
        判断是否应该刷新CSRF Token
        
        Args:
            response: Response对象
            
        Returns:
            是否应该刷新Token
        """
        if not self.enable_csrf:
            return False
        
        if self.csrf_refresh_strategy == 'manual':
            return False
        
        if self.csrf_refresh_strategy == 'on_error':
            # 仅在401/403错误时刷新
            return response.status_code in [401, 403]
        
        # 'auto': 每次响应都尝试刷新
        return True
    
    def _apply_request_interceptors(self, kwargs: Dict[str, Any]):
        """
        应用请求拦截器
        
        Args:
            kwargs: 请求参数字典
        """
        for interceptor in self.request_interceptors:
            try:
                interceptor(kwargs)
            except Exception as e:
                self.logger.warning(f"请求拦截器执行失败: {e}")
    
    def _apply_response_interceptors(self, response: requests.Response):
        """
        应用响应拦截器
        
        Args:
            response: 响应对象
        """
        for interceptor in self.response_interceptors:
            try:
                interceptor(response)
            except Exception as e:
                self.logger.warning(f"响应拦截器执行失败: {e}")
    
    def _build_url(self, url: str) -> str:
        """
        构建完整URL
        
        Args:
            url: 相对或绝对URL
            
        Returns:
            完整URL
        """
        if self.base_url:
            return urljoin(self.base_url, url)
        return url
    
    def _prepare_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Union[Dict, str, bytes]] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        准备请求参数
        
        Args:
            method: HTTP方法
            url: 请求URL
            params: URL参数
            data: 请求体数据
            json: JSON数据
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            准备好的请求参数字典
        """
        # 构建完整URL
        full_url = self._build_url(url)
        
        # 合并请求头
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)
        
        # 如果启用CSRF且存在Token，自动添加到请求中
        if self.enable_csrf and self.csrf_token:
            # 根据Token来源决定添加方式
            if self.csrf_token_source == 'header' or self.csrf_token_source == 'cookie':
                # 从响应头或Cookie提取的Token，添加到请求头
                request_headers['X-CSRF-Token'] = self.csrf_token
                # 如果同时有表单数据，也添加到表单中（某些框架需要）
                if data is not None and isinstance(data, dict):
                    field_name = self.csrf_token_field_name or self.csrf_token_name or '_token'
                    data[field_name] = self.csrf_token
                elif json is not None:
                    if not isinstance(json, dict):
                        json = {}
                    field_name = self.csrf_token_field_name or self.csrf_token_name or '_token'
                    json[field_name] = self.csrf_token
            elif self.csrf_token_source in ['html_input', 'html_meta']:
                # 从HTML提取的Token，根据请求类型添加
                field_name = self.csrf_token_field_name or self.csrf_token_name or '_token'
                
                if json is not None:
                    # JSON请求，添加到JSON数据中
                    if not isinstance(json, dict):
                        json = {}
                    json[field_name] = self.csrf_token
                elif data is not None and isinstance(data, dict):
                    # 表单请求，添加到表单数据中
                    data[field_name] = self.csrf_token
                else:
                    # 其他情况，添加到请求头
                    request_headers['X-CSRF-Token'] = self.csrf_token
        
        # 构建请求参数
        request_kwargs = {
            'method': method,
            'url': full_url,
            'params': params,
            'data': data,
            'json': json,
            'headers': request_headers,
            'timeout': kwargs.pop('timeout', self.timeout),
            'verify': kwargs.pop('verify', self.verify_ssl),
            'proxies': kwargs.pop('proxies', self.proxy),
            **kwargs
        }
        
        # 应用请求拦截器
        self._apply_request_interceptors(request_kwargs)
        
        return request_kwargs
    
    def _calculate_backoff_time(self, attempt: int) -> float:
        """
        计算指数退避时间
        
        Args:
            attempt: 当前尝试次数（从0开始）
            
        Returns:
            退避时间（秒）
        """
        backoff_time = self.retry_backoff_factor * (2 ** attempt)
        return min(backoff_time, self.max_backoff_time)
    
    def _should_retry(
        self,
        exception: Optional[Exception],
        response: Optional[requests.Response],
        attempt: int,
        max_retries: int
    ) -> bool:
        """
        判断是否应该重试
        
        Args:
            exception: 异常对象
            response: 响应对象（如果有）
            attempt: 当前尝试次数
            max_retries: 最大重试次数
            
        Returns:
            是否应该重试
        """
        # 已达到最大重试次数
        if attempt >= max_retries:
            return False
        
        # 自定义重试条件
        if self.custom_retry_condition:
            try:
                return self.custom_retry_condition(response, exception)
            except Exception as e:
                self.logger.warning(f"自定义重试条件函数执行失败: {e}")
        
        # 处理超时异常
        if isinstance(exception, (ConnectTimeout, ReadTimeout, Timeout)):
            return self.retry_on_timeout
        
        # 处理连接错误
        if isinstance(exception, RequestsConnectionError):
            return True  # 连接错误总是可以重试
        
        # 处理HTTP错误
        if isinstance(exception, HTTPError) and response:
            status_code = response.status_code
            
            # 429 Too Many Requests
            if status_code == 429:
                return self.retry_on_429
            
            # 5xx服务器错误
            if 500 <= status_code < 600:
                return self.retry_on_5xx
            
            # 4xx客户端错误（除了429）通常不重试
            if 400 <= status_code < 500:
                return False
        
        # 其他RequestException可以重试
        if isinstance(exception, RequestException):
            return True
        
        # 默认不重试
        return False
    
    def _classify_exception(
        self,
        exception: Exception,
        url: str,
        response: Optional[requests.Response] = None
    ) -> HttpClientError:
        """
        分类异常并转换为自定义异常
        
        Args:
            exception: 原始异常
            url: 请求URL
            response: 响应对象（如果有）
            
        Returns:
            分类后的异常对象
        """
        # 超时异常
        if isinstance(exception, (ConnectTimeout, ReadTimeout)):
            return NetworkError(
                f"请求超时: {type(exception).__name__}",
                url=url,
                original_exception=exception
            )
        
        if isinstance(exception, Timeout):
            return NetworkError(
                "请求超时",
                url=url,
                original_exception=exception
            )
        
        # 连接错误
        if isinstance(exception, RequestsConnectionError):
            return NetworkError(
                f"连接失败: {str(exception)}",
                url=url,
                original_exception=exception
            )
        
        # HTTP错误
        if isinstance(exception, HTTPError) and response:
            status_code = response.status_code
            
            # 5xx服务器错误
            if 500 <= status_code < 600:
                return ServerError(
                    f"服务器错误 {status_code}: {response.reason}",
                    url=url,
                    status_code=status_code
                )
            
            # 4xx客户端错误
            if 400 <= status_code < 500:
                return ClientError(
                    f"客户端错误 {status_code}: {response.reason}",
                    url=url,
                    status_code=status_code
                )
        
        # 其他RequestException
        if isinstance(exception, RequestException):
            return NetworkError(
                f"请求异常: {str(exception)}",
                url=url,
                original_exception=exception
            )
        
        # 未知异常
        return HttpClientError(
            f"未知错误: {str(exception)}",
            url=url
        )
    
    def _make_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Union[Dict, str, bytes]] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retries: Optional[int] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送HTTP请求（智能重试机制）
        
        Args:
            method: HTTP方法
            url: 请求URL
            params: URL参数
            data: 请求体数据
            json: JSON数据
            headers: 请求头
            retries: 重试次数（None则使用默认值）
            **kwargs: 其他参数
            
        Returns:
            Response对象
            
        Raises:
            NetworkError: 网络异常（可重试）
            ClientError: 客户端错误（4xx，通常不重试）
            ServerError: 服务器错误（5xx，可重试）
            HttpClientError: 其他错误
        """
        retries = retries if retries is not None else self.max_retries
        last_exception = None
        last_response = None
        
        # 准备请求参数
        request_kwargs = self._prepare_request(
            method, url, params, data, json, headers, **kwargs
        )
        
        for attempt in range(retries + 1):
            try:
                self.logger.debug(
                    f"发送请求 [{method}] {request_kwargs['url']} "
                    f"(尝试 {attempt + 1}/{retries + 1})"
                )
                
                # 发送请求
                response = self.session.request(**request_kwargs)
                last_response = response
                
                # 应用响应拦截器
                self._apply_response_interceptors(response)
                
                # 如果启用CSRF，尝试从响应中提取Token
                if self._should_refresh_csrf_token(response):
                    token_info = self._extract_csrf_token(response)
                    if token_info:
                        token, token_name, source = token_info
                        self.csrf_token = token
                        self.csrf_token_name = token_name
                        self.csrf_token_source = source
                        self.logger.debug(
                            f"CSRF Token已更新: {token[:20]}... "
                            f"(来源: {source}, 字段名: {token_name})"
                        )
                
                # 检查HTTP错误状态（会抛出HTTPError）
                try:
                    response.raise_for_status()
                except HTTPError as e:
                    # 判断是否应该重试
                    if self._should_retry(e, response, attempt, retries):
                        last_exception = e
                        wait_time = self._calculate_backoff_time(attempt)
                        
                        # 429错误特殊处理：检查Retry-After头
                        if response.status_code == 429:
                            retry_after = response.headers.get('Retry-After')
                            if retry_after:
                                try:
                                    wait_time = float(retry_after)
                                    self.logger.info(f"服务器要求等待 {wait_time} 秒（Retry-After）")
                                except ValueError:
                                    pass
                        
                        self.logger.warning(
                            f"HTTP错误 {response.status_code}，"
                            f"{wait_time:.2f}秒后重试 ({attempt + 1}/{retries})"
                        )
                        time.sleep(wait_time)
                        continue
                    else:
                        # 不重试，抛出分类后的异常
                        raise self._classify_exception(e, url, response)
                
                # 请求成功
                return response
                
            except (ConnectTimeout, ReadTimeout, Timeout) as e:
                last_exception = e
                if self._should_retry(e, None, attempt, retries):
                    wait_time = self._calculate_backoff_time(attempt)
                    timeout_type = type(e).__name__
                    self.logger.warning(
                        f"{timeout_type}，{wait_time:.2f}秒后重试 ({attempt + 1}/{retries})"
                    )
                    time.sleep(wait_time)
                else:
                    raise self._classify_exception(e, url, None)
                    
            except RequestsConnectionError as e:
                last_exception = e
                if self._should_retry(e, None, attempt, retries):
                    wait_time = self._calculate_backoff_time(attempt)
                    self.logger.warning(
                        f"连接错误，{wait_time:.2f}秒后重试 ({attempt + 1}/{retries})"
                    )
                    time.sleep(wait_time)
                else:
                    raise self._classify_exception(e, url, None)
                    
            except HTTPError as e:
                # 这种情况应该已经在raise_for_status中处理了
                # 但为了安全，这里也处理一下
                last_exception = e
                response = getattr(e, 'response', None)
                if self._should_retry(e, response, attempt, retries):
                    wait_time = self._calculate_backoff_time(attempt)
                    status_code = response.status_code if response else 'Unknown'
                    self.logger.warning(
                        f"HTTP错误 {status_code}，{wait_time:.2f}秒后重试 ({attempt + 1}/{retries})"
                    )
                    time.sleep(wait_time)
                else:
                    raise self._classify_exception(e, url, response)
                    
            except RequestException as e:
                last_exception = e
                if self._should_retry(e, None, attempt, retries):
                    wait_time = self._calculate_backoff_time(attempt)
                    self.logger.warning(
                        f"请求异常，{wait_time:.2f}秒后重试 ({attempt + 1}/{retries})"
                    )
                    time.sleep(wait_time)
                else:
                    raise self._classify_exception(e, url, None)
        
        # 所有重试都失败，抛出分类后的异常
        if last_exception:
            raise self._classify_exception(last_exception, url, last_response)
        else:
            raise HttpClientError(f"请求失败（已重试{retries}次）: {url}")
    
    def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送GET请求
        
        Args:
            url: 请求URL
            params: URL参数
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('GET', url, params=params, headers=headers, **kwargs)
    
    def post(
        self,
        url: str,
        data: Optional[Union[Dict, str, bytes]] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送POST请求
        
        Args:
            url: 请求URL
            data: 请求体数据（表单数据）
            json: JSON数据
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('POST', url, data=data, json=json, headers=headers, **kwargs)
    
    def put(
        self,
        url: str,
        data: Optional[Union[Dict, str, bytes]] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送PUT请求
        
        Args:
            url: 请求URL
            data: 请求体数据
            json: JSON数据
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('PUT', url, data=data, json=json, headers=headers, **kwargs)
    
    def delete(
        self,
        url: str,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送DELETE请求
        
        Args:
            url: 请求URL
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('DELETE', url, headers=headers, **kwargs)
    
    def patch(
        self,
        url: str,
        data: Optional[Union[Dict, str, bytes]] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送PATCH请求
        
        Args:
            url: 请求URL
            data: 请求体数据
            json: JSON数据
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('PATCH', url, data=data, json=json, headers=headers, **kwargs)
    
    def head(
        self,
        url: str,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送HEAD请求
        
        Args:
            url: 请求URL
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('HEAD', url, headers=headers, **kwargs)
    
    def options(
        self,
        url: str,
        headers: Optional[Dict] = None,
        **kwargs
    ) -> requests.Response:
        """
        发送OPTIONS请求
        
        Args:
            url: 请求URL
            headers: 请求头
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request('OPTIONS', url, headers=headers, **kwargs)
    
    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """
        发送自定义HTTP请求
        
        Args:
            method: HTTP方法
            url: 请求URL
            **kwargs: 其他参数
            
        Returns:
            Response对象
        """
        return self._make_request(method.upper(), url, **kwargs)
    
    def get_cookies(self) -> Dict[str, str]:
        """
        获取当前所有Cookie
        
        Returns:
            Cookie字典
        """
        return dict(self.session.cookies)
    
    def set_cookie(self, name: str, value: str, domain: Optional[str] = None):
        """
        设置Cookie
        
        Args:
            name: Cookie名称
            value: Cookie值
            domain: Cookie域名
        """
        if domain is not None:
            self.session.cookies.set(name, value, domain=domain)
        else:
            self.session.cookies.set(name, value)
        self.logger.debug(f"Cookie已设置: {name}={value}")
    
    def clear_cookies(self):
        """清空所有Cookie"""
        self.session.cookies.clear()
        self.logger.debug("所有Cookie已清空")
    
    def get_csrf_token(self) -> Optional[str]:
        """
        获取当前CSRF Token
        
        Returns:
            CSRF Token字符串，如果不存在返回None
        """
        return self.csrf_token
    
    def set_csrf_token(
        self,
        token: str,
        token_name: Optional[str] = None,
        source: Optional[str] = None
    ):
        """
        手动设置CSRF Token
        
        Args:
            token: CSRF Token值
            token_name: Token字段名（可选）
            source: Token来源（'html', 'header', 'cookie', 'manual'），默认'manual'
        """
        self.csrf_token = token
        if token_name:
            self.csrf_token_name = token_name
        self.csrf_token_source = source or 'manual'
        self.logger.debug(
            f"CSRF Token已手动设置: {token[:20]}... "
            f"(字段名: {token_name}, 来源: {self.csrf_token_source})"
        )
    
    def refresh_csrf_token(self, url: Optional[str] = None):
        """
        手动刷新CSRF Token
        
        Args:
            url: 用于获取Token的URL，如果为None则使用base_url
        """
        if not self.enable_csrf:
            self.logger.warning("CSRF功能未启用")
            return
        
        refresh_url = url or self.base_url or '/'
        try:
            response = self.get(refresh_url)
            token_info = self._extract_csrf_token(response)
            if token_info:
                token, token_name, source = token_info
                self.csrf_token = token
                self.csrf_token_name = token_name
                self.csrf_token_source = source
                self.logger.info(f"CSRF Token已刷新: {token[:20]}... (来源: {source})")
            else:
                self.logger.warning(f"未能从 {refresh_url} 提取CSRF Token")
        except Exception as e:
            self.logger.error(f"刷新CSRF Token失败: {e}")
    
    def get_csrf_token_info(self) -> Optional[Dict[str, str]]:
        """
        获取CSRF Token信息
        
        Returns:
            包含token、token_name、source的字典，如果不存在返回None
        """
        if not self.csrf_token:
            return None
        
        return {
            'token': self.csrf_token,
            'token_name': self.csrf_token_name,
            'source': self.csrf_token_source
        }
    
    def close(self):
        """关闭HTTP客户端，释放资源"""
        self.session.close()
        self.logger.debug("HTTP客户端已关闭")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()
        return False

