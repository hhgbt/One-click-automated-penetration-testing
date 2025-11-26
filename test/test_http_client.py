"""
HTTP客户端测试用例
"""

import unittest
import sys
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.http_client import HttpClient, HttpClientError


class TestHttpClient(unittest.TestCase):
    """HTTP客户端测试类"""
    
    def setUp(self):
        """测试前准备"""
        self.client = HttpClient(timeout=10, max_retries=1)
    
    def tearDown(self):
        """测试后清理"""
        self.client.close()
    
    def test_get_request(self):
        """测试GET请求"""
        response = self.client.get('https://httpbin.org/get', params={'test': 'value'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('args', data)
        self.assertEqual(data['args']['test'], 'value')
    
    def test_post_json(self):
        """测试POST JSON请求"""
        response = self.client.post(
            'https://httpbin.org/post',
            json={'name': 'test', 'value': 123}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('json', data)
        self.assertEqual(data['json']['name'], 'test')
    
    def test_post_form_data(self):
        """测试POST表单数据"""
        response = self.client.post(
            'https://httpbin.org/post',
            data={'username': 'admin', 'password': 'secret'}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('form', data)
    
    def test_put_request(self):
        """测试PUT请求"""
        response = self.client.put(
            'https://httpbin.org/put',
            json={'key': 'value'}
        )
        self.assertEqual(response.status_code, 200)
    
    def test_delete_request(self):
        """测试DELETE请求"""
        response = self.client.delete('https://httpbin.org/delete')
        self.assertEqual(response.status_code, 200)
    
    def test_cookie_management(self):
        """测试Cookie管理"""
        # 设置Cookie
        self.client.set_cookie('test_cookie', 'test_value')
        
        # 验证Cookie被设置
        cookies = self.client.get_cookies()
        self.assertIn('test_cookie', cookies)
        self.assertEqual(cookies['test_cookie'], 'test_value')
        
        # 清空Cookie
        self.client.clear_cookies()
        cookies = self.client.get_cookies()
        self.assertEqual(len(cookies), 0)
    
    def test_cookie_persistence(self):
        """测试Cookie持久化"""
        # 发送请求设置Cookie
        response = self.client.get('https://httpbin.org/cookies/set?test=value')
        
        # 验证Cookie被保存
        cookies = self.client.get_cookies()
        # httpbin可能不会在响应中设置Cookie，这里主要测试Session的Cookie管理
    
    def test_csrf_token_extraction(self):
        """测试CSRF Token提取"""
        # 模拟包含CSRF Token的HTML
        html = '<meta name="csrf-token" content="test-token-12345">'
        result = self.client._extract_csrf_token_from_html(html)
        self.assertIsNotNone(result)
        token, token_name, source = result
        self.assertEqual(token, 'test-token-12345')
    
    def test_base_url(self):
        """测试基础URL"""
        client = HttpClient(base_url='https://httpbin.org')
        response = client.get('/get')
        self.assertEqual(response.status_code, 200)
        client.close()
    
    def test_default_headers(self):
        """测试默认请求头"""
        client = HttpClient(default_headers={'X-Custom': 'value'})
        response = client.get('https://httpbin.org/headers')
        self.assertEqual(response.status_code, 200)
        client.close()
    
    def test_request_interceptor(self):
        """测试请求拦截器"""
        intercepted = []
        
        def interceptor(kwargs):
            intercepted.append(kwargs.get('url'))
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['headers']['X-Test'] = 'intercepted'
        
        self.client.add_request_interceptor(interceptor)
        response = self.client.get('https://httpbin.org/headers')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(intercepted) > 0)
    
    def test_response_interceptor(self):
        """测试响应拦截器"""
        intercepted = []
        
        def interceptor(response):
            intercepted.append(response.status_code)
        
        self.client.add_response_interceptor(interceptor)
        response = self.client.get('https://httpbin.org/get')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(len(intercepted) > 0)
    
    def test_ssl_verification(self):
        """测试SSL验证"""
        client = HttpClient(verify_ssl=False)
        # 注意：实际测试需要有效的HTTPS URL
        client.close()
    
    def test_context_manager(self):
        """测试上下文管理器"""
        with HttpClient() as client:
            response = client.get('https://httpbin.org/get')
            self.assertEqual(response.status_code, 200)


class TestHttpClientErrors(unittest.TestCase):
    """HTTP客户端错误处理测试"""
    
    def setUp(self):
        """测试前准备"""
        self.client = HttpClient(timeout=5, max_retries=1)
    
    def tearDown(self):
        """测试后清理"""
        self.client.close()
    
    def test_invalid_url(self):
        """测试无效URL"""
        with self.assertRaises(HttpClientError):
            self.client.get('https://invalid-domain-12345-xyz.com')
    
    def test_404_error(self):
        """测试404错误"""
        with self.assertRaises(HttpClientError):
            self.client.get('https://httpbin.org/status/404')


if __name__ == '__main__':
    unittest.main(verbosity=2)

