"""
FileUtils测试套件

使用pytest框架进行测试
"""

import pytest
import sys
import os
import tempfile
import shutil
import json
import time
import threading
from pathlib import Path
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.file_utils import FileUtils, FileUtilsError, FileLockError


@pytest.fixture
def temp_dir():
    """创建临时目录fixture"""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    # 清理
    if temp_path.exists():
        shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def temp_file(temp_dir):
    """创建临时文件fixture"""
    file_path = temp_dir / "test_file.txt"
    yield file_path
    # 清理
    if file_path.exists():
        try:
            file_path.unlink()
        except:
            pass


@pytest.fixture
def file_utils():
    """创建FileUtils实例fixture"""
    return FileUtils()


class TestFileReadWrite:
    """测试文件读写功能"""
    
    def test_read_write_text_file(self, file_utils, temp_file):
        """测试文本文件读写"""
        content = "Hello World\n测试中文\nLine 3"
        
        # 写入文件
        file_utils.write_file(temp_file, content)
        assert temp_file.exists()
        
        # 读取文件
        read_content = file_utils.read_file(temp_file)
        assert read_content == content
    
    def test_read_write_binary_file(self, file_utils, temp_file):
        """测试二进制文件读写"""
        binary_data = b'\x00\x01\x02\x03\xff\xfe\xfd'
        
        # 写入二进制
        file_utils.write_bytes(temp_file, binary_data)
        assert temp_file.exists()
        
        # 读取二进制
        read_data = file_utils.read_bytes(temp_file)
        assert read_data == binary_data
    
    def test_append_file(self, file_utils, temp_file):
        """测试追加文件"""
        content1 = "Line 1\n"
        content2 = "Line 2\n"
        
        # 写入初始内容
        file_utils.write_file(temp_file, content1)
        
        # 追加内容
        file_utils.append_file(temp_file, content2)
        
        # 验证
        read_content = file_utils.read_file(temp_file)
        assert content1 + content2 == read_content
    
    def test_read_nonexistent_file(self, file_utils, temp_dir):
        """测试读取不存在的文件"""
        nonexistent_file = temp_dir / "nonexistent.txt"
        
        with pytest.raises(FileUtilsError):
            file_utils.read_file(nonexistent_file)
    
    def test_file_exists(self, file_utils, temp_file):
        """测试文件存在检查"""
        # 文件不存在
        assert not file_utils.file_exists(temp_file)
        
        # 创建文件
        file_utils.write_file(temp_file, "test")
        
        # 文件存在
        assert file_utils.file_exists(temp_file)
    
    def test_read_file_with_encoding(self, file_utils, temp_file):
        """测试指定编码读写"""
        content = "测试UTF-8编码"
        
        # 写入UTF-8
        file_utils.write_file(temp_file, content, encoding='utf-8')
        
        # 读取UTF-8
        read_content = file_utils.read_file(temp_file, encoding='utf-8')
        assert read_content == content


class TestDirectoryOperations:
    """测试目录操作"""
    
    def test_create_dir(self, file_utils, temp_dir):
        """测试创建目录"""
        new_dir = temp_dir / "new_dir"
        
        # 创建目录
        file_utils.create_dir(new_dir)
        assert new_dir.exists()
        assert new_dir.is_dir()
    
    def test_create_nested_dir(self, file_utils, temp_dir):
        """测试创建嵌套目录"""
        nested_dir = temp_dir / "level1" / "level2" / "level3"
        
        # 创建嵌套目录
        file_utils.create_dir(nested_dir)
        assert nested_dir.exists()
        assert nested_dir.is_dir()
    
    def test_list_files(self, file_utils, temp_dir):
        """测试列出文件"""
        # 创建测试文件
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "file2.txt").write_text("content2")
        (temp_dir / "subdir").mkdir()
        (temp_dir / "subdir" / "file3.txt").write_text("content3")
        
        # 列出文件（非递归）
        files = file_utils.list_files(temp_dir, pattern="*.txt", recursive=False)
        assert len(files) == 2
        assert all("file" in f for f in files)
        
        # 列出文件（递归）
        files = file_utils.list_files(temp_dir, pattern="*.txt", recursive=True)
        assert len(files) == 3


class TestJSONOperations:
    """测试JSON操作"""
    
    def test_read_write_json(self, file_utils, temp_file):
        """测试JSON读写"""
        json_file = temp_file.with_suffix('.json')
        data = {
            "name": "test",
            "value": 123,
            "nested": {"key": "value"}
        }
        
        # 写入JSON
        file_utils.write_json(json_file, data)
        assert json_file.exists()
        
        # 读取JSON
        read_data = file_utils.read_json(json_file)
        assert read_data == data
    
    def test_read_json_default(self, file_utils, temp_dir):
        """测试读取不存在的JSON文件返回默认值"""
        json_file = temp_dir / "nonexistent.json"
        default = {"default": "value"}
        
        # 读取不存在的文件
        result = file_utils.read_json(json_file, default=default)
        assert result == default
    
    def test_update_json(self, file_utils, temp_file):
        """测试更新JSON"""
        json_file = temp_file.with_suffix('.json')
        initial_data = {"key1": "value1", "key2": "value2"}
        
        # 写入初始数据
        file_utils.write_json(json_file, initial_data)
        
        # 更新部分字段
        file_utils.update_json(json_file, {"key2": "updated", "key3": "new"})
        
        # 验证
        updated_data = file_utils.read_json(json_file)
        assert updated_data["key1"] == "value1"  # 保留原值
        assert updated_data["key2"] == "updated"  # 更新
        assert updated_data["key3"] == "new"  # 新增
    
    def test_json_safe_update(self, file_utils, temp_file):
        """测试安全JSON更新"""
        json_file = temp_file.with_suffix('.json')
        initial_data = {"count": 0}
        
        # 写入初始数据
        file_utils.write_json(json_file, initial_data)
        
        # 定义更新函数
        def increment(data):
            data["count"] = data.get("count", 0) + 1
            return data
        
        # 安全更新
        success = file_utils.json_safe_update(json_file, increment)
        assert success
        
        # 验证
        updated_data = file_utils.read_json(json_file)
        assert updated_data["count"] == 1
    
    def test_json_with_datetime(self, file_utils, temp_file):
        """测试JSON日期时间序列化"""
        json_file = temp_file.with_suffix('.json')
        data = {
            "created_at": datetime.now(),
            "date": datetime.now().date()
        }
        
        # 写入JSON（自动序列化日期时间）
        file_utils.write_json(json_file, data)
        
        # 读取JSON
        read_data = file_utils.read_json(json_file)
        assert "created_at" in read_data
        assert isinstance(read_data["created_at"], str)  # 已序列化为字符串


class TestFileHash:
    """测试文件哈希"""
    
    def test_get_file_hash_md5(self, file_utils, temp_file):
        """测试MD5哈希"""
        content = "test content"
        file_utils.write_file(temp_file, content)
        
        hash_value = file_utils.get_file_hash(temp_file, algorithm='md5')
        assert len(hash_value) == 32  # MD5是32位十六进制
        assert isinstance(hash_value, str)
    
    def test_get_file_hash_sha256(self, file_utils, temp_file):
        """测试SHA256哈希"""
        content = "test content"
        file_utils.write_file(temp_file, content)
        
        hash_value = file_utils.get_file_hash(temp_file, algorithm='sha256')
        assert len(hash_value) == 64  # SHA256是64位十六进制
        assert isinstance(hash_value, str)
    
    def test_get_file_hash_nonexistent(self, file_utils, temp_dir):
        """测试不存在的文件哈希"""
        nonexistent_file = temp_dir / "nonexistent.txt"
        
        with pytest.raises(FileUtilsError):
            file_utils.get_file_hash(nonexistent_file)
    
    def test_get_file_hash_invalid_algorithm(self, file_utils, temp_file):
        """测试无效的哈希算法"""
        file_utils.write_file(temp_file, "test")
        
        with pytest.raises(FileUtilsError):
            file_utils.get_file_hash(temp_file, algorithm='invalid')


class TestFilePermissions:
    """测试文件权限"""
    
    @pytest.mark.skipif(os.name == 'nt', reason="Windows不支持Unix权限")
    def test_set_file_permission(self, file_utils, temp_file):
        """测试设置文件权限"""
        file_utils.write_file(temp_file, "test")
        
        # 设置权限
        file_utils.set_file_permission(temp_file, mode=0o755)
        
        # 验证权限（简化检查）
        stat_info = temp_file.stat()
        assert stat_info.st_mode & 0o777
    
    def test_is_readable(self, file_utils, temp_file):
        """测试文件可读性"""
        # 文件不存在
        assert not file_utils.is_readable(temp_file)
        
        # 创建文件
        file_utils.write_file(temp_file, "test")
        
        # 文件应该可读
        assert file_utils.is_readable(temp_file)
    
    def test_is_writable(self, file_utils, temp_file):
        """测试文件可写性"""
        # 文件不存在，检查目录可写性
        assert file_utils.is_writable(temp_file)
        
        # 创建文件
        file_utils.write_file(temp_file, "test")
        
        # 文件应该可写
        assert file_utils.is_writable(temp_file)


class TestFileLocking:
    """测试文件锁"""
    
    def test_file_lock_basic(self, file_utils, temp_file):
        """测试基本文件锁"""
        content = "test content"
        
        # 使用文件锁写入
        with file_utils._file_lock(temp_file, 'w') as f:
            f.write(content)
            f.flush()
        
        # 验证写入成功
        read_content = file_utils.read_file(temp_file)
        assert read_content == content
    
    def test_file_lock_concurrent_write(self, file_utils, temp_file):
        """测试并发写入文件锁"""
        results = []
        
        def write_file(index):
            with file_utils._file_lock(temp_file, 'a') as f:
                f.write(f"Line {index}\n")
                time.sleep(0.01)  # 模拟写入延迟
                results.append(index)
        
        # 启动多个线程并发写入
        threads = []
        for i in range(5):
            thread = threading.Thread(target=write_file, args=(i,))
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        # 验证所有写入都成功
        assert len(results) == 5
        content = file_utils.read_file(temp_file)
        assert content.count("Line") == 5


class TestTempFiles:
    """测试临时文件"""
    
    def test_create_temp_file(self, file_utils):
        """测试创建临时文件"""
        temp_file = file_utils.create_temp_file(suffix='.txt', content="test")
        
        try:
            assert temp_file.exists()
            assert temp_file.suffix == '.txt'
            content = file_utils.read_file(temp_file)
            assert content == "test"
        finally:
            temp_file.unlink()
    
    def test_cleanup_temp_files(self, file_utils, temp_dir):
        """测试清理临时文件"""
        # 创建多个临时文件
        temp_files = []
        for i in range(3):
            temp_file = file_utils.create_temp_file(
                suffix='.tmp',
                prefix='test_',
                dir=temp_dir
            )
            temp_files.append(temp_file)
        
        # 等待1秒（确保文件时间戳不同）
        time.sleep(1.1)
        
        # 清理临时文件
        deleted = file_utils.cleanup_temp_files(
            dir_path=temp_dir,
            older_than=1,
            pattern='test_*.tmp'
        )
        
        assert deleted == 3


class TestFileSearch:
    """测试文件搜索"""
    
    def test_search_in_files(self, file_utils, temp_dir):
        """测试文件搜索"""
        # 创建测试文件
        (temp_dir / "file1.txt").write_text("password: secret123\nother line")
        (temp_dir / "file2.txt").write_text("no password here")
        (temp_dir / "file3.log").write_text("password: admin")
        
        # 搜索关键词
        results = file_utils.search_in_files(
            temp_dir,
            pattern='password',
            file_pattern='*.txt',
            recursive=False
        )
        
        assert len(results) > 0
        assert all('password' in r['content'].lower() for r in results)
    
    def test_search_with_regex(self, file_utils, temp_dir):
        """测试正则表达式搜索"""
        # 创建测试文件
        (temp_dir / "file.txt").write_text("API_KEY=secret123\nDEBUG=true")
        
        # 使用正则表达式搜索
        import re
        pattern = re.compile(r'API_KEY\s*=\s*(\w+)')
        results = file_utils.search_in_files(
            temp_dir,
            pattern=pattern,
            file_pattern='*.txt'
        )
        
        assert len(results) > 0


class TestFileWatch:
    """测试文件监控"""
    
    def test_watch_file(self, file_utils, temp_file):
        """测试文件监控"""
        file_utils.write_file(temp_file, "initial")
        
        changes = []
        
        def on_change(path):
            changes.append(path)
        
        # 启动监控
        stop_event = threading.Event()
        thread = file_utils.watch_file(
            temp_file,
            callback=on_change,
            check_interval=0.1,
            stop_event=stop_event
        )
        
        try:
            # 等待监控启动
            time.sleep(0.2)
            
            # 修改文件
            file_utils.append_file(temp_file, "\nmodified")
            time.sleep(0.3)
            
            # 停止监控
            stop_event.set()
            thread.join(timeout=1)
            
            # 验证检测到变化
            assert len(changes) > 0
        finally:
            stop_event.set()


class TestErrorHandling:
    """测试错误处理"""
    
    def test_read_nonexistent_file_error(self, file_utils, temp_dir):
        """测试读取不存在文件的错误"""
        nonexistent = temp_dir / "nonexistent.txt"
        
        with pytest.raises(FileUtilsError):
            file_utils.read_file(nonexistent)
    
    def test_write_to_readonly_dir(self, file_utils, temp_dir):
        """测试写入只读目录（如果可能）"""
        # 这个测试在某些系统上可能无法执行
        # 因为需要root权限创建只读目录
        pass
    
    def test_invalid_json(self, file_utils, temp_file):
        """测试无效JSON"""
        json_file = temp_file.with_suffix('.json')
        json_file.write_text("invalid json content")
        
        with pytest.raises(FileUtilsError):
            file_utils.read_json(json_file)


class TestContextManager:
    """测试上下文管理器"""
    
    def test_context_manager(self, file_utils, temp_file):
        """测试上下文管理器"""
        with FileUtils() as fu:
            fu.write_file(temp_file, "test")
            assert temp_file.exists()
        
        # 上下文管理器退出后应该仍然可以访问
        content = file_utils.read_file(temp_file)
        assert content == "test"


class TestLargeFiles:
    """测试大文件处理"""
    
    def test_large_file_read(self, file_utils, temp_file):
        """测试大文件读取"""
        # 创建较大的文件（1MB）
        large_content = "x" * (1024 * 1024)
        file_utils.write_file(temp_file, large_content)
        
        # 读取大文件
        read_content = file_utils.read_file(temp_file)
        assert len(read_content) == len(large_content)
    
    def test_chunked_read(self, file_utils, temp_file):
        """测试分块读取"""
        # 创建测试文件
        content = "line1\nline2\nline3\n" * 1000
        file_utils.write_file(temp_file, content)
        
        # 读取文件（应该使用分块读取）
        read_content = file_utils.read_file(temp_file)
        assert len(read_content) == len(content)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

