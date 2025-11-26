"""
日志工具完整测试用例

测试要求：
1. 测试各级别日志是否能正确输出
2. 测试日志文件是否按日期创建
3. 测试多线程环境下的日志安全
4. 测试日志文件自动滚动
5. 验证日志格式是否符合要求
"""

import unittest
import os
import sys
import threading
import time
import re
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import get_logger, Logger, ColoredFormatter
import logging


class TestLogLevels(unittest.TestCase):
    """测试1: 各级别日志输出测试"""
    
    def setUp(self):
        """测试前准备"""
        self.test_log_dir = "test_logs_levels"
        self.test_name = "level_test"
        self.logger = get_logger(self.test_name, log_dir=self.test_log_dir)
    
    def tearDown(self):
        """测试后清理"""
        self._cleanup_test_files()
    
    def _cleanup_test_files(self):
        """清理测试文件"""
        test_log_path = Path(self.test_log_dir)
        if test_log_path.exists():
            for log_file in test_log_path.glob("*.log"):
                try:
                    log_file.unlink()
                except:
                    pass
            try:
                test_log_path.rmdir()
            except:
                pass
    
    def test_debug_level_output(self):
        """测试DEBUG级别日志输出"""
        test_message = "这是一条DEBUG级别的测试消息"
        self.logger.debug(test_message)
        
        # 验证日志文件存在
        log_file = self._get_log_file_path()
        self.assertTrue(log_file.exists(), "DEBUG日志文件应该被创建")
        
        # 验证日志内容
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(test_message, content, "DEBUG消息应该被记录")
            self.assertIn("DEBUG", content, "应该包含DEBUG级别标识")
    
    def test_info_level_output(self):
        """测试INFO级别日志输出"""
        test_message = "这是一条INFO级别的测试消息"
        self.logger.info(test_message)
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(test_message, content, "INFO消息应该被记录")
            self.assertIn("INFO", content, "应该包含INFO级别标识")
    
    def test_warning_level_output(self):
        """测试WARNING级别日志输出"""
        test_message = "这是一条WARNING级别的测试消息"
        self.logger.warning(test_message)
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(test_message, content, "WARNING消息应该被记录")
            self.assertIn("WARNING", content, "应该包含WARNING级别标识")
    
    def test_error_level_output(self):
        """测试ERROR级别日志输出"""
        test_message = "这是一条ERROR级别的测试消息"
        self.logger.error(test_message)
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(test_message, content, "ERROR消息应该被记录")
            self.assertIn("ERROR", content, "应该包含ERROR级别标识")
    
    def test_all_levels_in_one_file(self):
        """测试所有级别日志都能输出到同一文件"""
        messages = {
            "DEBUG": "DEBUG测试消息",
            "INFO": "INFO测试消息",
            "WARNING": "WARNING测试消息",
            "ERROR": "ERROR测试消息"
        }
        
        self.logger.debug(messages["DEBUG"])
        self.logger.info(messages["INFO"])
        self.logger.warning(messages["WARNING"])
        self.logger.error(messages["ERROR"])
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            for level, message in messages.items():
                self.assertIn(message, content, f"{level}级别消息应该被记录")
                self.assertIn(level, content, f"应该包含{level}级别标识")
    
    def _get_log_file_path(self):
        """获取日志文件路径"""
        today = datetime.now().strftime("%Y-%m-%d")
        return Path(self.test_log_dir) / f"{self.test_name}_{today}.log"


class TestLogFileDateCreation(unittest.TestCase):
    """测试2: 日志文件按日期创建测试"""
    
    def setUp(self):
        """测试前准备"""
        self.test_log_dir = "test_logs_date"
        self.test_name = "date_test"
    
    def tearDown(self):
        """测试后清理"""
        self._cleanup_test_files()
    
    def _cleanup_test_files(self):
        """清理测试文件"""
        test_log_path = Path(self.test_log_dir)
        if test_log_path.exists():
            for log_file in test_log_path.glob("*.log"):
                try:
                    log_file.unlink()
                except:
                    pass
            try:
                test_log_path.rmdir()
            except:
                pass
    
    def test_log_file_created_with_current_date(self):
        """测试日志文件使用当前日期创建"""
        logger = get_logger(self.test_name, log_dir=self.test_log_dir)
        logger.info("测试消息")
        
        # 获取当前日期
        today = datetime.now().strftime("%Y-%m-%d")
        expected_filename = f"{self.test_name}_{today}.log"
        log_file = Path(self.test_log_dir) / expected_filename
        
        self.assertTrue(log_file.exists(), f"日志文件应该以当前日期创建: {expected_filename}")
        self.assertEqual(log_file.name, expected_filename, "文件名格式应该正确")
    
    def test_log_file_naming_format(self):
        """测试日志文件命名格式"""
        logger = get_logger(self.test_name, log_dir=self.test_log_dir)
        logger.info("测试消息")
        
        # 检查文件名格式：name_YYYY-MM-DD.log
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = Path(self.test_log_dir) / f"{self.test_name}_{today}.log"
        
        self.assertTrue(log_file.exists())
        # 验证文件名格式
        pattern = rf"{self.test_name}_\d{{4}}-\d{{2}}-\d{{2}}\.log"
        self.assertRegex(log_file.name, pattern, "文件名格式应该符合 name_YYYY-MM-DD.log")
    
    def test_multiple_loggers_different_dates(self):
        """测试多个日志器在同一天创建不同文件"""
        logger1 = get_logger("module1", log_dir=self.test_log_dir)
        logger2 = get_logger("module2", log_dir=self.test_log_dir)
        
        logger1.info("模块1的消息")
        logger2.info("模块2的消息")
        
        today = datetime.now().strftime("%Y-%m-%d")
        log_file1 = Path(self.test_log_dir) / f"module1_{today}.log"
        log_file2 = Path(self.test_log_dir) / f"module2_{today}.log"
        
        self.assertTrue(log_file1.exists(), "模块1的日志文件应该存在")
        self.assertTrue(log_file2.exists(), "模块2的日志文件应该存在")
        self.assertNotEqual(log_file1, log_file2, "不同模块应该创建不同的日志文件")
    
    def test_same_logger_same_date_same_file(self):
        """测试同一日志器在同一天使用同一文件"""
        logger1 = get_logger(self.test_name, log_dir=self.test_log_dir)
        logger1.info("第一条消息")
        
        # 再次获取相同配置的日志器
        logger2 = get_logger(self.test_name, log_dir=self.test_log_dir)
        logger2.info("第二条消息")
        
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = Path(self.test_log_dir) / f"{self.test_name}_{today}.log"
        
        self.assertTrue(log_file.exists())
        # 验证两条消息都在同一文件中
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("第一条消息", content)
            self.assertIn("第二条消息", content)


class TestThreadSafety(unittest.TestCase):
    """测试3: 多线程环境下的日志安全测试"""
    
    def setUp(self):
        """测试前准备"""
        self.test_log_dir = "test_logs_thread"
        self.test_name = "thread_test"
        self.logger = get_logger(self.test_name, log_dir=self.test_log_dir)
        self.thread_count = 10
        self.messages_per_thread = 20
    
    def tearDown(self):
        """测试后清理"""
        self._cleanup_test_files()
    
    def _cleanup_test_files(self):
        """清理测试文件"""
        test_log_path = Path(self.test_log_dir)
        if test_log_path.exists():
            for log_file in test_log_path.glob("*.log"):
                try:
                    log_file.unlink()
                except:
                    pass
            try:
                test_log_path.rmdir()
            except:
                pass
    
    def test_concurrent_logging_no_errors(self):
        """测试并发日志记录不产生错误"""
        errors = []
        results = []
        
        def log_worker(thread_id):
            """工作线程函数"""
            try:
                for i in range(self.messages_per_thread):
                    self.logger.info(f"线程{thread_id} - 消息{i}")
                    results.append((thread_id, i))
                    time.sleep(0.001)  # 短暂延迟，增加并发竞争
            except Exception as e:
                errors.append((thread_id, e))
        
        # 创建多个线程
        threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=log_worker, args=(i,))
            threads.append(t)
            t.start()
        
        # 等待所有线程完成
        for t in threads:
            t.join(timeout=10)  # 设置超时，避免死锁
        
        # 验证没有错误
        self.assertEqual(len(errors), 0, f"不应该有错误，但发现: {errors}")
        # 验证所有消息都被记录
        self.assertEqual(len(results), self.thread_count * self.messages_per_thread,
                       "所有消息都应该被记录")
    
    def test_concurrent_logging_all_messages_recorded(self):
        """测试并发日志记录，所有消息都被正确记录"""
        expected_messages = set()
        
        def log_worker(thread_id):
            """工作线程函数"""
            for i in range(self.messages_per_thread):
                message = f"线程{thread_id}_消息{i}"
                expected_messages.add(message)
                self.logger.info(message)
                time.sleep(0.001)
        
        # 创建多个线程
        threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=log_worker, args=(i,))
            threads.append(t)
            t.start()
        
        # 等待所有线程完成
        for t in threads:
            t.join(timeout=10)
        
        # 验证日志文件存在
        log_file = self._get_log_file_path()
        self.assertTrue(log_file.exists(), "日志文件应该被创建")
        
        # 验证所有消息都在日志文件中
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            for message in expected_messages:
                self.assertIn(message, content, f"消息 '{message}' 应该被记录")
    
    def test_concurrent_logging_no_corruption(self):
        """测试并发日志记录，文件内容不损坏"""
        def log_worker(thread_id):
            """工作线程函数"""
            for i in range(self.messages_per_thread):
                # 使用固定格式的消息，便于验证
                self.logger.info(f"THREAD{thread_id}_MSG{i}")
                time.sleep(0.001)
        
        # 创建多个线程
        threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=log_worker, args=(i,))
            threads.append(t)
            t.start()
        
        # 等待所有线程完成
        for t in threads:
            t.join(timeout=10)
        
        # 验证日志文件完整性
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # 验证每行都是有效的日志格式
            for line in lines:
                # 应该包含时间戳、级别、文件名等信息
                self.assertIn(" - ", line, "每行应该包含日志分隔符")
                # 验证没有乱码或损坏
                self.assertIsInstance(line, str, "每行应该是有效的字符串")
    
    def test_multiple_loggers_thread_safety(self):
        """测试多个日志器在多线程环境下的安全性"""
        def log_worker(thread_id, logger_name):
            """工作线程函数"""
            logger = get_logger(logger_name, log_dir=self.test_log_dir)
            for i in range(10):
                logger.info(f"线程{thread_id}_日志器{logger_name}_消息{i}")
                time.sleep(0.001)
        
        # 创建多个线程，使用不同的日志器
        threads = []
        for i in range(5):
            t1 = threading.Thread(target=log_worker, args=(i, "logger1"))
            t2 = threading.Thread(target=log_worker, args=(i, "logger2"))
            threads.extend([t1, t2])
            t1.start()
            t2.start()
        
        # 等待所有线程完成
        for t in threads:
            t.join(timeout=10)
        
        # 验证两个日志文件都存在且内容正确
        today = datetime.now().strftime("%Y-%m-%d")
        log_file1 = Path(self.test_log_dir) / f"logger1_{today}.log"
        log_file2 = Path(self.test_log_dir) / f"logger2_{today}.log"
        
        self.assertTrue(log_file1.exists(), "logger1的日志文件应该存在")
        self.assertTrue(log_file2.exists(), "logger2的日志文件应该存在")
    
    def _get_log_file_path(self):
        """获取日志文件路径"""
        today = datetime.now().strftime("%Y-%m-%d")
        return Path(self.test_log_dir) / f"{self.test_name}_{today}.log"


class TestLogFileRotation(unittest.TestCase):
    """测试4: 日志文件自动滚动测试"""
    
    def setUp(self):
        """测试前准备"""
        self.test_log_dir = "test_logs_rotation"
        self.test_name = "rotation_test"
    
    def tearDown(self):
        """测试后清理"""
        self._cleanup_test_files()
    
    def _cleanup_test_files(self):
        """清理测试文件"""
        test_log_path = Path(self.test_log_dir)
        if test_log_path.exists():
            for log_file in test_log_path.glob("*.log"):
                try:
                    log_file.unlink()
                except:
                    pass
            try:
                test_log_path.rmdir()
            except:
                    pass
    
    def test_timed_rotating_handler_configured(self):
        """测试TimedRotatingFileHandler是否正确配置"""
        logger_manager = Logger.get_instance(self.test_name, log_dir=self.test_log_dir)
        logger = logger_manager.get_logger()
        
        # 检查是否有TimedRotatingFileHandler
        has_timed_handler = False
        for handler in logger.handlers:
            if isinstance(handler, logging.handlers.TimedRotatingFileHandler):
                has_timed_handler = True
                # 验证配置（when值在logging中是'MIDNIGHT'）
                self.assertEqual(handler.when, 'MIDNIGHT', "应该在午夜滚动")
                self.assertEqual(handler.interval, 1, "应该每天滚动")
                self.assertEqual(handler.backupCount, 7, "应该保留7个备份文件")
                break
        
        self.assertTrue(has_timed_handler, "应该有TimedRotatingFileHandler")
    
    def test_log_file_retention_policy(self):
        """测试日志文件保留策略（7天）"""
        logger = get_logger(self.test_name, log_dir=self.test_log_dir)
        logger.info("测试消息")
        
        # 验证TimedRotatingFileHandler的backupCount配置
        logger_manager = Logger.get_instance(self.test_name, log_dir=self.test_log_dir)
        logger_obj = logger_manager.get_logger()
        
        for handler in logger_obj.handlers:
            if isinstance(handler, logging.handlers.TimedRotatingFileHandler):
                self.assertEqual(handler.backupCount, 7, "应该保留7天的日志文件")
                break
    
    def test_old_log_cleanup_logic(self):
        """测试旧日志清理逻辑"""
        logger_manager = Logger.get_instance(self.test_name, log_dir=self.test_log_dir)
        
        # 创建一些模拟的旧日志文件
        test_log_path = Path(self.test_log_dir)
        test_log_path.mkdir(exist_ok=True)
        
        # 创建8天前的日志文件（应该被清理）
        old_date = (datetime.now() - timedelta(days=8)).strftime("%Y-%m-%d")
        old_log_file = test_log_path / f"{self.test_name}_{old_date}.log"
        old_log_file.write_text("旧日志内容")
        
        # 创建6天前的日志文件（应该保留）
        recent_date = (datetime.now() - timedelta(days=6)).strftime("%Y-%m-%d")
        recent_log_file = test_log_path / f"{self.test_name}_{recent_date}.log"
        recent_log_file.write_text("较新的日志内容")
        
        # 触发清理逻辑
        logger_manager._cleanup_old_logs()
        
        # 验证8天前的文件被删除
        self.assertFalse(old_log_file.exists(), "8天前的日志文件应该被删除")
        # 验证6天前的文件被保留
        self.assertTrue(recent_log_file.exists(), "6天前的日志文件应该被保留")


class TestLogFormat(unittest.TestCase):
    """测试5: 日志格式验证测试"""
    
    def setUp(self):
        """测试前准备"""
        self.test_log_dir = "test_logs_format"
        self.test_name = "format_test"
        self.logger = get_logger(self.test_name, log_dir=self.test_log_dir)
    
    def tearDown(self):
        """测试后清理"""
        self._cleanup_test_files()
    
    def _cleanup_test_files(self):
        """清理测试文件"""
        test_log_path = Path(self.test_log_dir)
        if test_log_path.exists():
            for log_file in test_log_path.glob("*.log"):
                try:
                    log_file.unlink()
                except:
                    pass
            try:
                test_log_path.rmdir()
            except:
                pass
    
    def test_log_format_structure(self):
        """测试日志格式结构：时间戳 - 级别 - 文件名:行号 - 消息"""
        test_message = "格式测试消息"
        self.logger.info(test_message)
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = [line for line in content.split('\n') if line.strip()]
            self.assertGreater(len(lines), 0, "应该有日志记录")
            
            # 验证格式：时间戳 - 级别 - 文件名:行号 - 消息
            log_line = lines[-1]  # 获取最后一行（最新的日志）
            
            # 验证包含所有必需部分
            parts = log_line.split(' - ')
            self.assertGreaterEqual(len(parts), 4, "日志应该包含至少4个部分")
            
            # 验证时间戳格式：YYYY-MM-DD HH:MM:SS
            timestamp = parts[0]
            timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
            self.assertRegex(timestamp, timestamp_pattern, "时间戳格式应该正确")
            
            # 验证级别
            level = parts[1]
            self.assertIn(level, ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                         "级别应该是有效的日志级别")
            
            # 验证文件名:行号格式
            file_location = parts[2]
            file_pattern = r'\w+\.py:\d+'
            self.assertRegex(file_location, file_pattern, "文件名:行号格式应该正确")
            
            # 验证消息
            message = ' - '.join(parts[3:])  # 消息可能包含 ' - '
            self.assertIn(test_message, message, "消息应该被正确记录")
    
    def test_log_format_regex_match(self):
        """使用正则表达式验证日志格式"""
        test_message = "正则测试消息"
        self.logger.info(test_message)
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 完整的日志格式正则表达式
            pattern = (
                r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'  # 时间戳
                r' - '                                    # 分隔符
                r'(DEBUG|INFO|WARNING|ERROR|CRITICAL)'   # 级别
                r' - '                                    # 分隔符
                r'\w+\.py:\d+'                           # 文件名:行号
                r' - '                                    # 分隔符
                r'.+'                                     # 消息
            )
            
            # 查找匹配的行
            matches = re.findall(pattern, content)
            self.assertGreater(len(matches), 0, "应该有匹配的日志行")
    
    def test_all_levels_format_consistency(self):
        """测试所有级别的日志格式一致性"""
        levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
        messages = {}
        
        for level in levels:
            message = f"{level}级别测试消息"
            messages[level] = message
            getattr(self.logger, level.lower())(message)
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = [line for line in content.split('\n') if line.strip()]
            
            # 验证每条日志都符合格式
            for line in lines:
                if any(msg in line for msg in messages.values()):
                    parts = line.split(' - ')
                    self.assertGreaterEqual(len(parts), 4, f"日志行格式不正确: {line}")
    
    def test_log_format_no_color_in_file(self):
        """测试日志文件中不包含颜色代码"""
        self.logger.debug("DEBUG消息")
        self.logger.info("INFO消息")
        self.logger.warning("WARNING消息")
        self.logger.error("ERROR消息")
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
            # 验证不包含ANSI颜色代码
            ansi_pattern = r'\033\[[0-9;]*m'
            matches = re.findall(ansi_pattern, content)
            self.assertEqual(len(matches), 0, "日志文件不应该包含ANSI颜色代码")
    
    def test_log_format_timestamp_accuracy(self):
        """测试时间戳的准确性"""
        before_time = datetime.now()
        self.logger.info("时间戳测试消息")
        after_time = datetime.now()
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            # 提取时间戳
            timestamp_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
            matches = re.findall(timestamp_pattern, content)
            self.assertGreater(len(matches), 0, "应该找到时间戳")
            
            # 解析时间戳
            log_timestamp = datetime.strptime(matches[-1], '%Y-%m-%d %H:%M:%S')
            
            # 验证时间戳在合理范围内
            self.assertGreaterEqual(log_timestamp, before_time - timedelta(seconds=1),
                                  "日志时间戳应该不早于记录前的时间")
            self.assertLessEqual(log_timestamp, after_time + timedelta(seconds=1),
                               "日志时间戳应该不晚于记录后的时间")
    
    def test_log_format_filename_lineno_accuracy(self):
        """测试文件名和行号的准确性"""
        # 记录当前文件名和行号
        current_file = Path(__file__).name
        test_line_number = None
        
        def log_with_line_check():
            nonlocal test_line_number
            test_line_number = sys._getframe().f_lineno + 1  # 下一行
            self.logger.info("文件名和行号测试消息")
        
        log_with_line_check()
        
        log_file = self._get_log_file_path()
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            # 查找包含测试消息的行
            for line in content.split('\n'):
                if "文件名和行号测试消息" in line:
                    # 提取文件名:行号部分
                    match = re.search(r'(\w+\.py):(\d+)', line)
                    if match:
                        logged_file, logged_line = match.groups()
                        # 验证文件名（可能是当前文件或logger文件）
                        self.assertIn(logged_file, [current_file, 'logger.py', 'test_logger_comprehensive.py'],
                                    "文件名应该正确")
                        # 验证行号是数字
                        self.assertTrue(logged_line.isdigit(), "行号应该是数字")
                    break
    
    def _get_log_file_path(self):
        """获取日志文件路径"""
        today = datetime.now().strftime("%Y-%m-%d")
        return Path(self.test_log_dir) / f"{self.test_name}_{today}.log"


class TestLoggerIntegration(unittest.TestCase):
    """综合集成测试"""
    
    def setUp(self):
        """测试前准备"""
        self.test_log_dir = "test_logs_integration"
        self.test_name = "integration_test"
    
    def tearDown(self):
        """测试后清理"""
        self._cleanup_test_files()
    
    def _cleanup_test_files(self):
        """清理测试文件"""
        test_log_path = Path(self.test_log_dir)
        if test_log_path.exists():
            for log_file in test_log_path.glob("*.log"):
                try:
                    log_file.unlink()
                except:
                    pass
            try:
                test_log_path.rmdir()
            except:
                pass
    
    def test_complete_workflow(self):
        """测试完整的日志工作流程"""
        logger = get_logger(self.test_name, log_dir=self.test_log_dir)
        
        # 1. 测试各级别日志
        logger.debug("工作流程DEBUG")
        logger.info("工作流程INFO")
        logger.warning("工作流程WARNING")
        logger.error("工作流程ERROR")
        
        # 2. 验证文件创建
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = Path(self.test_log_dir) / f"{self.test_name}_{today}.log"
        self.assertTrue(log_file.exists(), "日志文件应该被创建")
        
        # 3. 验证格式
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} - \w+ - \w+\.py:\d+ - .+'
            matches = re.findall(pattern, content)
            self.assertGreater(len(matches), 0, "应该有符合格式的日志")
        
        # 4. 测试多线程
        def worker(thread_id):
            logger.info(f"线程{thread_id}工作")
        
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # 5. 验证所有内容都在文件中
        with open(log_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn("工作流程DEBUG", content)
            self.assertIn("工作流程INFO", content)
            for i in range(5):
                self.assertIn(f"线程{i}工作", content)


if __name__ == '__main__':
    # 创建测试套件
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # 添加所有测试类
    suite.addTests(loader.loadTestsFromTestCase(TestLogLevels))
    suite.addTests(loader.loadTestsFromTestCase(TestLogFileDateCreation))
    suite.addTests(loader.loadTestsFromTestCase(TestThreadSafety))
    suite.addTests(loader.loadTestsFromTestCase(TestLogFileRotation))
    suite.addTests(loader.loadTestsFromTestCase(TestLogFormat))
    suite.addTests(loader.loadTestsFromTestCase(TestLoggerIntegration))
    
    # 运行测试
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 输出测试摘要
    print("\n" + "=" * 60)
    print("测试摘要")
    print("=" * 60)
    print(f"运行测试: {result.testsRun}")
    print(f"成功: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    
    if result.failures:
        print("\n失败的测试:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\n错误的测试:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    print("=" * 60)

