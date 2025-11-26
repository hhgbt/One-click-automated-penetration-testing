"""
日志管理工具模块

功能特性：
1. 支持DEBUG/INFO/WARNING/ERROR四级日志输出
2. 同时输出到控制台（带颜色）和文件
3. 自动创建logs目录（如果不存在）
4. 日志格式：时间戳 - 级别 - 文件名:行号 - 消息
5. 文件按日期滚动，最大保留7天
6. 文件命名：app_YYYY-MM-DD.log
7. 线程安全设计
8. 权限问题处理
9. 单例模式，避免重复配置
10. 提供简单的调用接口

使用示例：
    from src.utils.logger import get_logger
    
    logger = get_logger(__name__)
    logger.debug("这是一条调试信息")
    logger.info("这是一条普通信息")
    logger.warning("这是一条警告信息")
    logger.error("这是一条错误信息")
"""

import os
import sys
import logging
import logging.handlers
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """带颜色的日志格式化器，用于控制台输出"""
    
    # ANSI颜色代码
    COLORS = {
        'DEBUG': '\033[34m',      # 蓝色
        'INFO': '\033[32m',       # 绿色
        'WARNING': '\033[33m',    # 黄色
        'ERROR': '\033[31m',      # 红色
        'CRITICAL': '\033[35m',   # 紫色
        'RESET': '\033[0m'        # 重置颜色
    }
    
    def __init__(self, fmt=None, datefmt=None, use_color=True):
        """
        初始化彩色格式化器
        
        Args:
            fmt: 日志格式字符串
            datefmt: 日期格式字符串
            use_color: 是否使用颜色（Windows需要支持ANSI）
        """
        super().__init__(fmt, datefmt)
        self.use_color = use_color and self._supports_color()
    
    def _supports_color(self) -> bool:
        """
        检测终端是否支持ANSI颜色代码
        
        Returns:
            如果支持颜色返回True，否则返回False
        """
        # Windows 10+ 支持ANSI转义序列
        if sys.platform == 'win32':
            try:
                # 尝试启用Windows ANSI支持
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                return True
            except:
                return False
        # Unix/Linux/Mac通常支持
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    
    def format(self, record):
        """
        格式化日志记录，添加颜色
        
        Args:
            record: 日志记录对象
            
        Returns:
            格式化后的日志字符串
        """
        if self.use_color:
            # 保存原始级别名称
            levelname = record.levelname
            # 添加颜色代码
            color = self.COLORS.get(levelname, self.COLORS['RESET'])
            reset = self.COLORS['RESET']
            # 为级别名称添加颜色
            record.levelname = f"{color}{levelname}{reset}"
        
        # 调用父类方法格式化
        formatted = super().format(record)
        
        # 恢复原始级别名称（避免影响文件输出）
        if self.use_color:
            record.levelname = levelname
        
        return formatted


class Logger:
    """
    日志管理器类，负责日志的初始化、配置和管理
    
    采用单例模式，确保每个配置只创建一个实例
    线程安全设计，支持多线程环境使用
    """
    
    _instances = {}  # 存储不同配置的实例
    _lock = threading.Lock()  # 线程锁，确保线程安全
    
    def __init__(self, name: str = "app", log_dir: str = "logs"):
        """
        初始化日志管理器
        
        Args:
            name: 日志名称，用于文件命名（默认为"app"）
            log_dir: 日志文件存储目录（默认为"logs"）
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)  # 设置根日志级别为DEBUG，允许所有级别的日志
        
        # 避免重复添加处理器
        if not self.logger.handlers:
            self._setup_handlers()
            self._cleanup_old_logs()
    
    def _ensure_log_dir(self):
        """
        确保日志目录存在，如果不存在则创建
        处理权限问题，如果创建失败会抛出异常
        """
        if not self.log_dir.exists():
            try:
                self.log_dir.mkdir(parents=True, exist_ok=True)
                # 验证目录是否真的创建成功
                if not self.log_dir.exists():
                    raise PermissionError(f"无法创建日志目录: {self.log_dir.absolute()}")
            except PermissionError as e:
                # 权限错误，尝试使用当前目录
                print(f"警告: 无法创建日志目录 {self.log_dir}: {e}")
                print(f"将使用当前目录作为日志存储位置")
                self.log_dir = Path(".")
            except OSError as e:
                # 其他系统错误
                raise OSError(f"创建日志目录失败: {self.log_dir.absolute()}, 错误: {e}")
    
    def _get_log_file_path(self) -> Path:
        """
        获取当前日期的日志文件路径
        
        Returns:
            日志文件的完整路径
        """
        today = datetime.now().strftime("%Y-%m-%d")
        filename = f"{self.name}_{today}.log"
        return self.log_dir / filename
    
    def _setup_handlers(self):
        """
        设置日志处理器：控制台处理器（带颜色）和文件处理器
        处理文件创建时的权限问题
        """
        # 确保日志目录存在
        self._ensure_log_dir()
        
        # 定义日志格式：时间戳 - 级别 - 文件名:行号 - 消息
        log_format = '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        date_format = '%Y-%m-%d %H:%M:%S'
        
        # 1. 控制台处理器 - 使用彩色格式化器
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_formatter = ColoredFormatter(
            fmt=log_format,
            datefmt=date_format,
            use_color=True
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # 2. 文件处理器 - 使用TimedRotatingFileHandler实现按日期滚动
        log_file = self._get_log_file_path()
        
        try:
            file_handler = logging.handlers.TimedRotatingFileHandler(
                filename=str(log_file),
                when='midnight',  # 每天午夜滚动
                interval=1,       # 间隔1天
                backupCount=7,    # 保留7个备份文件（7天）
                encoding='utf-8', # 使用UTF-8编码
                delay=False       # 不延迟创建文件
            )
            file_handler.setLevel(logging.DEBUG)
            # 文件输出不使用颜色
            file_formatter = logging.Formatter(
                fmt=log_format,
                datefmt=date_format
            )
            file_handler.setFormatter(file_formatter)
            file_handler.suffix = "%Y-%m-%d"  # 备份文件后缀格式
            self.logger.addHandler(file_handler)
        except PermissionError as e:
            # 权限错误，只使用控制台输出
            self.logger.warning(f"无法创建日志文件 {log_file}: {e}，将仅使用控制台输出")
        except OSError as e:
            # 其他文件系统错误
            self.logger.warning(f"创建日志文件失败 {log_file}: {e}，将仅使用控制台输出")
    
    def _cleanup_old_logs(self):
        """
        清理超过7天的旧日志文件
        注意：TimedRotatingFileHandler的backupCount参数会自动管理备份文件，
        但为了确保清理，这里手动检查并删除超过7天的日志文件
        线程安全：使用锁保护文件操作
        """
        if not self.log_dir.exists():
            return
        
        # 计算7天前的日期
        cutoff_date = datetime.now() - timedelta(days=7)
        
        # 使用锁保护文件操作
        with self._lock:
            # 遍历日志目录，删除超过7天的日志文件
            for log_file in self.log_dir.glob(f"{self.name}_*.log"):
                try:
                    # 从文件名中提取日期（格式：app_YYYY-MM-DD.log）
                    filename = log_file.stem  # 获取不带扩展名的文件名
                    date_str = filename.replace(f"{self.name}_", "")
                    file_date = datetime.strptime(date_str, "%Y-%m-%d")
                    
                    # 如果文件日期早于7天前，则删除
                    if file_date < cutoff_date:
                        log_file.unlink()
                        self.logger.debug(f"已删除过期日志文件: {log_file.name}")
                except (ValueError, OSError, PermissionError) as e:
                    # 如果文件名格式不正确、删除失败或权限不足，记录错误但继续处理其他文件
                    self.logger.warning(f"处理日志文件 {log_file.name} 时出错: {e}")
    
    def get_logger(self) -> logging.Logger:
        """
        获取配置好的logger对象
        
        Returns:
            配置好的logging.Logger对象
        """
        return self.logger
    
    @classmethod
    def get_instance(cls, name: str = "app", log_dir: str = "logs") -> 'Logger':
        """
        获取Logger单例实例（线程安全）
        
        Args:
            name: 日志名称
            log_dir: 日志目录
            
        Returns:
            Logger实例
        """
        key = (name, log_dir)
        
        # 双重检查锁定模式，确保线程安全
        if key not in cls._instances:
            with cls._lock:
                if key not in cls._instances:
                    cls._instances[key] = cls(name, log_dir)
        
        return cls._instances[key]
    
    def _ensure_log_dir(self):
        """
        确保日志目录存在，如果不存在则创建
        """
        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True, exist_ok=True)
            print(f"已创建日志目录: {self.log_dir.absolute()}")
    
    def _get_log_file_path(self) -> Path:
        """
        获取当前日期的日志文件路径
        
        Returns:
            日志文件的完整路径
        """
        today = datetime.now().strftime("%Y-%m-%d")
        filename = f"{self.name}_{today}.log"
        return self.log_dir / filename
    
    def _setup_handlers(self):
        """
        设置日志处理器：控制台处理器和文件处理器
        """
        # 确保日志目录存在
        self._ensure_log_dir()
        
        # 定义日志格式：时间戳 - 级别 - 文件名:行号 - 消息
        formatter = logging.Formatter(
            fmt='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # 1. 控制台处理器 - 输出所有级别的日志
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 2. 文件处理器 - 使用TimedRotatingFileHandler实现按日期滚动
        log_file = self._get_log_file_path()
        file_handler = logging.handlers.TimedRotatingFileHandler(
            filename=str(log_file),
            when='midnight',  # 每天午夜滚动
            interval=1,       # 间隔1天
            backupCount=7,    # 保留7个备份文件（7天）
            encoding='utf-8', # 使用UTF-8编码
            delay=False       # 不延迟创建文件
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        file_handler.suffix = "%Y-%m-%d"  # 备份文件后缀格式
        self.logger.addHandler(file_handler)
    
    def _cleanup_old_logs(self):
        """
        清理超过7天的旧日志文件
        注意：TimedRotatingFileHandler的backupCount参数会自动管理备份文件，
        但为了确保清理，这里手动检查并删除超过7天的日志文件
        """
        if not self.log_dir.exists():
            return
        
        # 计算7天前的日期
        cutoff_date = datetime.now() - timedelta(days=7)
        
        # 遍历日志目录，删除超过7天的日志文件
        for log_file in self.log_dir.glob(f"{self.name}_*.log"):
            try:
                # 从文件名中提取日期（格式：app_YYYY-MM-DD.log）
                filename = log_file.stem  # 获取不带扩展名的文件名
                date_str = filename.replace(f"{self.name}_", "")
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                # 如果文件日期早于7天前，则删除
                if file_date < cutoff_date:
                    log_file.unlink()
                    print(f"已删除过期日志文件: {log_file.name}")
            except (ValueError, OSError) as e:
                # 如果文件名格式不正确或删除失败，记录错误但继续处理其他文件
                print(f"处理日志文件 {log_file.name} 时出错: {e}")
    
    def get_logger(self):
        """
        获取配置好的logger对象
        
        Returns:
            配置好的logging.Logger对象
        """
        return self.logger


def get_logger(name: str = "app", log_dir: str = "logs") -> logging.Logger:
    """
    获取日志记录器的便捷函数（线程安全）
    
    这是推荐的使用方式，会自动管理日志器的创建和配置。
    采用单例模式，相同配置的日志器只会创建一次。
    每个模块应该使用自己的模块名作为name参数，这样可以更好地追踪日志来源。
    
    Args:
        name: 日志名称，通常使用__name__（模块名）或自定义名称
        log_dir: 日志文件存储目录（默认为"logs"）
    
    Returns:
        配置好的logging.Logger对象，可以直接使用debug/info/warning/error方法
    
    Examples:
        # 在模块中使用
        from src.utils.logger import get_logger
        
        logger = get_logger(__name__)
        logger.debug("调试信息（蓝色）")
        logger.info("普通信息（绿色）")
        logger.warning("警告信息（黄色）")
        logger.error("错误信息（红色）")
        
        # 或者使用自定义名称和目录
        logger = get_logger("my_module", log_dir="custom_logs")
    """
    # 使用单例模式获取Logger实例
    logger_manager = Logger.get_instance(name=name, log_dir=log_dir)
    return logger_manager.get_logger()


# 如果直接运行此模块，进行功能测试
if __name__ == "__main__":
    # 测试日志功能
    print("=" * 60)
    print("日志工具测试")
    print("=" * 60)
    
    # 获取日志器
    logger = get_logger("test_module")
    
    # 测试不同级别的日志（控制台会显示不同颜色）
    logger.debug("这是一条DEBUG级别的日志消息（蓝色）")
    logger.info("这是一条INFO级别的日志消息（绿色）")
    logger.warning("这是一条WARNING级别的日志消息（黄色）")
    logger.error("这是一条ERROR级别的日志消息（红色）")
    
    # 测试日志格式（应该显示文件名和行号）
    logger.info("测试日志格式：应该显示文件名logger.py和行号")
    
    # 测试异常日志
    try:
        result = 1 / 0
    except Exception as e:
        logger.error(f"捕获到异常: {e}", exc_info=True)
    
    print("\n" + "=" * 60)
    print("测试完成！请检查logs目录下的日志文件。")
    print(f"日志文件路径: {Path('logs').absolute()}")
    print("=" * 60)

