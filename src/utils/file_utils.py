"""
文件操作工具模块

功能特性：
1. 安全的文件读写（文本和二进制）
2. 自动创建不存在的目录
3. 文件编码自动检测
4. 大文件分块读取
5. 文件锁机制（避免并发冲突）
6. 线程安全设计
7. 支持上下文管理器

使用示例：
    from src.utils.file_utils import FileUtils
    
    # 基本使用
    file_utils = FileUtils()
    content = file_utils.read_file('data.txt')
    file_utils.write_file('output.txt', 'Hello World')
    
    # 使用上下文管理器
    with FileUtils() as fu:
        content = fu.read_file('data.txt')
        fu.write_file('output.txt', content)
"""

import os
import io
import json
import re
import time
import hashlib
import stat
import tempfile
import threading
import fcntl  # Unix文件锁
import msvcrt  # Windows文件锁
from pathlib import Path
from typing import Optional, List, Union, BinaryIO, TextIO, Dict, Any, Callable
from datetime import datetime, date, timedelta
from contextlib import contextmanager

try:
    import chardet  # 编码检测库
    HAS_CHARDET = True
except ImportError:
    HAS_CHARDET = False

try:
    from src.utils.logger import get_logger
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    get_logger = lambda name: logging.getLogger(name)


class FileUtilsError(Exception):
    """文件操作工具异常基类"""
    pass


class FileLockError(FileUtilsError):
    """文件锁异常"""
    pass


class FileUtils:
    """
    文件操作工具类
    
    提供安全的文件读写、目录管理、编码检测等功能
    支持文件锁机制，确保线程安全
    """
    
    def __init__(self, default_encoding: str = 'utf-8', chunk_size: int = 8192):
        """
        初始化文件操作工具
        
        Args:
            default_encoding: 默认文件编码，默认'utf-8'
            chunk_size: 大文件分块读取的块大小（字节），默认8192
        """
        self.default_encoding = default_encoding
        self.chunk_size = chunk_size
        self._locks = {}  # 文件锁字典
        self._lock = threading.Lock()  # 保护锁字典的线程锁
        self.logger = get_logger(__name__)
    
    def _get_file_lock(self, file_path: Path) -> threading.Lock:
        """
        获取文件锁（线程安全）
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件对应的线程锁
        """
        file_key = str(file_path.absolute())
        
        with self._lock:
            if file_key not in self._locks:
                self._locks[file_key] = threading.Lock()
            return self._locks[file_key]
    
    def _detect_encoding(self, file_path: Path) -> str:
        """
        自动检测文件编码
        
        Args:
            file_path: 文件路径
            
        Returns:
            检测到的编码名称
        """
        if not HAS_CHARDET:
            self.logger.warning("chardet未安装，无法自动检测编码，使用默认编码")
            return self.default_encoding
        
        try:
            # 读取文件的前几个字节来检测编码
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)  # 读取前10KB
            
            if not raw_data:
                return self.default_encoding
            
            # 使用chardet检测编码
            result = chardet.detect(raw_data)
            encoding = result.get('encoding', self.default_encoding)
            confidence = result.get('confidence', 0)
            
            # 如果置信度太低，使用默认编码
            if confidence < 0.7:
                self.logger.debug(f"编码检测置信度较低({confidence:.2f})，使用默认编码")
                return self.default_encoding
            
            self.logger.debug(f"检测到文件编码: {encoding} (置信度: {confidence:.2f})")
            return encoding
            
        except Exception as e:
            self.logger.warning(f"编码检测失败: {e}，使用默认编码")
            return self.default_encoding
    
    @contextmanager
    def _file_lock(self, file_path: Path, mode: str = 'r'):
        """
        文件锁上下文管理器（跨平台）
        
        Args:
            file_path: 文件路径
            mode: 文件打开模式
            
        Yields:
            文件对象
        """
        file_path = Path(file_path)
        
        # 确保目录存在
        if mode in ['w', 'a', 'x']:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 获取线程锁
        thread_lock = self._get_file_lock(file_path)
        
        try:
            # 获取线程锁
            thread_lock.acquire()
            
            # 打开文件
            if 'b' in mode:
                file_obj = open(file_path, mode)
            else:
                file_obj = open(file_path, mode, encoding=self.default_encoding)
            
            # 尝试获取系统级文件锁（如果支持）
            lock_acquired = False
            try:
                if os.name == 'nt':  # Windows
                    # Windows文件锁
                    # 注意：msvcrt.locking需要文件大小，对于新文件可能有问题
                    # 这里使用一个较大的值来锁定文件
                    try:
                        file_size = file_path.stat().st_size if file_path.exists() else 1
                        msvcrt.locking(file_obj.fileno(), msvcrt.LK_LOCK, max(file_size, 1))
                        lock_acquired = True
                    except (OSError, IOError, AttributeError):
                        # 文件锁获取失败，使用线程锁
                        pass
                else:  # Unix/Linux
                    # Unix文件锁（独占锁）
                    fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
                    lock_acquired = True
            except (OSError, IOError, AttributeError) as e:
                # 文件锁获取失败，记录调试信息但继续执行
                # 线程锁仍然有效，可以保证基本安全
                self.logger.debug(f"无法获取系统级文件锁: {e}，使用线程锁")
            
            try:
                yield file_obj
            finally:
                # 释放系统级文件锁
                if lock_acquired:
                    try:
                        if os.name == 'nt':
                            file_size = file_path.stat().st_size if file_path.exists() else 1
                            msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, max(file_size, 1))
                        else:
                            fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
                    except (OSError, IOError, AttributeError):
                        pass
                
                file_obj.close()
        finally:
            # 释放线程锁
            thread_lock.release()
    
    def read_file(
        self,
        file_path: Union[str, Path],
        encoding: Optional[str] = None,
        auto_detect_encoding: bool = True
    ) -> str:
        """
        读取文本文件
        
        Args:
            file_path: 文件路径
            encoding: 文件编码，如果为None则使用默认编码或自动检测
            auto_detect_encoding: 是否自动检测编码，默认True
            
        Returns:
            文件内容（字符串）
            
        Raises:
            FileUtilsError: 文件读取失败时抛出
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if not file_path.is_file():
            raise FileUtilsError(f"路径不是文件: {file_path}")
        
        # 确定编码
        if encoding is None:
            if auto_detect_encoding:
                encoding = self._detect_encoding(file_path)
            else:
                encoding = self.default_encoding
        
        try:
            with self._file_lock(file_path, 'r') as f:
                content = f.read()
            return content
        except UnicodeDecodeError as e:
            raise FileUtilsError(f"文件编码错误: {file_path}，尝试使用编码: {encoding}") from e
        except Exception as e:
            raise FileUtilsError(f"读取文件失败: {file_path}") from e
    
    def write_file(
        self,
        file_path: Union[str, Path],
        content: str,
        encoding: Optional[str] = None,
        create_dirs: bool = True
    ):
        """
        写入文本文件
        
        Args:
            file_path: 文件路径
            content: 文件内容（字符串）
            encoding: 文件编码，如果为None则使用默认编码
            create_dirs: 是否自动创建目录，默认True
            
        Raises:
            FileUtilsError: 文件写入失败时抛出
        """
        file_path = Path(file_path)
        
        # 自动创建目录
        if create_dirs:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        encoding = encoding or self.default_encoding
        
        try:
            with self._file_lock(file_path, 'w') as f:
                f.write(content)
            self.logger.debug(f"文件写入成功: {file_path}")
        except Exception as e:
            raise FileUtilsError(f"写入文件失败: {file_path}") from e
    
    def read_bytes(self, file_path: Union[str, Path]) -> bytes:
        """
        读取二进制文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容（字节）
            
        Raises:
            FileUtilsError: 文件读取失败时抛出
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if not file_path.is_file():
            raise FileUtilsError(f"路径不是文件: {file_path}")
        
        try:
            with self._file_lock(file_path, 'rb') as f:
                data = f.read()
            return data
        except Exception as e:
            raise FileUtilsError(f"读取二进制文件失败: {file_path}") from e
    
    def write_bytes(
        self,
        file_path: Union[str, Path],
        data: bytes,
        create_dirs: bool = True
    ):
        """
        写入二进制文件
        
        Args:
            file_path: 文件路径
            data: 文件内容（字节）
            create_dirs: 是否自动创建目录，默认True
            
        Raises:
            FileUtilsError: 文件写入失败时抛出
        """
        file_path = Path(file_path)
        
        # 自动创建目录
        if create_dirs:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with self._file_lock(file_path, 'wb') as f:
                f.write(data)
            self.logger.debug(f"二进制文件写入成功: {file_path}")
        except Exception as e:
            raise FileUtilsError(f"写入二进制文件失败: {file_path}") from e
    
    def append_file(
        self,
        file_path: Union[str, Path],
        content: str,
        encoding: Optional[str] = None,
        create_dirs: bool = True
    ):
        """
        追加内容到文本文件
        
        Args:
            file_path: 文件路径
            content: 要追加的内容（字符串）
            encoding: 文件编码，如果为None则使用默认编码
            create_dirs: 是否自动创建目录，默认True
            
        Raises:
            FileUtilsError: 文件追加失败时抛出
        """
        file_path = Path(file_path)
        
        # 自动创建目录
        if create_dirs:
            file_path.parent.mkdir(parents=True, exist_ok=True)
        
        encoding = encoding or self.default_encoding
        
        try:
            with self._file_lock(file_path, 'a') as f:
                f.write(content)
            self.logger.debug(f"文件追加成功: {file_path}")
        except Exception as e:
            raise FileUtilsError(f"追加文件失败: {file_path}") from e
    
    def read_file_chunked(
        self,
        file_path: Union[str, Path],
        encoding: Optional[str] = None,
        chunk_size: Optional[int] = None
    ):
        """
        分块读取大文件（生成器）
        
        Args:
            file_path: 文件路径
            encoding: 文件编码，如果为None则使用默认编码或自动检测
            chunk_size: 块大小（字节），如果为None则使用默认值
            
        Yields:
            文件内容块（字符串）
            
        Raises:
            FileUtilsError: 文件读取失败时抛出
        """
        file_path = Path(file_path)
        chunk_size = chunk_size or self.chunk_size
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if not file_path.is_file():
            raise FileUtilsError(f"路径不是文件: {file_path}")
        
        # 确定编码
        if encoding is None:
            encoding = self._detect_encoding(file_path)
        
        try:
            with self._file_lock(file_path, 'r') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except Exception as e:
            raise FileUtilsError(f"分块读取文件失败: {file_path}") from e
    
    def read_bytes_chunked(
        self,
        file_path: Union[str, Path],
        chunk_size: Optional[int] = None
    ):
        """
        分块读取大二进制文件（生成器）
        
        Args:
            file_path: 文件路径
            chunk_size: 块大小（字节），如果为None则使用默认值
            
        Yields:
            文件内容块（字节）
            
        Raises:
            FileUtilsError: 文件读取失败时抛出
        """
        file_path = Path(file_path)
        chunk_size = chunk_size or self.chunk_size
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if not file_path.is_file():
            raise FileUtilsError(f"路径不是文件: {file_path}")
        
        try:
            with self._file_lock(file_path, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except Exception as e:
            raise FileUtilsError(f"分块读取二进制文件失败: {file_path}") from e
    
    def file_exists(self, file_path: Union[str, Path]) -> bool:
        """
        检查文件是否存在
        
        Args:
            file_path: 文件路径
            
        Returns:
            如果文件存在返回True，否则返回False
        """
        file_path = Path(file_path)
        return file_path.exists() and file_path.is_file()
    
    def create_dir(
        self,
        dir_path: Union[str, Path],
        exist_ok: bool = True
    ) -> Path:
        """
        创建目录
        
        Args:
            dir_path: 目录路径
            exist_ok: 如果目录已存在是否不抛出异常，默认True
            
        Returns:
            创建的目录路径
            
        Raises:
            FileUtilsError: 目录创建失败时抛出
        """
        dir_path = Path(dir_path)
        
        try:
            dir_path.mkdir(parents=True, exist_ok=exist_ok)
            self.logger.debug(f"目录创建成功: {dir_path}")
            return dir_path
        except FileExistsError:
            if not exist_ok:
                raise FileUtilsError(f"目录已存在: {dir_path}")
            return dir_path
        except Exception as e:
            raise FileUtilsError(f"创建目录失败: {dir_path}") from e
    
    def list_files(
        self,
        dir_path: Union[str, Path],
        pattern: str = '*',
        recursive: bool = False
    ) -> List[Path]:
        """
        列出目录中的文件
        
        Args:
            dir_path: 目录路径
            pattern: 文件匹配模式（glob模式），默认'*'
            recursive: 是否递归搜索子目录，默认False
            
        Returns:
            文件路径列表
            
        Raises:
            FileUtilsError: 目录不存在或读取失败时抛出
        """
        dir_path = Path(dir_path)
        
        if not dir_path.exists():
            raise FileUtilsError(f"目录不存在: {dir_path}")
        
        if not dir_path.is_dir():
            raise FileUtilsError(f"路径不是目录: {dir_path}")
        
        try:
            if recursive:
                files = list(dir_path.rglob(pattern))
            else:
                files = list(dir_path.glob(pattern))
            
            # 只返回文件，不包括目录
            files = [f for f in files if f.is_file()]
            return files
        except Exception as e:
            raise FileUtilsError(f"列出文件失败: {dir_path}") from e
    
    def get_file_size(self, file_path: Union[str, Path]) -> int:
        """
        获取文件大小（字节）
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件大小（字节）
            
        Raises:
            FileUtilsError: 文件不存在或获取失败时抛出
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if not file_path.is_file():
            raise FileUtilsError(f"路径不是文件: {file_path}")
        
        try:
            return file_path.stat().st_size
        except Exception as e:
            raise FileUtilsError(f"获取文件大小失败: {file_path}") from e
    
    def delete_file(self, file_path: Union[str, Path]) -> bool:
        """
        删除文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            如果删除成功返回True，否则返回False
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return False
        
        if not file_path.is_file():
            return False
        
        try:
            file_path.unlink()
            self.logger.debug(f"文件删除成功: {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"删除文件失败: {file_path}, 错误: {e}")
            return False
    
    def copy_file(
        self,
        src_path: Union[str, Path],
        dst_path: Union[str, Path],
        create_dirs: bool = True
    ):
        """
        复制文件
        
        Args:
            src_path: 源文件路径
            dst_path: 目标文件路径
            create_dirs: 是否自动创建目标目录，默认True
            
        Raises:
            FileUtilsError: 文件复制失败时抛出
        """
        src_path = Path(src_path)
        dst_path = Path(dst_path)
        
        if not src_path.exists():
            raise FileUtilsError(f"源文件不存在: {src_path}")
        
        if not src_path.is_file():
            raise FileUtilsError(f"源路径不是文件: {src_path}")
        
        # 自动创建目标目录
        if create_dirs:
            dst_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # 读取源文件
            data = self.read_bytes(src_path)
            # 写入目标文件
            self.write_bytes(dst_path, data, create_dirs=False)
            self.logger.debug(f"文件复制成功: {src_path} -> {dst_path}")
        except Exception as e:
            raise FileUtilsError(f"复制文件失败: {src_path} -> {dst_path}") from e
    
    def _json_serializer(self, obj: Any) -> Any:
        """
        JSON序列化器，处理日期时间等特殊类型
        
        Args:
            obj: 要序列化的对象
            
        Returns:
            可序列化的对象
        """
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        raise TypeError(f"类型 {type(obj)} 无法序列化为JSON")
    
    def _backup_file(self, file_path: Path) -> Optional[Path]:
        """
        备份文件
        
        Args:
            file_path: 文件路径
            
        Returns:
            备份文件路径，如果备份失败返回None
        """
        if not file_path.exists():
            return None
        
        try:
            backup_path = file_path.with_suffix(file_path.suffix + '.bak')
            self.copy_file(file_path, backup_path, create_dirs=False)
            self.logger.debug(f"文件备份成功: {backup_path}")
            return backup_path
        except Exception as e:
            self.logger.warning(f"文件备份失败: {e}")
            return None
    
    def read_json(
        self,
        file_path: Union[str, Path],
        encoding: str = 'utf-8',
        default: Optional[Union[Dict, List]] = None
    ) -> Union[Dict, List]:
        """
        读取JSON文件
        
        Args:
            file_path: JSON文件路径
            encoding: 文件编码，默认'utf-8'
            default: 如果文件不存在返回的默认值，默认None
            
        Returns:
            JSON数据（字典或列表）
            
        Raises:
            FileUtilsError: JSON解析失败时抛出
        """
        file_path = Path(file_path)
        
        # 如果文件不存在，返回默认值
        if not file_path.exists():
            if default is not None:
                self.logger.debug(f"文件不存在，返回默认值: {file_path}")
                return default
            raise FileUtilsError(f"JSON文件不存在: {file_path}")
        
        try:
            # 读取文件内容
            content = self.read_file(file_path, encoding=encoding, auto_detect_encoding=False)
            
            # 解析JSON
            data = json.loads(content)
            self.logger.debug(f"JSON文件读取成功: {file_path}")
            return data
            
        except json.JSONDecodeError as e:
            raise FileUtilsError(f"JSON解析失败: {file_path}, 错误: {e}") from e
        except Exception as e:
            raise FileUtilsError(f"读取JSON文件失败: {file_path}") from e
    
    def write_json(
        self,
        file_path: Union[str, Path],
        data: Union[Dict, List],
        encoding: str = 'utf-8',
        indent: int = 2,
        ensure_ascii: bool = False,
        create_backup: bool = True
    ):
        """
        写入JSON文件
        
        Args:
            file_path: JSON文件路径
            data: 要写入的数据（字典或列表）
            encoding: 文件编码，默认'utf-8'
            indent: JSON缩进空格数，默认2（美化输出）
            ensure_ascii: 是否确保ASCII编码，默认False（支持中文）
            create_backup: 是否创建备份文件，默认True
            
        Raises:
            FileUtilsError: JSON写入失败时抛出
        """
        file_path = Path(file_path)
        
        # 自动创建目录
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 如果文件存在且需要备份，先备份
        if create_backup and file_path.exists():
            self._backup_file(file_path)
        
        try:
            # 序列化JSON
            json_str = json.dumps(
                data,
                indent=indent,
                ensure_ascii=ensure_ascii,
                default=self._json_serializer
            )
            
            # 写入文件
            self.write_file(file_path, json_str, encoding=encoding, create_dirs=False)
            self.logger.debug(f"JSON文件写入成功: {file_path}")
            
        except (TypeError, ValueError) as e:
            raise FileUtilsError(f"JSON序列化失败: {file_path}, 错误: {e}") from e
        except Exception as e:
            raise FileUtilsError(f"写入JSON文件失败: {file_path}") from e
    
    def update_json(
        self,
        file_path: Union[str, Path],
        updates: Dict[str, Any],
        encoding: str = 'utf-8',
        create_backup: bool = True
    ):
        """
        部分更新JSON文件，保留其他字段
        
        Args:
            file_path: JSON文件路径
            updates: 要更新的字段字典
            encoding: 文件编码，默认'utf-8'
            create_backup: 是否创建备份文件，默认True
            
        Raises:
            FileUtilsError: JSON更新失败时抛出
        """
        file_path = Path(file_path)
        
        # 读取现有数据
        if file_path.exists():
            try:
                data = self.read_json(file_path, encoding=encoding, default={})
            except FileUtilsError:
                data = {}
        else:
            data = {}
        
        # 更新数据
        if isinstance(data, dict):
            data.update(updates)
        else:
            raise FileUtilsError(f"JSON文件不是字典类型，无法更新: {file_path}")
        
        # 写入更新后的数据
        self.write_json(file_path, data, encoding=encoding, create_backup=create_backup)
        self.logger.debug(f"JSON文件更新成功: {file_path}")
    
    def json_safe_update(
        self,
        file_path: Union[str, Path],
        update_func: Callable[[Dict[str, Any]], Dict[str, Any]],
        max_retries: int = 3,
        encoding: str = 'utf-8',
        create_backup: bool = True
    ) -> bool:
        """
        安全的JSON更新，使用文件锁避免并发写入冲突
        
        Args:
            file_path: JSON文件路径
            update_func: 更新函数，接收当前数据，返回更新后的数据
            max_retries: 最大重试次数，默认3
            encoding: 文件编码，默认'utf-8'
            create_backup: 是否创建备份文件，默认True
            
        Returns:
            更新是否成功
            
        Raises:
            FileUtilsError: 更新失败时抛出
        """
        file_path = Path(file_path)
        
        # 自动创建目录
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        for attempt in range(max_retries):
            try:
                # 读取现有数据（使用文件锁）
                if file_path.exists():
                    data = self.read_json(file_path, encoding=encoding, default={})
                else:
                    data = {}
                
                # 确保是字典类型
                if not isinstance(data, dict):
                    raise FileUtilsError(f"JSON文件不是字典类型: {file_path}")
                
                # 调用更新函数
                updated_data = update_func(data.copy())
                
                # 如果文件存在且需要备份，先备份
                if create_backup and file_path.exists():
                    self._backup_file(file_path)
                
                # 写入更新后的数据（使用文件锁）
                self.write_json(
                    file_path,
                    updated_data,
                    encoding=encoding,
                    create_backup=False  # 已经备份过了
                )
                
                self.logger.debug(f"JSON安全更新成功: {file_path}")
                return True
                
            except (IOError, OSError) as e:
                if attempt < max_retries - 1:
                    wait_time = 0.1 * (2 ** attempt)  # 指数退避
                    self.logger.warning(
                        f"JSON更新冲突，{wait_time:.2f}秒后重试 "
                        f"({attempt + 1}/{max_retries})"
                    )
                    time.sleep(wait_time)
                else:
                    raise FileUtilsError(f"JSON安全更新失败（已重试{max_retries}次）: {file_path}") from e
            except Exception as e:
                raise FileUtilsError(f"JSON安全更新失败: {file_path}") from e
        
        return False
    
    def read_json_lines(
        self,
        file_path: Union[str, Path],
        encoding: str = 'utf-8'
    ) -> List[Dict[str, Any]]:
        """
        读取JSON Lines格式文件（每行一个JSON对象）
        
        Args:
            file_path: JSON Lines文件路径
            encoding: 文件编码，默认'utf-8'
            
        Returns:
            JSON对象列表
            
        Raises:
            FileUtilsError: 读取失败时抛出
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"JSON Lines文件不存在: {file_path}")
        
        try:
            results = []
            content = self.read_file(file_path, encoding=encoding, auto_detect_encoding=False)
            
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line:  # 跳过空行
                    continue
                
                try:
                    obj = json.loads(line)
                    results.append(obj)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"JSON Lines第{line_num}行解析失败: {e}")
                    continue
            
            self.logger.debug(f"JSON Lines文件读取成功: {file_path}, 共{len(results)}条记录")
            return results
            
        except Exception as e:
            raise FileUtilsError(f"读取JSON Lines文件失败: {file_path}") from e
    
    def write_json_lines(
        self,
        file_path: Union[str, Path],
        data: List[Dict[str, Any]],
        encoding: str = 'utf-8',
        create_backup: bool = True
    ):
        """
        写入JSON Lines格式文件（每行一个JSON对象）
        
        Args:
            file_path: JSON Lines文件路径
            data: JSON对象列表
            encoding: 文件编码，默认'utf-8'
            create_backup: 是否创建备份文件，默认True
            
        Raises:
            FileUtilsError: 写入失败时抛出
        """
        file_path = Path(file_path)
        
        # 自动创建目录
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 如果文件存在且需要备份，先备份
        if create_backup and file_path.exists():
            self._backup_file(file_path)
        
        try:
            lines = []
            for obj in data:
                json_line = json.dumps(obj, ensure_ascii=False, default=self._json_serializer)
                lines.append(json_line)
            
            content = '\n'.join(lines) + '\n'
            self.write_file(file_path, content, encoding=encoding, create_dirs=False)
            self.logger.debug(f"JSON Lines文件写入成功: {file_path}, 共{len(data)}条记录")
            
        except Exception as e:
            raise FileUtilsError(f"写入JSON Lines文件失败: {file_path}") from e
    
    # ==================== 文件监控功能 ====================
    
    def watch_file(
        self,
        file_path: Union[str, Path],
        callback: Callable[[Path], None],
        check_interval: float = 1.0,
        stop_event: Optional[threading.Event] = None
    ) -> threading.Thread:
        """
        监控文件变化并触发回调
        
        Args:
            file_path: 要监控的文件路径
            callback: 回调函数，接收文件路径作为参数
            check_interval: 检查间隔（秒），默认1.0
            stop_event: 停止事件，如果提供则用于控制监控线程
            
        Returns:
            监控线程对象（可以通过stop_event.set()停止）
            
        Raises:
            FileUtilsError: 文件监控失败时抛出
            
        示例:
            # 基本使用
            def on_change(path):
                print(f"文件已修改: {path}")
            
            thread = file_utils.watch_file('file.txt', on_change)
            
            # 使用stop_event控制
            stop_event = threading.Event()
            thread = file_utils.watch_file('file.txt', on_change, stop_event=stop_event)
            # 稍后调用 stop_event.set() 停止监控
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"要监控的文件不存在: {file_path}")
        
        if stop_event is None:
            stop_event = threading.Event()
        
        # 使用列表来存储last_mtime，以便在嵌套函数中修改
        last_mtime = [file_path.stat().st_mtime if file_path.exists() else 0]
        
        def watch_worker():
            """监控工作线程"""
            self.logger.debug(f"开始监控文件: {file_path}")
            
            while not stop_event.is_set():
                try:
                    if file_path.exists():
                        current_mtime = file_path.stat().st_mtime
                        
                        # 检查文件是否被修改
                        if current_mtime > last_mtime[0]:
                            self.logger.debug(f"文件已修改: {file_path}")
                            try:
                                callback(file_path)
                            except Exception as e:
                                self.logger.error(f"文件监控回调执行失败: {e}")
                            last_mtime[0] = current_mtime
                    else:
                        # 文件被删除
                        if last_mtime[0] > 0:
                            self.logger.warning(f"监控的文件被删除: {file_path}")
                            last_mtime[0] = 0
                    
                    # 等待检查间隔
                    stop_event.wait(check_interval)
                    
                except Exception as e:
                    self.logger.error(f"文件监控出错: {e}")
                    stop_event.wait(check_interval)
        
        thread = threading.Thread(target=watch_worker, daemon=True)
        thread.start()
        self.logger.debug(f"文件监控线程已启动: {file_path}")
        return thread
    
    # ==================== 文件哈希计算 ====================
    
    def get_file_hash(
        self,
        file_path: Union[str, Path],
        algorithm: str = 'md5'
    ) -> str:
        """
        计算文件哈希值
        
        Args:
            file_path: 文件路径
            algorithm: 哈希算法，支持'md5', 'sha1', 'sha256'，默认'md5'
            
        Returns:
            文件的哈希值（十六进制字符串）
            
        Raises:
            FileUtilsError: 文件不存在或哈希计算失败时抛出
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if not file_path.is_file():
            raise FileUtilsError(f"路径不是文件: {file_path}")
        
        # 支持的哈希算法
        supported_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512,
        }
        
        if algorithm.lower() not in supported_algorithms:
            raise FileUtilsError(
                f"不支持的哈希算法: {algorithm}，"
                f"支持的算法: {', '.join(supported_algorithms.keys())}"
            )
        
        hash_func = supported_algorithms[algorithm.lower()]()
        
        try:
            # 分块读取文件计算哈希（节省内存）
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    hash_func.update(chunk)
            
            hash_value = hash_func.hexdigest()
            self.logger.debug(f"文件哈希计算成功: {file_path} ({algorithm})")
            return hash_value
            
        except Exception as e:
            raise FileUtilsError(f"计算文件哈希失败: {file_path}") from e
    
    # ==================== 文件权限管理 ====================
    
    def set_file_permission(
        self,
        file_path: Union[str, Path],
        mode: int = 0o644
    ):
        """
        设置文件权限（Unix/Linux）
        
        Args:
            file_path: 文件路径
            mode: 权限模式（八进制），默认0o644
            
        Raises:
            FileUtilsError: 权限设置失败时抛出
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileUtilsError(f"文件不存在: {file_path}")
        
        if os.name == 'nt':
            self.logger.warning("Windows系统不支持Unix权限模式")
            return
        
        try:
            file_path.chmod(mode)
            self.logger.debug(f"文件权限设置成功: {file_path} (0o{oct(mode)[2:]})")
        except Exception as e:
            raise FileUtilsError(f"设置文件权限失败: {file_path}") from e
    
    def is_readable(self, file_path: Union[str, Path]) -> bool:
        """
        检查文件是否可读
        
        Args:
            file_path: 文件路径
            
        Returns:
            如果文件可读返回True，否则返回False
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return False
        
        try:
            # 检查文件权限
            if os.name != 'nt':  # Unix/Linux
                file_stat = file_path.stat()
                # 检查用户、组、其他用户的读权限
                return bool(file_stat.st_mode & stat.S_IRUSR or
                           file_stat.st_mode & stat.S_IRGRP or
                           file_stat.st_mode & stat.S_IROTH)
            else:  # Windows
                # Windows直接尝试打开文件
                with open(file_path, 'r'):
                    return True
        except (OSError, IOError, PermissionError):
            return False
    
    def is_writable(self, file_path: Union[str, Path]) -> bool:
        """
        检查文件是否可写
        
        Args:
            file_path: 文件路径
            
        Returns:
            如果文件可写返回True，否则返回False
        """
        file_path = Path(file_path)
        
        # 如果文件不存在，检查目录是否可写
        if not file_path.exists():
            return os.access(file_path.parent, os.W_OK)
        
        try:
            # 检查文件权限
            if os.name != 'nt':  # Unix/Linux
                file_stat = file_path.stat()
                # 检查用户、组、其他用户的写权限
                return bool(file_stat.st_mode & stat.S_IWUSR or
                           file_stat.st_mode & stat.S_IWGRP or
                           file_stat.st_mode & stat.S_IWOTH)
            else:  # Windows
                # Windows直接尝试打开文件
                with open(file_path, 'a'):
                    return True
        except (OSError, IOError, PermissionError):
            return False
    
    # ==================== 临时文件管理 ====================
    
    def create_temp_file(
        self,
        suffix: str = '.tmp',
        content: Optional[Union[str, bytes]] = None,
        prefix: str = 'file_utils_',
        dir: Optional[Union[str, Path]] = None
    ) -> Path:
        """
        创建临时文件
        
        Args:
            suffix: 文件后缀，默认'.tmp'
            content: 文件内容（字符串或字节），默认None
            prefix: 文件前缀，默认'file_utils_'
            dir: 临时文件目录，默认None（使用系统临时目录）
            
        Returns:
            临时文件路径
            
        Raises:
            FileUtilsError: 临时文件创建失败时抛出
        """
        try:
            # 创建临时文件
            if dir:
                dir = Path(dir)
                dir.mkdir(parents=True, exist_ok=True)
            
            fd, temp_path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=str(dir) if dir else None)
            os.close(fd)  # 关闭文件描述符，我们稍后会重新打开
            
            temp_path = Path(temp_path)
            
            # 如果提供了内容，写入文件
            if content is not None:
                if isinstance(content, str):
                    self.write_file(temp_path, content)
                else:
                    self.write_bytes(temp_path, content)
            
            self.logger.debug(f"临时文件创建成功: {temp_path}")
            return temp_path
            
        except Exception as e:
            raise FileUtilsError(f"创建临时文件失败") from e
    
    def cleanup_temp_files(
        self,
        dir_path: Optional[Union[str, Path]] = None,
        older_than: int = 3600,
        pattern: str = 'file_utils_*.tmp'
    ) -> int:
        """
        清理临时文件
        
        Args:
            dir_path: 要清理的目录，默认None（使用系统临时目录）
            older_than: 删除多少秒前的文件，默认3600（1小时）
            pattern: 文件匹配模式，默认'file_utils_*.tmp'
            
        Returns:
            删除的文件数量
        """
        if dir_path is None:
            dir_path = Path(tempfile.gettempdir())
        else:
            dir_path = Path(dir_path)
        
        if not dir_path.exists():
            return 0
        
        deleted_count = 0
        cutoff_time = time.time() - older_than
        
        try:
            # 查找匹配的临时文件
            for file_path in dir_path.glob(pattern):
                if file_path.is_file():
                    try:
                        # 检查文件修改时间
                        file_mtime = file_path.stat().st_mtime
                        if file_mtime < cutoff_time:
                            file_path.unlink()
                            deleted_count += 1
                            self.logger.debug(f"临时文件已删除: {file_path}")
                    except Exception as e:
                        self.logger.warning(f"删除临时文件失败 {file_path}: {e}")
            
            if deleted_count > 0:
                self.logger.info(f"清理了 {deleted_count} 个临时文件")
            
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"清理临时文件失败: {e}")
            return deleted_count
    
    # ==================== 文件搜索 ====================
    
    def search_in_files(
        self,
        dir_path: Union[str, Path],
        pattern: Union[str, re.Pattern],
        file_pattern: str = '*.txt',
        recursive: bool = True,
        case_sensitive: bool = False,
        encoding: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        在文件中搜索文本模式
        
        Args:
            dir_path: 搜索目录
            pattern: 搜索模式（字符串或正则表达式）
            file_pattern: 文件匹配模式（glob），默认'*.txt'
            recursive: 是否递归搜索子目录，默认True
            case_sensitive: 是否区分大小写，默认False
            encoding: 文件编码，默认None（自动检测）
            
        Returns:
            搜索结果列表，每个结果包含：
            - file: 文件路径
            - line: 行号
            - content: 匹配的行内容
            - match: 匹配的文本
        """
        dir_path = Path(dir_path)
        
        if not dir_path.exists():
            raise FileUtilsError(f"搜索目录不存在: {dir_path}")
        
        if not dir_path.is_dir():
            raise FileUtilsError(f"路径不是目录: {dir_path}")
        
        # 编译正则表达式
        if isinstance(pattern, str):
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
        else:
            regex = pattern
        
        results = []
        
        try:
            # 查找匹配的文件
            if recursive:
                files = list(dir_path.rglob(file_pattern))
            else:
                files = list(dir_path.glob(file_pattern))
            
            # 只处理文件
            files = [f for f in files if f.is_file()]
            
            self.logger.debug(f"在 {len(files)} 个文件中搜索模式: {pattern}")
            
            # 搜索每个文件
            for file_path in files:
                try:
                    # 读取文件内容
                    if encoding:
                        content = self.read_file(file_path, encoding=encoding, auto_detect_encoding=False)
                    else:
                        content = self.read_file(file_path, auto_detect_encoding=True)
                    
                    # 按行搜索
                    for line_num, line in enumerate(content.splitlines(), 1):
                        matches = regex.finditer(line)
                        for match in matches:
                            results.append({
                                'file': str(file_path),
                                'line': line_num,
                                'content': line.strip(),
                                'match': match.group(),
                                'start': match.start(),
                                'end': match.end()
                            })
                
                except Exception as e:
                    self.logger.warning(f"搜索文件失败 {file_path}: {e}")
                    continue
            
            self.logger.debug(f"搜索完成，找到 {len(results)} 个匹配项")
            return results
            
        except Exception as e:
            raise FileUtilsError(f"文件搜索失败: {dir_path}") from e
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        # 清理资源（如果需要）
        return False


# 便捷函数（模块级）
_file_utils_instance = None
_file_utils_lock = threading.Lock()


def get_file_utils() -> FileUtils:
    """
    获取全局文件工具实例（单例模式）
    
    Returns:
        FileUtils实例
    """
    global _file_utils_instance
    
    with _file_utils_lock:
        if _file_utils_instance is None:
            _file_utils_instance = FileUtils()
        return _file_utils_instance


# 便捷函数
def read_file(file_path: Union[str, Path], encoding: Optional[str] = None) -> str:
    """读取文本文件的便捷函数"""
    return get_file_utils().read_file(file_path, encoding)


def write_file(file_path: Union[str, Path], content: str, encoding: Optional[str] = None):
    """写入文本文件的便捷函数"""
    get_file_utils().write_file(file_path, content, encoding)


def read_bytes(file_path: Union[str, Path]) -> bytes:
    """读取二进制文件的便捷函数"""
    return get_file_utils().read_bytes(file_path)


def write_bytes(file_path: Union[str, Path], data: bytes):
    """写入二进制文件的便捷函数"""
    get_file_utils().write_bytes(file_path, data)


def read_json(
    file_path: Union[str, Path],
    encoding: str = 'utf-8',
    default: Optional[Union[Dict, List]] = None
) -> Union[Dict, List]:
    """读取JSON文件的便捷函数"""
    return get_file_utils().read_json(file_path, encoding, default)


def write_json(
    file_path: Union[str, Path],
    data: Union[Dict, List],
    encoding: str = 'utf-8',
    indent: int = 2,
    ensure_ascii: bool = False
):
    """写入JSON文件的便捷函数"""
    get_file_utils().write_json(file_path, data, encoding, indent, ensure_ascii)

