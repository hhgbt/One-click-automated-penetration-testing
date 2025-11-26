"""
命令执行工具模块

功能特性：
1. 同步执行命令并获取结果
2. 实时捕获stdout和stderr
3. 超时控制（默认30秒）
4. 返回码检查
5. 环境变量支持
6. 命令注入防护
7. 危险命令黑名单
8. 工作目录限制
9. 内存使用限制

使用示例：
    from src.utils.cmd_runner import CommandRunner, CommandResult
    
    runner = CommandRunner()
    result = runner.run_command('ls -la', timeout=10)
    print(result.stdout)
"""

import os
import re
import shlex
import subprocess
import threading
import time
import queue
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, List, Union, Tuple, Callable, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from dataclasses import dataclass, field

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from src.utils.logger import get_logger
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    get_logger = lambda name: logging.getLogger(name)


class CommandError(Exception):
    """命令执行异常基类"""
    pass


class CommandTimeoutError(CommandError):
    """命令执行超时异常"""
    pass


class CommandInjectionError(CommandError):
    """命令注入检测异常"""
    pass


class DangerousCommandError(CommandError):
    """危险命令检测异常"""
    pass


class PenetrationTestResult:
    """
    渗透测试结果标准化类
    
    提供统一的返回格式、错误分类和性能统计
    """
    
    def __init__(
        self,
        tool_name: str,
        command: str,
        success: bool,
        data: Any = None,
        error_type: Optional[str] = None,
        error_message: Optional[str] = None,
        execution_time: float = 0.0,
        raw_output: Optional[str] = None,
        raw_stderr: Optional[str] = None,
        returncode: int = 0
    ):
        """
        初始化渗透测试结果
        
        Args:
            tool_name: 工具名称
            command: 执行的命令
            success: 是否成功
            data: 解析后的数据
            error_type: 错误类型
            error_message: 错误消息
            execution_time: 执行时间（秒）
            raw_output: 原始输出
            raw_stderr: 原始错误输出
            returncode: 返回码
        """
        self.tool_name = tool_name
        self.command = command
        self.success = success
        self.data = data
        self.error_type = error_type
        self.error_message = error_message
        self.execution_time = execution_time
        self.raw_output = raw_output
        self.raw_stderr = raw_stderr
        self.returncode = returncode
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典
        
        Returns:
            结果字典
        """
        return {
            'tool_name': self.tool_name,
            'command': self.command,
            'success': self.success,
            'data': self.data,
            'error_type': self.error_type,
            'error_message': self.error_message,
            'execution_time': self.execution_time,
            'raw_output': self.raw_output,
            'raw_stderr': self.raw_stderr,
            'returncode': self.returncode,
            'timestamp': self.timestamp
        }
    
    def __repr__(self):
        status = "成功" if self.success else "失败"
        return (
            f"PenetrationTestResult({self.tool_name}, {status}, "
            f"time={self.execution_time:.2f}s)"
        )


class CommandResult:
    """
    命令执行结果数据类
    
    属性：
        returncode: 命令返回码
        stdout: 标准输出
        stderr: 标准错误输出
        success: 是否执行成功（returncode == 0）
        execution_time: 执行时间（秒）
        command: 执行的命令
    """
    
    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        execution_time: float,
        command: str
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.success = returncode == 0
        self.execution_time = execution_time
        self.command = command
    
    def to_dict(self) -> Dict[str, any]:
        """
        转换为字典
        
        Returns:
            结果字典
        """
        return {
            'returncode': self.returncode,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'success': self.success,
            'execution_time': self.execution_time,
            'command': self.command
        }
    
    def __repr__(self):
        return (
            f"CommandResult(returncode={self.returncode}, "
            f"success={self.success}, time={self.execution_time:.2f}s)"
        )


class AsyncCommand:
    """
    异步命令执行对象
    
    提供异步命令执行的状态查询和结果获取
    """
    
    def __init__(
        self,
        process: subprocess.Popen,
        command: str,
        encoding: str = 'utf-8'
    ):
        """
        初始化异步命令对象
        
        Args:
            process: 进程对象
            command: 执行的命令
            encoding: 输出编码
        """
        self.process = process
        self.command = command
        self.encoding = encoding
        self._lock = threading.Lock()
        self._stdout_lines = []
        self._stderr_lines = []
        self._result = None
        self._exception = None
        self._start_time = time.time()
        
        # 启动输出捕获线程
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            daemon=True
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            daemon=True
        )
        
        self._stdout_thread.start()
        self._stderr_thread.start()
        
        # 启动等待线程
        self._wait_thread = threading.Thread(
            target=self._wait_process,
            daemon=True
        )
        self._wait_thread.start()
    
    def _read_stdout(self):
        """读取标准输出"""
        try:
            for line in iter(self.process.stdout.readline, b''):
                if not line:
                    break
                decoded_line = line.decode(self.encoding, errors='replace').rstrip('\n\r')
                with self._lock:
                    self._stdout_lines.append(decoded_line)
        except Exception as e:
            with self._lock:
                self._exception = e
        finally:
            if self.process.stdout:
                self.process.stdout.close()
    
    def _read_stderr(self):
        """读取标准错误输出"""
        try:
            for line in iter(self.process.stderr.readline, b''):
                if not line:
                    break
                decoded_line = line.decode(self.encoding, errors='replace').rstrip('\n\r')
                with self._lock:
                    self._stderr_lines.append(decoded_line)
        except Exception as e:
            with self._lock:
                self._exception = e
        finally:
            if self.process.stderr:
                self.process.stderr.close()
    
    def _wait_process(self):
        """等待进程完成"""
        try:
            returncode = self.process.wait()
            execution_time = time.time() - self._start_time
            
            # 等待输出线程完成
            self._stdout_thread.join(timeout=1.0)
            self._stderr_thread.join(timeout=1.0)
            
            with self._lock:
                stdout = '\n'.join(self._stdout_lines)
                stderr = '\n'.join(self._stderr_lines)
                
                self._result = CommandResult(
                    returncode=returncode,
                    stdout=stdout,
                    stderr=stderr,
                    execution_time=execution_time,
                    command=self.command
                )
        except Exception as e:
            with self._lock:
                self._exception = e
    
    def is_running(self) -> bool:
        """
        检查命令是否正在运行
        
        Returns:
            如果正在运行返回True，否则返回False
        """
        with self._lock:
            if self._result is not None or self._exception is not None:
                return False
        
        return self.process.poll() is None
    
    def wait(self, timeout: Optional[float] = None) -> CommandResult:
        """
        等待命令执行完成
        
        Args:
            timeout: 超时时间（秒），默认None（无限等待）
            
        Returns:
            CommandResult对象
            
        Raises:
            CommandTimeoutError: 等待超时
            CommandError: 命令执行失败
        """
        if timeout:
            self._wait_thread.join(timeout=timeout)
            if self._wait_thread.is_alive():
                raise CommandTimeoutError(f"等待命令完成超时: {self.command[:100]}")
        else:
            self._wait_thread.join()
        
        with self._lock:
            if self._exception:
                raise CommandError(f"命令执行失败: {self.command[:100]}") from self._exception
            
            if self._result is None:
                raise CommandError(f"命令结果未就绪: {self.command[:100]}")
            
            return self._result
    
    def terminate(self):
        """终止命令执行"""
        try:
            if self.process.poll() is None:
                self.process.terminate()
                # 等待进程终止
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
        except Exception:
            pass  # 忽略终止错误
    
    def get_output_so_far(self) -> Tuple[str, str]:
        """
        获取当前已捕获的输出
        
        Returns:
            (stdout, stderr) 元组
        """
        with self._lock:
            stdout = '\n'.join(self._stdout_lines)
            stderr = '\n'.join(self._stderr_lines)
            return stdout, stderr


class CommandRunner:
    """
    命令执行工具类
    
    提供安全的命令执行功能，包括命令注入防护、危险命令检测等
    """
    
    # 危险命令黑名单
    DANGEROUS_COMMANDS = {
        'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd',
        'shutdown', 'reboot', 'halt', 'poweroff',
        'sudo', 'su', 'chmod', 'chown',
        'wget', 'curl',  # 可以下载恶意文件
        'nc', 'netcat', 'ncat',  # 网络工具
        'python', 'python3', 'perl', 'ruby',  # 脚本执行
        'bash', 'sh', 'zsh', 'csh',  # Shell执行
        'eval', 'exec', 'system',
    }
    
    # 危险字符模式
    DANGEROUS_PATTERNS = [
        r'[;&|`$(){}]',  # 命令分隔符和特殊字符
        r'<|>',  # 重定向
        r'\$\{',  # 变量展开
        r'`.*`',  # 命令替换
        r'\$\(.*\)',  # 命令替换
    ]
    
    def __init__(
        self,
        default_timeout: int = 30,
        max_memory_mb: int = 512,
        allowed_commands: Optional[List[str]] = None,
        blocked_commands: Optional[List[str]] = None,
        allowed_directories: Optional[List[str]] = None,
        enable_safety_checks: bool = True
    ):
        """
        初始化命令执行工具
        
        Args:
            default_timeout: 默认超时时间（秒），默认30
            max_memory_mb: 最大内存使用限制（MB），默认512
            allowed_commands: 允许的命令白名单，默认None（不限制）
            blocked_commands: 阻止的命令黑名单，默认None（使用默认黑名单）
            allowed_directories: 允许的工作目录列表，默认None（不限制）
            enable_safety_checks: 是否启用安全检查，默认True
        """
        self.default_timeout = default_timeout
        self.max_memory_mb = max_memory_mb
        self.allowed_commands = set(allowed_commands) if allowed_commands else None
        self.blocked_commands = set(blocked_commands) if blocked_commands else set(self.DANGEROUS_COMMANDS)
        self.allowed_directories = [Path(d) for d in allowed_directories] if allowed_directories else None
        self.enable_safety_checks = enable_safety_checks
        self.logger = get_logger(__name__)
    
    def _check_command_injection(self, command: str) -> bool:
        """
        检查命令是否包含注入攻击
        
        Args:
            command: 命令字符串
            
        Returns:
            如果检测到注入攻击返回True，否则返回False
        """
        if not self.enable_safety_checks:
            return False
        
        # 检查危险字符模式
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command):
                self.logger.warning(f"检测到命令注入模式: {pattern} in {command[:50]}")
                return True
        
        return False
    
    def _check_dangerous_command(self, command: str) -> bool:
        """
        检查命令是否在危险命令列表中
        
        Args:
            command: 命令字符串
            
        Returns:
            如果检测到危险命令返回True，否则返回False
        """
        if not self.enable_safety_checks:
            return False
        
        # 解析命令（简单解析，获取第一个词）
        parts = shlex.split(command, posix=False) if command else []
        if not parts:
            return False
        
        cmd_name = parts[0].lower()
        
        # 检查黑名单
        if cmd_name in self.blocked_commands:
            self.logger.warning(f"检测到危险命令: {cmd_name}")
            return True
        
        # 检查白名单（如果设置了）
        if self.allowed_commands is not None:
            if cmd_name not in self.allowed_commands:
                self.logger.warning(f"命令不在白名单中: {cmd_name}")
                return True
        
        return False
    
    def _check_working_directory(self, cwd: Optional[Union[str, Path]]) -> bool:
        """
        检查工作目录是否在允许列表中
        
        Args:
            cwd: 工作目录路径
            
        Returns:
            如果目录不在允许列表中返回True，否则返回False
        """
        if not self.enable_safety_checks or not self.allowed_directories:
            return False
        
        if cwd is None:
            return False
        
        cwd_path = Path(cwd).resolve()
        
        # 检查是否在允许的目录中
        for allowed_dir in self.allowed_directories:
            allowed_dir = allowed_dir.resolve()
            try:
                # 检查cwd是否是allowed_dir的子目录
                cwd_path.relative_to(allowed_dir)
                return False  # 在允许目录中
            except ValueError:
                continue
        
        self.logger.warning(f"工作目录不在允许列表中: {cwd_path}")
        return True
    
    def _monitor_memory(self, process: subprocess.Popen, timeout: float) -> Optional[float]:
        """
        监控进程内存使用
        
        Args:
            process: 进程对象
            timeout: 超时时间
            
        Returns:
            如果超过内存限制返回内存使用量（MB），否则返回None
        """
        if not HAS_PSUTIL:
            # 如果没有psutil，跳过内存监控
            return None
        
        max_memory_bytes = self.max_memory_mb * 1024 * 1024
        start_time = time.time()
        
        while process.poll() is None:
            if time.time() - start_time > timeout:
                break
            
            try:
                # 获取进程内存使用
                proc = psutil.Process(process.pid)
                memory_info = proc.memory_info()
                memory_mb = memory_info.rss / 1024 / 1024
                
                if memory_info.rss > max_memory_bytes:
                    self.logger.warning(
                        f"进程内存使用超过限制: {memory_mb:.2f}MB > {self.max_memory_mb}MB"
                    )
                    # 尝试终止进程
                    try:
                        process.kill()
                    except:
                        pass
                    return memory_mb
                
                time.sleep(0.1)  # 每100ms检查一次
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        
        return None
    
    def _read_output_stream(
        self,
        stream,
        output_list: List[str],
        encoding: str = 'utf-8'
    ):
        """
        读取输出流（用于实时捕获）
        
        Args:
            stream: 输出流
            output_list: 输出列表（用于存储）
            encoding: 编码，默认'utf-8'
        """
        try:
            for line in iter(stream.readline, ''):
                if not line:
                    break
                decoded_line = line.decode(encoding, errors='replace').rstrip('\n\r')
                output_list.append(decoded_line)
        except Exception as e:
            self.logger.warning(f"读取输出流失败: {e}")
        finally:
            stream.close()
    
    def run_command(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = True,
        encoding: str = 'utf-8',
        check_returncode: bool = False
    ) -> CommandResult:
        """
        执行命令并获取结果
        
        Args:
            cmd: 命令（字符串或列表）
            timeout: 超时时间（秒），默认使用default_timeout
            cwd: 工作目录，默认None（当前目录）
            env: 环境变量字典，默认None
            shell: 是否使用shell执行，默认True
            encoding: 输出编码，默认'utf-8'
            check_returncode: 是否检查返回码（非0时抛出异常），默认False
            
        Returns:
            CommandResult对象
            
        Raises:
            CommandInjectionError: 检测到命令注入
            DangerousCommandError: 检测到危险命令
            CommandTimeoutError: 命令执行超时
            CommandError: 其他命令执行错误
        """
        timeout = timeout or self.default_timeout
        start_time = time.time()
        
        # 安全检查
        if isinstance(cmd, str):
            cmd_str = cmd
        else:
            cmd_str = ' '.join(cmd)
        
        # 检查命令注入
        if self._check_command_injection(cmd_str):
            raise CommandInjectionError(f"检测到命令注入攻击: {cmd_str[:100]}")
        
        # 检查危险命令
        if self._check_dangerous_command(cmd_str):
            raise DangerousCommandError(f"检测到危险命令: {cmd_str[:100]}")
        
        # 检查工作目录
        if self._check_working_directory(cwd):
            raise CommandError(f"工作目录不在允许列表中: {cwd}")
        
        # 准备环境变量
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        # 准备命令
        if isinstance(cmd, str):
            if shell:
                cmd_to_run = cmd
            else:
                cmd_to_run = shlex.split(cmd, posix=False)
        else:
            cmd_to_run = cmd
            shell = False
        
        self.logger.debug(f"执行命令: {cmd_str} (超时: {timeout}秒)")
        
        try:
            # 启动进程
            process = subprocess.Popen(
                cmd_to_run,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=process_env,
                shell=shell,
                bufsize=1  # 行缓冲
            )
            
            # 实时捕获输出
            stdout_lines = []
            stderr_lines = []
            
            stdout_thread = threading.Thread(
                target=self._read_output_stream,
                args=(process.stdout, stdout_lines, encoding),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=self._read_output_stream,
                args=(process.stderr, stderr_lines, encoding),
                daemon=True
            )
            
            stdout_thread.start()
            stderr_thread.start()
            
            # 启动内存监控（如果启用）
            memory_thread = None
            if self.enable_safety_checks:
                memory_thread = threading.Thread(
                    target=self._monitor_memory,
                    args=(process, timeout),
                    daemon=True
                )
                memory_thread.start()
            
            # 等待进程完成或超时
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # 超时，终止进程
                process.kill()
                process.wait()
                execution_time = time.time() - start_time
                raise CommandTimeoutError(
                    f"命令执行超时 ({timeout}秒): {cmd_str[:100]}"
                )
            
            # 等待输出线程完成
            stdout_thread.join(timeout=1.0)
            stderr_thread.join(timeout=1.0)
            
            execution_time = time.time() - start_time
            
            # 构建结果
            stdout = '\n'.join(stdout_lines)
            stderr = '\n'.join(stderr_lines)
            
            result = CommandResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                command=cmd_str
            )
            
            # 检查返回码
            if check_returncode and returncode != 0:
                raise CommandError(
                    f"命令执行失败 (返回码: {returncode}): {cmd_str[:100]}\n"
                    f"stderr: {stderr[:200]}"
                )
            
            self.logger.debug(
                f"命令执行完成: {cmd_str[:50]} "
                f"(返回码: {returncode}, 耗时: {execution_time:.2f}秒)"
            )
            
            return result
            
        except CommandTimeoutError:
            raise
        except CommandInjectionError:
            raise
        except DangerousCommandError:
            raise
        except Exception as e:
            execution_time = time.time() - start_time
            raise CommandError(f"命令执行失败: {cmd_str[:100]}") from e
    
    def run_command_safe(
        self,
        cmd: Union[str, List[str]],
        allowed_commands: Optional[List[str]] = None,
        **kwargs
    ) -> CommandResult:
        """
        安全执行命令（使用白名单）
        
        Args:
            cmd: 命令（字符串或列表）
            allowed_commands: 允许的命令白名单，默认None（使用实例的白名单）
            **kwargs: 其他参数，传递给run_command
            
        Returns:
            CommandResult对象
            
        Raises:
            CommandError: 命令不在白名单中或执行失败
        """
        # 解析命令
        if isinstance(cmd, str):
            parts = shlex.split(cmd, posix=False)
        else:
            parts = cmd
        
        if not parts:
            raise CommandError("命令为空")
        
        cmd_name = parts[0].lower()
        
        # 检查白名单
        check_list = allowed_commands or self.allowed_commands
        if check_list and cmd_name not in check_list:
            raise CommandError(f"命令不在白名单中: {cmd_name}")
        
        # 执行命令（强制启用安全检查）
        original_checks = self.enable_safety_checks
        self.enable_safety_checks = True
        
        try:
            return self.run_command(cmd, **kwargs)
        finally:
            self.enable_safety_checks = original_checks
    
    def validate_command(self, cmd: Union[str, List[str]]) -> Tuple[bool, Optional[str]]:
        """
        验证命令是否安全
        
        Args:
            cmd: 命令（字符串或列表）
            
        Returns:
            (是否安全, 错误信息)
        """
        if isinstance(cmd, str):
            cmd_str = cmd
        else:
            cmd_str = ' '.join(cmd)
        
        # 检查命令注入
        if self._check_command_injection(cmd_str):
            return False, "检测到命令注入攻击"
        
        # 检查危险命令
        if self._check_dangerous_command(cmd_str):
            return False, "检测到危险命令"
        
        return True, None
    
    def run_command_stream(
        self,
        cmd: Union[str, List[str]],
        stdout_callback: Optional[Callable[[str], None]] = None,
        stderr_callback: Optional[Callable[[str], None]] = None,
        timeout: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = True,
        encoding: str = 'utf-8',
        check_returncode: bool = False
    ) -> CommandResult:
        """
        执行命令并实时输出（逐行回调）
        
        Args:
            cmd: 命令（字符串或列表）
            stdout_callback: 标准输出回调函数，接收每行输出
            stderr_callback: 标准错误输出回调函数，接收每行输出
            timeout: 超时时间（秒），默认使用default_timeout
            cwd: 工作目录，默认None
            env: 环境变量字典，默认None
            shell: 是否使用shell执行，默认True
            encoding: 输出编码，默认'utf-8'
            check_returncode: 是否检查返回码，默认False
            
        Returns:
            CommandResult对象
            
        Raises:
            CommandError: 命令执行失败
        """
        timeout = timeout or self.default_timeout
        start_time = time.time()
        
        # 安全检查
        if isinstance(cmd, str):
            cmd_str = cmd
        else:
            cmd_str = ' '.join(cmd)
        
        # 检查命令注入
        if self._check_command_injection(cmd_str):
            raise CommandInjectionError(f"检测到命令注入攻击: {cmd_str[:100]}")
        
        # 检查危险命令
        if self._check_dangerous_command(cmd_str):
            raise DangerousCommandError(f"检测到危险命令: {cmd_str[:100]}")
        
        # 检查工作目录
        if self._check_working_directory(cwd):
            raise CommandError(f"工作目录不在允许列表中: {cwd}")
        
        # 准备环境变量
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        # 准备命令
        if isinstance(cmd, str):
            if shell:
                cmd_to_run = cmd
            else:
                cmd_to_run = shlex.split(cmd, posix=False)
        else:
            cmd_to_run = cmd
            shell = False
        
        self.logger.debug(f"执行命令（实时输出）: {cmd_str} (超时: {timeout}秒)")
        
        stdout_lines = []
        stderr_lines = []
        
        def read_stdout_with_callback(stream, lines_list):
            """读取标准输出并调用回调"""
            try:
                for line in iter(stream.readline, b''):
                    if not line:
                        break
                    decoded_line = line.decode(encoding, errors='replace').rstrip('\n\r')
                    lines_list.append(decoded_line)
                    if stdout_callback:
                        try:
                            stdout_callback(decoded_line)
                        except Exception as e:
                            self.logger.warning(f"stdout回调执行失败: {e}")
            except Exception as e:
                self.logger.warning(f"读取stdout失败: {e}")
            finally:
                stream.close()
        
        def read_stderr_with_callback(stream, lines_list):
            """读取标准错误输出并调用回调"""
            try:
                for line in iter(stream.readline, b''):
                    if not line:
                        break
                    decoded_line = line.decode(encoding, errors='replace').rstrip('\n\r')
                    lines_list.append(decoded_line)
                    if stderr_callback:
                        try:
                            stderr_callback(decoded_line)
                        except Exception as e:
                            self.logger.warning(f"stderr回调执行失败: {e}")
            except Exception as e:
                self.logger.warning(f"读取stderr失败: {e}")
            finally:
                stream.close()
        
        try:
            # 启动进程
            process = subprocess.Popen(
                cmd_to_run,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=process_env,
                shell=shell,
                bufsize=1  # 行缓冲
            )
            
            # 启动输出捕获线程
            stdout_thread = threading.Thread(
                target=read_stdout_with_callback,
                args=(process.stdout, stdout_lines),
                daemon=True
            )
            stderr_thread = threading.Thread(
                target=read_stderr_with_callback,
                args=(process.stderr, stderr_lines),
                daemon=True
            )
            
            stdout_thread.start()
            stderr_thread.start()
            
            # 等待进程完成或超时
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                execution_time = time.time() - start_time
                raise CommandTimeoutError(
                    f"命令执行超时 ({timeout}秒): {cmd_str[:100]}"
                )
            
            # 等待输出线程完成
            stdout_thread.join(timeout=1.0)
            stderr_thread.join(timeout=1.0)
            
            execution_time = time.time() - start_time
            
            # 构建结果
            stdout = '\n'.join(stdout_lines)
            stderr = '\n'.join(stderr_lines)
            
            result = CommandResult(
                returncode=returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                command=cmd_str
            )
            
            # 检查返回码
            if check_returncode and returncode != 0:
                raise CommandError(
                    f"命令执行失败 (返回码: {returncode}): {cmd_str[:100]}\n"
                    f"stderr: {stderr[:200]}"
                )
            
            return result
            
        except CommandTimeoutError:
            raise
        except Exception as e:
            execution_time = time.time() - start_time
            raise CommandError(f"命令执行失败: {cmd_str[:100]}") from e
    
    def run_command_async(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = True,
        encoding: str = 'utf-8'
    ) -> AsyncCommand:
        """
        异步执行命令
        
        Args:
            cmd: 命令（字符串或列表）
            timeout: 超时时间（秒），默认None（不限制）
            cwd: 工作目录，默认None
            env: 环境变量字典，默认None
            shell: 是否使用shell执行，默认True
            encoding: 输出编码，默认'utf-8'
            
        Returns:
            AsyncCommand对象
            
        Raises:
            CommandInjectionError: 检测到命令注入
            DangerousCommandError: 检测到危险命令
        """
        # 安全检查
        if isinstance(cmd, str):
            cmd_str = cmd
        else:
            cmd_str = ' '.join(cmd)
        
        # 检查命令注入
        if self._check_command_injection(cmd_str):
            raise CommandInjectionError(f"检测到命令注入攻击: {cmd_str[:100]}")
        
        # 检查危险命令
        if self._check_dangerous_command(cmd_str):
            raise DangerousCommandError(f"检测到危险命令: {cmd_str[:100]}")
        
        # 检查工作目录
        if self._check_working_directory(cwd):
            raise CommandError(f"工作目录不在允许列表中: {cwd}")
        
        # 准备环境变量
        process_env = os.environ.copy()
        if env:
            process_env.update(env)
        
        # 准备命令
        if isinstance(cmd, str):
            if shell:
                cmd_to_run = cmd
            else:
                cmd_to_run = shlex.split(cmd, posix=False)
        else:
            cmd_to_run = cmd
            shell = False
        
        self.logger.debug(f"异步执行命令: {cmd_str}")
        
        # 启动进程
        process = subprocess.Popen(
            cmd_to_run,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd) if cwd else None,
            env=process_env,
            shell=shell,
            bufsize=1  # 行缓冲
        )
        
        # 创建异步命令对象
        async_cmd = AsyncCommand(process, cmd_str, encoding)
        
        # 如果设置了超时，启动超时监控
        if timeout:
            def timeout_monitor():
                time.sleep(timeout)
                if async_cmd.is_running():
                    async_cmd.terminate()
                    with async_cmd._lock:
                        async_cmd._exception = CommandTimeoutError(
                            f"命令执行超时 ({timeout}秒): {cmd_str[:100]}"
                        )
            
            timeout_thread = threading.Thread(target=timeout_monitor, daemon=True)
            timeout_thread.start()
        
        return async_cmd
    
    def run_pipeline(
        self,
        commands: List[Union[str, List[str]]],
        timeout: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = True,
        encoding: str = 'utf-8',
        stop_on_error: bool = True
    ) -> List[CommandResult]:
        """
        执行命令管道（前一个命令的输出作为下一个命令的输入）
        
        Args:
            commands: 命令列表
            timeout: 每个命令的超时时间（秒），默认None
            cwd: 工作目录，默认None
            env: 环境变量字典，默认None
            shell: 是否使用shell执行，默认True
            encoding: 输出编码，默认'utf-8'
            stop_on_error: 遇到错误是否停止，默认True
            
        Returns:
            CommandResult列表
            
        Raises:
            CommandError: 命令执行失败
        """
        if not commands:
            return []
        
        results = []
        previous_output = None
        
        for i, cmd in enumerate(commands):
            try:
                # 准备输入
                input_data = previous_output.encode(encoding) if previous_output else None
                
                # 执行命令
                if isinstance(cmd, str):
                    cmd_str = cmd
                else:
                    cmd_str = ' '.join(cmd)
                
                # 安全检查
                if self._check_command_injection(cmd_str):
                    raise CommandInjectionError(f"检测到命令注入攻击: {cmd_str[:100]}")
                
                if self._check_dangerous_command(cmd_str):
                    raise DangerousCommandError(f"检测到危险命令: {cmd_str[:100]}")
                
                # 准备环境变量
                process_env = os.environ.copy()
                if env:
                    process_env.update(env)
                
                # 准备命令
                if isinstance(cmd, str):
                    if shell:
                        cmd_to_run = cmd
                    else:
                        cmd_to_run = shlex.split(cmd, posix=False)
                else:
                    cmd_to_run = cmd
                    shell = False
                
                start_time = time.time()
                
                # 启动进程
                process = subprocess.Popen(
                    cmd_to_run,
                    stdin=subprocess.PIPE if input_data else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=str(cwd) if cwd else None,
                    env=process_env,
                    shell=shell,
                    bufsize=1
                )
                
                # 写入输入
                if input_data:
                    process.stdin.write(input_data)
                    process.stdin.close()
                
                # 等待进程完成
                try:
                    returncode = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise CommandTimeoutError(
                        f"管道命令执行超时 ({timeout}秒): {cmd_str[:100]}"
                    )
                
                # 读取输出
                stdout, stderr = process.communicate()
                stdout_text = stdout.decode(encoding, errors='replace')
                stderr_text = stderr.decode(encoding, errors='replace')
                
                execution_time = time.time() - start_time
                
                result = CommandResult(
                    returncode=returncode,
                    stdout=stdout_text,
                    stderr=stderr_text,
                    execution_time=execution_time,
                    command=cmd_str
                )
                
                results.append(result)
                
                # 如果命令失败且需要停止
                if stop_on_error and returncode != 0:
                    raise CommandError(
                        f"管道命令执行失败 (返回码: {returncode}): {cmd_str[:100]}\n"
                        f"stderr: {stderr_text[:200]}"
                    )
                
                # 将输出作为下一个命令的输入
                previous_output = stdout_text
                
            except Exception as e:
                if stop_on_error:
                    raise CommandError(f"管道执行失败: {cmd_str[:100]}") from e
                else:
                    # 创建失败结果
                    result = CommandResult(
                        returncode=-1,
                        stdout='',
                        stderr=str(e),
                        execution_time=0,
                        command=cmd_str
                    )
                    results.append(result)
                    break
        
        return results
    
    def run_batch(
        self,
        commands: Dict[str, Union[str, List[str]]],
        max_workers: int = 5,
        timeout: Optional[int] = None,
        cwd: Optional[Union[str, Path]] = None,
        env: Optional[Dict[str, str]] = None,
        shell: bool = True,
        encoding: str = 'utf-8'
    ) -> Dict[str, CommandResult]:
        """
        批量执行命令（并发）
        
        Args:
            commands: 命令字典 {name: command}
            max_workers: 最大并发数，默认5
            timeout: 每个命令的超时时间（秒），默认None
            cwd: 工作目录，默认None
            env: 环境变量字典，默认None
            shell: 是否使用shell执行，默认True
            encoding: 输出编码，默认'utf-8'
            
        Returns:
            命令结果字典 {name: CommandResult}
        """
        results = {}
        
        def execute_single(name: str, cmd: Union[str, List[str]]) -> Tuple[str, CommandResult]:
            """执行单个命令"""
            try:
                result = self.run_command(
                    cmd,
                    timeout=timeout,
                    cwd=cwd,
                    env=env,
                    shell=shell,
                    encoding=encoding,
                    check_returncode=False
                )
                return name, result
            except Exception as e:
                # 创建错误结果
                error_result = CommandResult(
                    returncode=-1,
                    stdout='',
                    stderr=str(e),
                    execution_time=0,
                    command=str(cmd) if isinstance(cmd, str) else ' '.join(cmd)
                )
                return name, error_result
        
        # 使用线程池并发执行
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # 提交所有任务
            future_to_name = {
                executor.submit(execute_single, name, cmd): name
                for name, cmd in commands.items()
            }
            
            # 收集结果
            for future in as_completed(future_to_name):
                name, result = future.result()
                results[name] = result
        
        return results


# 便捷函数
def run_command(
    cmd: Union[str, List[str]],
    timeout: Optional[int] = None,
    **kwargs
) -> CommandResult:
    """
    执行命令的便捷函数
    
    Args:
        cmd: 命令
        timeout: 超时时间
        **kwargs: 其他参数
        
    Returns:
        CommandResult对象
    """
    runner = CommandRunner()
    return runner.run_command(cmd, timeout=timeout, **kwargs)

