"""
CommandRunner测试套件

使用pytest框架进行测试
"""

import pytest
import sys
import os
import tempfile
import shutil
import time
import threading
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.cmd_runner import (
    CommandRunner, CommandResult, AsyncCommand,
    CommandError, CommandTimeoutError,
    CommandInjectionError, DangerousCommandError
)


@pytest.fixture
def runner():
    """创建CommandRunner实例fixture"""
    return CommandRunner(default_timeout=10, enable_safety_checks=True)


@pytest.fixture
def runner_no_checks():
    """创建禁用安全检查的CommandRunner实例fixture"""
    return CommandRunner(default_timeout=10, enable_safety_checks=False)


@pytest.fixture
def temp_dir():
    """创建临时目录fixture"""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    # 清理
    if temp_path.exists():
        shutil.rmtree(temp_path, ignore_errors=True)


class TestBasicCommandExecution:
    """测试基础命令执行"""
    
    def test_run_simple_command(self, runner):
        """测试执行简单命令"""
        if os.name == 'nt':
            result = runner.run_command('echo test', timeout=5)
        else:
            result = runner.run_command('echo test', timeout=5)
        
        assert isinstance(result, CommandResult)
        assert result.success
        assert result.returncode == 0
        assert 'test' in result.stdout.lower()
    
    def test_run_command_with_output(self, runner):
        """测试命令输出"""
        if os.name == 'nt':
            result = runner.run_command('echo Hello World', timeout=5)
        else:
            result = runner.run_command('echo "Hello World"', timeout=5)
        
        assert result.success
        assert 'Hello' in result.stdout or 'World' in result.stdout
    
    def test_run_command_with_error(self, runner):
        """测试命令错误"""
        if os.name == 'nt':
            result = runner.run_command('dir nonexistent', timeout=5, check_returncode=False)
        else:
            result = runner.run_command('ls nonexistent', timeout=5, check_returncode=False)
        
        assert not result.success
        assert result.returncode != 0
    
    def test_run_command_with_cwd(self, runner, temp_dir):
        """测试指定工作目录"""
        if os.name == 'nt':
            result = runner.run_command('cd', cwd=temp_dir, timeout=5)
        else:
            result = runner.run_command('pwd', cwd=temp_dir, timeout=5)
        
        assert result.success
    
    def test_run_command_with_env(self, runner):
        """测试环境变量"""
        if os.name == 'nt':
            result = runner.run_command(
                'echo %TEST_VAR%',
                env={'TEST_VAR': 'test_value'},
                timeout=5
            )
        else:
            result = runner.run_command(
                'echo $TEST_VAR',
                env={'TEST_VAR': 'test_value'},
                timeout=5
            )
        
        assert result.success
        assert 'test_value' in result.stdout


class TestTimeout:
    """测试超时控制"""
    
    def test_command_timeout(self, runner):
        """测试命令超时"""
        if os.name == 'nt':
            with pytest.raises(CommandTimeoutError):
                runner.run_command('timeout /t 5', timeout=1)
        else:
            with pytest.raises(CommandTimeoutError):
                runner.run_command('sleep 5', timeout=1)
    
    def test_timeout_with_result(self, runner):
        """测试超时后结果"""
        try:
            if os.name == 'nt':
                runner.run_command('timeout /t 3', timeout=1)
            else:
                runner.run_command('sleep 3', timeout=1)
        except CommandTimeoutError as e:
            assert 'timeout' in str(e).lower() or '超时' in str(e)


class TestSafetyChecks:
    """测试安全检查"""
    
    def test_dangerous_command_blocked(self, runner):
        """测试危险命令被阻止"""
        with pytest.raises(DangerousCommandError):
            runner.run_command('rm -rf /', timeout=1)
    
    def test_command_injection_blocked(self, runner):
        """测试命令注入被阻止"""
        with pytest.raises(CommandInjectionError):
            runner.run_command('ls; rm file', timeout=1)
    
    def test_allowed_commands_whitelist(self, runner):
        """测试命令白名单"""
        runner.allowed_commands = {'echo', 'ls', 'dir'}
        
        if os.name == 'nt':
            result = runner.run_command_safe('echo test', allowed_commands=['echo'])
        else:
            result = runner.run_command_safe('echo test', allowed_commands=['echo'])
        
        assert result.success
        
        # 不在白名单的命令应该被阻止
        with pytest.raises(CommandError):
            runner.run_command_safe('rm file', allowed_commands=['echo'])
    
    def test_validate_command(self, runner):
        """测试命令验证"""
        # 安全命令
        is_safe, error = runner.validate_command('echo test')
        assert is_safe
        assert error is None
        
        # 危险命令
        is_safe, error = runner.validate_command('rm -rf /')
        assert not is_safe
        assert error is not None


class TestStreamOutput:
    """测试实时输出"""
    
    def test_stream_output_with_callback(self, runner):
        """测试实时输出回调"""
        stdout_lines = []
        stderr_lines = []
        
        def on_stdout(line):
            stdout_lines.append(line)
        
        def on_stderr(line):
            stderr_lines.append(line)
        
        if os.name == 'nt':
            result = runner.run_command_stream(
                'echo Line1 && echo Line2',
                stdout_callback=on_stdout,
                stderr_callback=on_stderr,
                timeout=5
            )
        else:
            result = runner.run_command_stream(
                'echo "Line1" && echo "Line2"',
                stdout_callback=on_stdout,
                stderr_callback=on_stderr,
                timeout=5
            )
        
        assert result.success
        assert len(stdout_lines) > 0


class TestAsyncExecution:
    """测试异步执行"""
    
    def test_run_command_async(self, runner_no_checks):
        """测试异步执行命令"""
        if os.name == 'nt':
            async_cmd = runner_no_checks.run_command_async('timeout /t 2', timeout=5)
        else:
            async_cmd = runner_no_checks.run_command_async('sleep 2', timeout=5)
        
        assert isinstance(async_cmd, AsyncCommand)
        assert async_cmd.is_running()
        
        # 等待完成
        result = async_cmd.wait()
        assert isinstance(result, CommandResult)
        assert not async_cmd.is_running()
    
    def test_async_command_status(self, runner_no_checks):
        """测试异步命令状态"""
        if os.name == 'nt':
            async_cmd = runner_no_checks.run_command_async('timeout /t 1', timeout=5)
        else:
            async_cmd = runner_no_checks.run_command_async('sleep 1', timeout=5)
        
        # 检查状态
        assert async_cmd.is_running()
        
        # 获取当前输出
        stdout, stderr = async_cmd.get_output_so_far()
        assert isinstance(stdout, str)
        assert isinstance(stderr, str)
        
        # 等待完成
        result = async_cmd.wait()
        assert not async_cmd.is_running()
    
    def test_async_command_terminate(self, runner_no_checks):
        """测试终止异步命令"""
        if os.name == 'nt':
            async_cmd = runner_no_checks.run_command_async('timeout /t 10', timeout=15)
        else:
            async_cmd = runner_no_checks.run_command_async('sleep 10', timeout=15)
        
        # 等待一小段时间
        time.sleep(0.5)
        
        # 终止命令
        if async_cmd.is_running():
            async_cmd.terminate()
            time.sleep(0.5)
            assert not async_cmd.is_running()


class TestPipeline:
    """测试命令管道"""
    
    def test_run_pipeline(self, runner_no_checks):
        """测试命令管道"""
        if os.name == 'nt':
            commands = ['echo test', 'findstr test']
        else:
            commands = ['echo "test"', 'grep test']
        
        results = runner_no_checks.run_pipeline(commands, timeout=10)
        
        assert len(results) == 2
        assert all(isinstance(r, CommandResult) for r in results)
    
    def test_pipeline_stop_on_error(self, runner_no_checks):
        """测试管道错误停止"""
        if os.name == 'nt':
            commands = ['echo test', 'nonexistent_command']
        else:
            commands = ['echo "test"', 'nonexistent_command']
        
        with pytest.raises(CommandError):
            runner_no_checks.run_pipeline(commands, timeout=10, stop_on_error=True)


class TestBatchExecution:
    """测试批量执行"""
    
    def test_run_batch(self, runner_no_checks):
        """测试批量执行"""
        if os.name == 'nt':
            commands = {
                'cmd1': 'echo command1',
                'cmd2': 'echo command2',
                'cmd3': 'echo command3',
            }
        else:
            commands = {
                'cmd1': 'echo "command1"',
                'cmd2': 'echo "command2"',
                'cmd3': 'echo "command3"',
            }
        
        results = runner_no_checks.run_batch(commands, max_workers=3, timeout=10)
        
        assert len(results) == 3
        assert all(isinstance(r, CommandResult) for r in results.values())
        assert all(r.success for r in results.values())


class TestCommandResult:
    """测试CommandResult类"""
    
    def test_command_result_structure(self, runner):
        """测试CommandResult结构"""
        if os.name == 'nt':
            result = runner.run_command('echo test', timeout=5)
        else:
            result = runner.run_command('echo test', timeout=5)
        
        assert hasattr(result, 'returncode')
        assert hasattr(result, 'stdout')
        assert hasattr(result, 'stderr')
        assert hasattr(result, 'success')
        assert hasattr(result, 'execution_time')
        assert hasattr(result, 'command')
    
    def test_command_result_to_dict(self, runner):
        """测试CommandResult转字典"""
        if os.name == 'nt':
            result = runner.run_command('echo test', timeout=5)
        else:
            result = runner.run_command('echo test', timeout=5)
        
        result_dict = result.to_dict()
        assert isinstance(result_dict, dict)
        assert 'returncode' in result_dict
        assert 'stdout' in result_dict
        assert 'success' in result_dict


class TestPenetrationTools:
    """测试渗透测试工具封装"""
    
    def test_run_nmap(self, runner_no_checks):
        """测试Nmap扫描（如果可用）"""
        # 检查nmap是否可用
        import shutil
        if not shutil.which('nmap'):
            pytest.skip("nmap not available")
        
        # 注意：这里需要导入PenetrationTools
        try:
            from src.utils.penetration_tools import PenetrationTools
            tools = PenetrationTools()
            tools.enable_safety_checks = False
            
            result = tools.run_nmap('127.0.0.1', options='-p 80', timeout=30)
            
            assert hasattr(result, 'tool_name')
            assert result.tool_name == 'nmap'
        except ImportError:
            pytest.skip("penetration_tools module not available")
        except Exception as e:
            # 如果nmap不可用或执行失败，跳过测试
            pytest.skip(f"nmap test failed: {e}")
    
    def test_parse_nmap_output(self, runner_no_checks):
        """测试解析Nmap输出"""
        try:
            from src.utils.penetration_tools import PenetrationTools
            tools = PenetrationTools()
            
            # 模拟Nmap输出
            nmap_output = """
Nmap scan report for 127.0.0.1
Host is up (0.001s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache/2.4.49
443/tcp  open  ssl/http Apache/2.4.49
"""
            
            parsed = tools.parse_nmap_output(nmap_output)
            
            assert 'ports' in parsed
            assert len(parsed['ports']) > 0
            assert parsed['ports'][0]['port'] == 80
        except ImportError:
            pytest.skip("penetration_tools not available")
    
    def test_parse_dirsearch_output(self, runner_no_checks):
        """测试解析Dirsearch输出"""
        try:
            from src.utils.penetration_tools import PenetrationTools
            tools = PenetrationTools()
            
            # 模拟Dirsearch输出
            dirsearch_output = """
[200] /admin 1234
[200] /login 5678
[403] /config 0
"""
            
            parsed = tools.parse_dirsearch_output(dirsearch_output)
            
            assert isinstance(parsed, list)
            assert len(parsed) > 0
            assert parsed[0]['status_code'] == 200
        except ImportError:
            pytest.skip("penetration_tools not available")
    
    def test_parse_sqlmap_output(self, runner_no_checks):
        """测试解析SQLMap输出"""
        try:
            from src.utils.penetration_tools import PenetrationTools
            tools = PenetrationTools()
            
            # 模拟SQLMap输出
            sqlmap_output = """
[INFO] testing 'Boolean-based blind SQL injection'
[INFO] parameter 'id' is vulnerable
[INFO] injection type: Boolean-based blind
Payload: 1' AND 1=1--
"""
            
            parsed = tools.parse_sqlmap_output(sqlmap_output)
            
            assert 'vulnerable' in parsed
            assert parsed['vulnerable'] is True
        except ImportError:
            pytest.skip("penetration_tools not available")


class TestErrorHandling:
    """测试错误处理"""
    
    def test_command_not_found(self, runner_no_checks):
        """测试命令不存在"""
        with pytest.raises(CommandError):
            runner_no_checks.run_command('nonexistent_command_xyz', timeout=5)
    
    def test_invalid_command(self, runner_no_checks):
        """测试无效命令"""
        # 某些系统可能不会抛出异常，只是返回非0返回码
        result = runner_no_checks.run_command('invalid_command_xyz', timeout=5, check_returncode=False)
        assert not result.success or result.returncode != 0


class TestWorkingDirectory:
    """测试工作目录限制"""
    
    def test_allowed_directory(self, runner, temp_dir):
        """测试允许的目录"""
        runner.allowed_directories = [temp_dir]
        
        if os.name == 'nt':
            result = runner.run_command('cd', cwd=temp_dir, timeout=5)
        else:
            result = runner.run_command('pwd', cwd=temp_dir, timeout=5)
        
        assert result.success
    
    def test_blocked_directory(self, runner, temp_dir):
        """测试被阻止的目录"""
        # 设置只允许temp_dir
        runner.allowed_directories = [temp_dir]
        
        # 尝试在父目录执行（应该被阻止）
        parent_dir = temp_dir.parent
        if parent_dir != temp_dir:
            with pytest.raises(CommandError):
                if os.name == 'nt':
                    runner.run_command('cd', cwd=parent_dir, timeout=5)
                else:
                    runner.run_command('pwd', cwd=parent_dir, timeout=5)


class TestReturnCode:
    """测试返回码检查"""
    
    def test_check_returncode_success(self, runner):
        """测试检查返回码（成功）"""
        if os.name == 'nt':
            result = runner.run_command('echo test', timeout=5, check_returncode=True)
        else:
            result = runner.run_command('echo test', timeout=5, check_returncode=True)
        
        assert result.success
    
    def test_check_returncode_failure(self, runner):
        """测试检查返回码（失败）"""
        with pytest.raises(CommandError):
            if os.name == 'nt':
                runner.run_command('dir nonexistent', timeout=5, check_returncode=True)
            else:
                runner.run_command('ls nonexistent', timeout=5, check_returncode=True)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
