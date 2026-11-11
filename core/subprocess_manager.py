"""
Secure Subprocess Management for Kibuo.

Ensures that external Linux security tools and commands are invoked using
secure argument arrays, explicit timeouts, proper permission handling,
and zero shell execution (shell=False).
"""

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class CommandResult:
    """Encapsulates the execution result of an external command."""
    command: str
    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    success: bool = False
    error_message: Optional[str] = None
    extra_metadata: Dict[str, Any] = field(default_factory=dict)

    def is_ok(self) -> bool:
        """Returns True if the process terminated successfully (returncode == 0)."""
        return self.success and self.returncode == 0


class SubprocessManager:
    """Manages safe execution of external system utilities."""

    @staticmethod
    def is_binary_available(binary_name: str) -> bool:
        """Check if an executable binary exists in system PATH."""
        return shutil.which(binary_name) is not None

    @staticmethod
    def get_binary_path(binary_name: str) -> Optional[str]:
        """Locate the full path to a system executable."""
        return shutil.which(binary_name)

    @classmethod
    def execute(
        cls,
        args: List[str],
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None
    ) -> CommandResult:
        """
        Execute an external tool securely.
        
        Args:
            args: Command and arguments as an array of strings.
            timeout: Maximum execution time in seconds.
            env: Optional environment variables dictionary.
            cwd: Working directory.
            
        Returns:
            CommandResult containing execution output, duration, and returncode.
        """
        if not args or not isinstance(args, list):
            return CommandResult(
                command="",
                args=args or [],
                returncode=-1,
                stdout="",
                stderr="Invalid command arguments provided (must be non-empty list).",
                duration_seconds=0.0,
                success=False,
                error_message="Invalid argument array"
            )

        binary = args[0]
        # Verify binary exists in path
        binary_path = cls.get_binary_path(binary)
        if not binary_path:
            return CommandResult(
                command=binary,
                args=args,
                returncode=127,
                stdout="",
                stderr=f"Executable '{binary}' was not found in system PATH.",
                duration_seconds=0.0,
                success=False,
                error_message=f"Missing binary: {binary}"
            )

        # Prepare clean execution environment
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        start_time = time.time()
        try:
            # Defensive execution: strictly shell=False, argument array
            completed = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=exec_env,
                cwd=cwd,
                errors="replace"
            )
            duration = round(time.time() - start_time, 2)
            
            return CommandResult(
                command=binary,
                args=args,
                returncode=completed.returncode,
                stdout=completed.stdout or "",
                stderr=completed.stderr or "",
                duration_seconds=duration,
                timed_out=False,
                success=(completed.returncode == 0)
            )

        except subprocess.TimeoutExpired as exc:
            duration = round(time.time() - start_time, 2)
            stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout.decode("utf-8", errors="replace") if exc.stdout else "")
            stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr.decode("utf-8", errors="replace") if exc.stderr else "")
            return CommandResult(
                command=binary,
                args=args,
                returncode=-1,
                stdout=stdout,
                stderr=f"{stderr}\n[Error] Command timed out after {timeout} seconds.",
                duration_seconds=duration,
                timed_out=True,
                success=False,
                error_message=f"Command timed out after {timeout} seconds"
            )

        except PermissionError as exc:
            duration = round(time.time() - start_time, 2)
            return CommandResult(
                command=binary,
                args=args,
                returncode=-1,
                stdout="",
                stderr=f"Permission denied executing '{binary}': {exc}",
                duration_seconds=duration,
                timed_out=False,
                success=False,
                error_message=f"Permission denied: {exc}"
            )

        except FileNotFoundError as exc:
            duration = round(time.time() - start_time, 2)
            return CommandResult(
                command=binary,
                args=args,
                returncode=127,
                stdout="",
                stderr=f"File not found: {exc}",
                duration_seconds=duration,
                timed_out=False,
                success=False,
                error_message=f"Executable not found: {exc}"
            )

        except Exception as exc:
            duration = round(time.time() - start_time, 2)
            return CommandResult(
                command=binary,
                args=args,
                returncode=-1,
                stdout="",
                stderr=f"Unexpected error running '{binary}': {str(exc)}",
                duration_seconds=duration,
                timed_out=False,
                success=False,
                error_message=str(exc)
            )
