#!/usr/bin/env python3
"""
O2Cli v0.2.0 - AI-powered CLI tool that converts natural language to terminal commands.
Uses local LLMs via Ollama or LM Studio. No cloud API needed.
"""

import csv
import io
import ipaddress
import json
import logging
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

REQUIRED_PACKAGES = {
    "httpx": "httpx>=0.27.0",
    "click": "click>=8.1.0",
    "rich": "rich>=13.0.0",
    "pydantic": "pydantic>=2.0.0",
    "pyperclip": "pyperclip>=1.8.0",
}

PACKAGE_HASHES = {
    "httpx":   "sha256:auto",
    "click":   "sha256:auto",
    "rich":    "sha256:auto",
    "pydantic":"sha256:auto",
    "pyperclip":"sha256:auto",
}

CONFIG_DIR = Path.cwd() / ".o2cli"
_MARKER_FILE = CONFIG_DIR / ".deps_installed"
_WELCOME_SHOWN_FILE = CONFIG_DIR / ".welcome_shown"
SESSIONS_DIR = CONFIG_DIR / "sessions"

MAX_CMD_LENGTH = 4096
MAX_STEPS = 20
MAX_LLM_CALLS_PER_SESSION = 100


def _install_dependencies():
    missing = {}
    for mod, spec in REQUIRED_PACKAGES.items():
        try:
            __import__(mod)
        except ImportError:
            missing[mod] = spec
    if not missing:
        return
    print(f"O2Cli: First run detected. Installing: {', '.join(missing.keys())}...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "--no-cache-dir"]
            + list(missing.values())
        )
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        _MARKER_FILE.write_text(datetime.now().isoformat())
        try:
            os.chmod(str(_MARKER_FILE), 0o600)
        except OSError:
            pass
        print("Dependencies installed!\n")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        print(f"Please run: pip install {' '.join(missing.values())}")
        sys.exit(1)


if not _MARKER_FILE.exists():
    _install_dependencies()

import click
import httpx
import pyperclip
from pydantic import BaseModel, Field
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

__version__ = "0.2.0"
APP_NAME = "o2cli"

OLLAMA_DEFAULT_URL   = "http://localhost:11434/v1"
LMSTUDIO_DEFAULT_URL = "http://localhost:1234/v1"

CONFIG_FILE   = CONFIG_DIR / "config.json"
HISTORY_FILE  = CONFIG_DIR / "history.json"
ALIASES_FILE  = CONFIG_DIR / "aliases.json"
PROFILES_FILE = CONFIG_DIR / "profiles.json"
SECURITY_FILE = CONFIG_DIR / "security.json"
DEBUG_LOG     = CONFIG_DIR / "debug.log"

console = Console()


def _secure_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)


def _secure_write_json(path: Path, data) -> None:
    _secure_write(path, json.dumps(data, indent=2, ensure_ascii=False))


_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private_url(url_str: str) -> bool:
    try:
        parsed = urlparse(url_str)
        hostname = parsed.hostname
        if not hostname:
            return True
        if hostname in ("localhost", "127.0.0.1", "::1"):
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            for network in _PRIVATE_NETWORKS:
                if ip in network:
                    return True
        except ValueError:
            blocked_domains = (".internal", ".local", ".localhost",
                               "metadata.google.internal",
                               "metadata.azure.com")
            for bd in blocked_domains:
                if hostname.endswith(bd) or hostname == bd.lstrip("."):
                    return True
        return False
    except Exception:
        return True


def validate_backend_url(url_str: str) -> tuple[bool, str]:
    try:
        parsed = urlparse(url_str)
    except Exception:
        return False, f"Invalid URL: {url_str}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Use http:// or https://"

    if not parsed.hostname:
        return False, "URL must include a hostname"

    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return True, ""

    if _is_private_url(url_str):
        return False, (
            f"URL '{url_str}' points to a private/internal network. "
            "Only localhost or public endpoints are allowed."
        )

    return True, ""


def _is_allowlisted(command: str, allowed_patterns: list[str]) -> bool:
    if not allowed_patterns:
        return False
    first_word = command.split()[0] if command.split() else ""
    for pat in allowed_patterns:
        try:
            regex_pat = "^" + re.escape(pat).replace(re.escape("*"), ".*").replace(re.escape("?"), ".") + "$"
            if re.match(regex_pat, command) or re.match(regex_pat, first_word):
                _SHELL_META_RE = re.compile(r"[;&|`$(){}\\!><\n\r]")
                if _SHELL_META_RE.search(command):
                    continue
                return True
        except re.error:
            continue
    return False


def _setup_debug_logging():
    if os.environ.get("O2CLI_DEBUG"):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=str(DEBUG_LOG),
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(message)s",
        )
        try:
            os.chmod(str(DEBUG_LOG), 0o600)
        except OSError:
            pass
    else:
        logging.disable(logging.CRITICAL)

_setup_debug_logging()


def _redact_for_logging(text: str, max_len: int = 200) -> str:
    text = re.sub(r'(api[_-]?key|authorization|token|secret)["\s:=]+["\']?[\w\-]+["\']?',
                  r'\1=***REDACTED***', text, flags=re.IGNORECASE)
    if len(text) > max_len:
        text = text[:max_len] + "...[TRUNCATED]"
    return text


BANNER = r"""
  ▄▄▄▄▄   ▄▄▄▄▄▄▄     ▄▄▄▄▄▄▄ ▄▄▄      ▄▄▄▄▄
▄███████▄ ▀▀▀▀████   ███▀▀▀▀▀ ███       ███
███   ███    ▄██▀    ███      ███       ███
███▄▄▄███  ▄███▄▄▄   ███      ███       ███
 ▀█████▀  ████████   ▀███████ ████████ ▄███▄
"""


def show_banner_if_first_run():
    if not _WELCOME_SHOWN_FILE.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        console.print(Text(BANNER, style="bold cyan"))
        console.print(f"  [bold green]O2Cli v{__version__} (Hardened)[/bold green]  [dim]- AI-powered terminal command generator[/dim]")
        console.print(f"  [dim]Powered by Ollama & LM Studio | 100% Local | No cloud needed[/dim]\n")
        _secure_write(_WELCOME_SHOWN_FILE, datetime.now().isoformat())


def print_short_header():
    console.print(f"[bold cyan]O2Cli[/bold cyan] [dim]v{__version__}[/dim]")


class BackendConfig(BaseModel):
    provider: str = "lmstudio"
    base_url: str = LMSTUDIO_DEFAULT_URL
    model: str = "qwen2.5-coder-0.5b-instruct"
    api_key: str = "not-needed"
    temperature: float = 0.1
    max_tokens: int = 512
    timeout: float = 30.0


class ShellConfig(BaseModel):
    preferred_shell: str = "cmd"
    confirm_before_execute: bool = True
    explain_commands: bool = True
    no_history: bool = False
    auto_context: bool = True  # Auto-detect project context (git, env, etc.)


class AppConfig(BaseModel):
    backend: BackendConfig = Field(default_factory=BackendConfig)
    shell: ShellConfig = Field(default_factory=ShellConfig)
    active_profile: str = "default"


class SecurityConfig(BaseModel):
    trusted_dirs: list[str] = Field(default_factory=list)
    allowed_patterns: list[str] = Field(default_factory=list)


CONFIG_BUNDLE_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "exported_at": {"type": "string"},
        "config": {
            "type": "object",
            "properties": {
                "backend": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string", "enum": ["ollama", "lmstudio"]},
                        "base_url": {"type": "string"},
                        "model": {"type": "string"},
                        "api_key": {"type": "string"},
                        "temperature": {"type": "number", "minimum": 0, "maximum": 2},
                        "max_tokens": {"type": "integer", "minimum": 1, "maximum": 32768},
                        "timeout": {"type": "number", "minimum": 1, "maximum": 300},
                    },
                    "additionalProperties": False,
                },
                "shell": {
                    "type": "object",
                    "properties": {
                        "preferred_shell": {"type": "string"},
                        "confirm_before_execute": {"type": "boolean"},
                        "explain_commands": {"type": "boolean"},
                        "no_history": {"type": "boolean"},
                        "auto_context": {"type": "boolean"},
                    },
                    "additionalProperties": False,
                },
                "active_profile": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "profiles": {"type": "object"},
        "aliases": {
            "type": "object",
            "additionalProperties": {"type": "string"},
        },
        "security": {
            "type": "object",
            "properties": {
                "trusted_dirs": {"type": "array", "items": {"type": "string"}},
                "allowed_patterns": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        },
    },
    "required": ["version"],
    "additionalProperties": False,
}


def _validate_json_schema(data: dict, schema: dict, path: str = "") -> list[str]:
    errors = []
    if "type" in schema:
        expected = schema["type"]
        if expected == "object" and not isinstance(data, dict):
            errors.append(f"{path}: expected object, got {type(data).__name__}")
            return errors
        if expected == "string" and not isinstance(data, str):
            errors.append(f"{path}: expected string, got {type(data).__name__}")
            return errors
        if expected == "number" and not isinstance(data, (int, float)):
            errors.append(f"{path}: expected number, got {type(data).__name__}")
            return errors
        if expected == "integer" and not isinstance(data, int):
            errors.append(f"{path}: expected integer, got {type(data).__name__}")
            return errors
        if expected == "boolean" and not isinstance(data, bool):
            errors.append(f"{path}: expected boolean, got {type(data).__name__}")
            return errors
        if expected == "array" and not isinstance(data, list):
            errors.append(f"{path}: expected array, got {type(data).__name__}")
            return errors

    if "enum" in schema and data not in schema["enum"]:
        errors.append(f"{path}: value {data!r} not in {schema['enum']}")

    if isinstance(data, (int, float)):
        if "minimum" in schema and data < schema["minimum"]:
            errors.append(f"{path}: {data} < minimum {schema['minimum']}")
        if "maximum" in schema and data > schema["maximum"]:
            errors.append(f"{path}: {data} > maximum {schema['maximum']}")

    if isinstance(data, str):
        _SHELL_META_RE = re.compile(r"[;&|`$(){}\\!><\n\r]")
        if path.endswith(("base_url", "model", "api_key")) and _SHELL_META_RE.search(data):
            errors.append(f"{path}: contains potentially dangerous shell metacharacters")

    if isinstance(data, dict):
        props = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)

        for key, prop_schema in props.items():
            if key in data:
                errors.extend(_validate_json_schema(data[key], prop_schema, f"{path}.{key}"))

        if additional is False:
            extra_keys = set(data.keys()) - set(props.keys())
            if extra_keys:
                errors.append(f"{path}: additional properties not allowed: {extra_keys}")

        for req in schema.get("required", []):
            if req not in data:
                errors.append(f"{path}: missing required property '{req}'")

    if isinstance(data, list) and "items" in schema:
        for i, item in enumerate(data):
            errors.extend(_validate_json_schema(item, schema["items"], f"{path}[{i}]"))

    return errors


def get_default_shell() -> str:
    if platform.system() == "Windows":
        return "powershell" if os.environ.get("PSModulePath") else "cmd"
    return os.environ.get("SHELL", "/bin/bash").split("/")[-1]


def resolve_provider_defaults(provider: str) -> dict:
    if provider == "ollama":
        return {"base_url": OLLAMA_DEFAULT_URL, "model": "llama3.2"}
    return {"base_url": LMSTUDIO_DEFAULT_URL, "model": ""}


def load_config() -> AppConfig:
    if CONFIG_FILE.exists():
        try:
            raw = CONFIG_FILE.read_text(encoding="utf-8")
            cfg = AppConfig(**json.loads(raw))
        except json.JSONDecodeError as e:
            logging.warning("Config file corrupted: %s", e)
            console.print(f"[yellow]Warning: Config file corrupted ({e}). Using defaults.[/yellow]")
            console.print(f"[dim]Fix with: o2cli config --reset[/dim]\n")
            cfg = AppConfig()
        except Exception as e:
            logging.warning("Config file invalid: %s", e)
            console.print(f"[yellow]Warning: Config file invalid ({e}). Using defaults.[/yellow]")
            cfg = AppConfig()
    else:
        cfg = AppConfig()

    env_overrides = {}
    if os.environ.get("O2CLI_MODEL"):
        cfg.backend.model = os.environ["O2CLI_MODEL"]
        env_overrides["O2CLI_MODEL"] = os.environ["O2CLI_MODEL"]
    if os.environ.get("O2CLI_PROVIDER"):
        provider = os.environ["O2CLI_PROVIDER"]
        if provider not in ("ollama", "lmstudio"):
            console.print(f"[yellow]Warning: O2CLI_PROVIDER='{provider}' is not a valid provider. Ignored.[/yellow]")
        else:
            cfg.backend.provider = provider
            env_overrides["O2CLI_PROVIDER"] = provider
    if os.environ.get("O2CLI_BASE_URL"):
        url = os.environ["O2CLI_BASE_URL"]
        is_valid, err = validate_backend_url(url)
        if not is_valid:
            console.print(f"[yellow]Warning: O2CLI_BASE_URL rejected: {err}. Using config value.[/yellow]")
        else:
            cfg.backend.base_url = url
            env_overrides["O2CLI_BASE_URL"] = url

    if env_overrides:
        logging.warning("Env overrides applied: %s", _redact_for_logging(str(env_overrides)))
        console.print(f"[dim]Env overrides: {', '.join(env_overrides.keys())}[/dim]")

    return cfg


def save_config(config: AppConfig) -> None:
    _secure_write_json(CONFIG_FILE, json.loads(config.model_dump_json(indent=2)))


def load_security() -> SecurityConfig:
    if SECURITY_FILE.exists():
        try:
            return SecurityConfig(**json.loads(SECURITY_FILE.read_text(encoding="utf-8")))
        except json.JSONDecodeError as e:
            logging.warning("Security config corrupted: %s", e)
        except Exception as e:
            logging.warning("Security config invalid: %s", e)
    return SecurityConfig()


def save_security(sec: SecurityConfig) -> None:
    _secure_write_json(SECURITY_FILE, json.loads(sec.model_dump_json(indent=2)))


def load_history() -> list[dict]:
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def save_history(history: list[dict], max_entries: int = 500) -> None:
    _secure_write_json(HISTORY_FILE, history[-max_entries:])


def load_profiles() -> dict:
    if PROFILES_FILE.exists():
        try:
            return json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_profiles(profiles: dict) -> None:
    _secure_write_json(PROFILES_FILE, profiles)


def apply_profile(config: AppConfig, profile_name: str) -> AppConfig:
    profiles = load_profiles()
    if profile_name in profiles:
        p = profiles[profile_name]
        for key in ("model", "provider", "temperature", "base_url"):
            if key in p:
                if key == "base_url":
                    is_valid, err = validate_backend_url(p[key])
                    if not is_valid:
                        console.print(f"[yellow]Profile URL rejected: {err}. Skipping.[/yellow]")
                        continue
                if key == "provider" and p[key] not in ("ollama", "lmstudio"):
                    console.print(f"[yellow]Invalid provider in profile: {p[key]}. Skipping.[/yellow]")
                    continue
                setattr(config.backend, key, p[key])
    return config


def load_aliases() -> dict:
    if ALIASES_FILE.exists():
        try:
            return json.loads(ALIASES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_aliases(aliases: dict) -> None:
    _secure_write_json(ALIASES_FILE, aliases)


def export_config_bundle() -> dict:
    return {
        "version": __version__,
        "exported_at": datetime.now().isoformat(),
        "config":   json.loads(CONFIG_FILE.read_text())   if CONFIG_FILE.exists()   else {},
        "profiles": load_profiles(),
        "aliases":  load_aliases(),
        "security": json.loads(SECURITY_FILE.read_text()) if SECURITY_FILE.exists() else {},
    }


def import_config_bundle(bundle: dict) -> None:
    errors = _validate_json_schema(bundle, CONFIG_BUNDLE_SCHEMA)
    if errors:
        console.print("[bold red]Config bundle validation failed:[/bold red]")
        for err in errors[:10]:
            console.print(f"  [red]{err}[/red]")
        if len(errors) > 10:
            console.print(f"  [dim]... and {len(errors) - 10} more errors[/dim]")
        raise ValueError(f"Config bundle validation failed with {len(errors)} error(s)")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if bundle.get("config"):
        try:
            AppConfig(**bundle["config"])
        except Exception as e:
            raise ValueError(f"Invalid config in bundle: {e}")
        _secure_write_json(CONFIG_FILE, bundle["config"])
    if bundle.get("profiles"):
        _secure_write_json(PROFILES_FILE, bundle["profiles"])
    if bundle.get("aliases"):
        for k, v in bundle["aliases"].items():
            if not isinstance(v, str):
                raise ValueError(f"Alias '{k}' has non-string value: {v!r}")
            _SHELL_META_RE = re.compile(r"[;&|`$(){}\\!><\n\r]")
            if _SHELL_META_RE.search(v):
                raise ValueError(f"Alias '{k}' contains shell metacharacters — rejected for safety")
        _secure_write_json(ALIASES_FILE, bundle["aliases"])
    if bundle.get("security"):
        try:
            SecurityConfig(**bundle["security"])
        except Exception as e:
            raise ValueError(f"Invalid security config in bundle: {e}")
        _secure_write_json(SECURITY_FILE, bundle["security"])


_DANGER_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brm\b.*-[a-zA-Z]*[rR][a-zA-Z]*[fF]?\s+[/~*]", re.IGNORECASE),
     "Recursive delete of root / home / all files"),
    (re.compile(r"\brm\b.*-[a-zA-Z]*[fF][a-zA-Z]*[rR]?\s+[/~*]", re.IGNORECASE),
     "Recursive force-delete of root / home / all files"),
    (re.compile(r"\brm\b\s+-rf\s+--no-preserve-root", re.IGNORECASE),
     "Explicit --no-preserve-root delete"),
    (re.compile(r"\bdel\b.*/[sqfSQF]+.*[a-zA-Z]:\\", re.IGNORECASE),
     "Force-delete on a Windows drive root"),
    (re.compile(r"\bformat\b\s+[a-zA-Z]:", re.IGNORECASE),
     "Formats a Windows disk"),
    (re.compile(r"\brd\b\s+/s\s+/q\s+[a-zA-Z]:\\", re.IGNORECASE),
     "Silently removes entire Windows drive tree"),
    (re.compile(r":\(\)\s*\{.*\|.*:.*&.*\}", re.IGNORECASE), "Fork bomb detected"),
    (re.compile(r":\(\)\{.*\|.*:&\}",        re.IGNORECASE), "Fork bomb (compact form)"),
    (re.compile(r"\bmkfs\b",                    re.IGNORECASE), "Formats a filesystem"),
    (re.compile(r"\bdd\b.*\bif=",              re.IGNORECASE), "Direct disk operation (dd)"),
    (re.compile(r">\s*/dev/sd[a-zA-Z]",        re.IGNORECASE), "Writes to raw disk device"),
    (re.compile(r">\s*/dev/nvme",              re.IGNORECASE), "Writes to NVMe device"),
    (re.compile(r"\bfdisk\b",                  re.IGNORECASE), "Partition table editor"),
    (re.compile(r"\bparted\b",                 re.IGNORECASE), "Partition table editor"),
    (re.compile(r"\bshutdown\b",  re.IGNORECASE), "Shuts down the system"),
    (re.compile(r"\breboot\b",    re.IGNORECASE), "Reboots the system"),
    (re.compile(r"\bhalt\b",      re.IGNORECASE), "Halts the system"),
    (re.compile(r"\bpoweroff\b",  re.IGNORECASE), "Powers off the system"),
    (re.compile(r"(wget|curl)\s+\S+\s*[|]\s*(sh|bash|zsh|python\d*|ruby|perl)", re.IGNORECASE),
     "Downloads and executes a remote script"),
    (re.compile(r"eval\s*\(\s*(wget|curl)", re.IGNORECASE),
     "Evaluates downloaded content"),
    (re.compile(r"\bsudo\b.*\brm\b.*-[a-zA-Z]*r", re.IGNORECASE),
     "Sudo recursive delete"),
    (re.compile(r"\bsudo\b.*\bchmod\b.*777.*[/~]", re.IGNORECASE),
     "Sudo world-writable permission on root/home"),
    (re.compile(r">\s*(~/)?\.(bash|zsh|sh)_history", re.IGNORECASE),
     "Erases shell history"),
    (re.compile(r"\bhistory\s+-c\b", re.IGNORECASE), "Clears shell history"),
    (re.compile(r"\brm\b.*\s/etc/(passwd|shadow|sudoers|hosts)", re.IGNORECASE),
     "Deletes a critical system file"),
    (re.compile(r">\s*/etc/(passwd|shadow|sudoers)", re.IGNORECASE),
     "Overwrites a critical system file"),
    (re.compile(r";\s*(curl|wget)\s+", re.IGNORECASE),
     "Command chaining with network tool"),
    (re.compile(r"\|\s*(sh|bash|zsh|python\d*|ruby|perl)\b", re.IGNORECASE),
     "Pipe to interpreter"),
    (re.compile(r"\$\([^)]*\)", re.IGNORECASE),
     "Command substitution detected"),
    (re.compile(r"`[^`]+`", re.IGNORECASE),
     "Backtick command substitution detected"),
    (re.compile(r"&&\s*(rm|dd|mkfs|format)\b", re.IGNORECASE),
     "Chained destructive command"),
    (re.compile(r">\s*/dev/null\s*2>&1\s*;", re.IGNORECASE),
     "Output suppression followed by command chain"),
]

RISK_COLORS = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}


def _static_danger_check(command: str) -> tuple[bool, str]:
    for pattern, reason in _DANGER_PATTERNS:
        if pattern.search(command):
            return True, reason
    return False, ""


def _is_trusted_dir(sec: SecurityConfig) -> bool:
    cwd = Path.cwd().resolve()
    for td in sec.trusted_dirs:
        try:
            cwd.relative_to(Path(td).resolve())
            return True
        except ValueError:
            pass
    return False


_SAFE_COMMANDS = {
    "ls", "dir", "pwd", "cd", "cat", "head", "tail", "less", "more",
    "echo", "printf", "wc", "sort", "uniq", "diff", "grep", "rg", "ack",
    "find", "locate", "which", "whereis", "type", "file", "stat",
    "cp", "mv", "mkdir", "touch", "ln", "chmod", "chown",
    "tar", "gzip", "gunzip", "zip", "unzip", "bzip2", "xz",
    "df", "du", "free", "top", "htop", "ps", "kill", "killall",
    "netstat", "ss", "lsof", "ping", "traceroute", "dig", "nslookup", "host",
    "curl", "wget",
    "git", "svn", "hg",
    "docker", "docker-compose", "podman", "kubectl", "helm",
    "npm", "npx", "yarn", "pnpm", "pip", "python", "python3", "node",
    "java", "javac", "mvn", "gradle", "cargo", "rustc", "go",
    "make", "cmake", "gcc", "g++", "clang",
    "sed", "awk", "cut", "tr", "tee", "xargs",
    "systemctl", "service", "journalctl",
    "env", "export", "set", "unset", "alias", "unalias",
    "date", "cal", "uptime", "whoami", "id", "hostname", "uname",
    "man", "info", "help",
    "code", "vim", "nano", "emacs", "ed",
    "ssh", "scp", "rsync", "sftp",
    "dir", "type", "copy", "xcopy", "move", "del", "rmdir", "mkdir",
    "tasklist", "taskkill", "ipconfig", "netstat", "systeminfo",
    "Get-Process", "Get-ChildItem", "Set-Location", "Test-Connection",
}

_SHELL_META_PATTERN = re.compile(
    r'(?:'
    r';'
    r'|&{2}'
    r'|`'
    r'|\$\('
    r'|&&'
    r'|\|\|'
    r')'
)


def _parse_and_validate_command(raw: str) -> tuple[str, list[str]]:
    warnings = []

    cleaned = raw.strip()
    cleaned = re.sub(r"^```[a-z]*\n?", "", cleaned)
    cleaned = re.sub(r"\n?```$", "", cleaned)
    cleaned = cleaned.strip().strip("`").strip()

    if cleaned.startswith("$ ") or cleaned.startswith("> "):
        cleaned = cleaned[2:]

    if len(cleaned) > MAX_CMD_LENGTH:
        warnings.append(f"Command exceeds {MAX_CMD_LENGTH} chars — truncated")
        cleaned = cleaned[:MAX_CMD_LENGTH]

    first_line = cleaned.splitlines()[0] if cleaned else ""
    first_token = first_line.split()[0] if first_line.split() else ""
    cmd_name = os.path.basename(first_token)

    if cmd_name not in _SAFE_COMMANDS:
        warnings.append(f"Command '{cmd_name}' not in safe list — proceed with caution")

    if _SHELL_META_PATTERN.search(cleaned):
        warnings.append("Shell metacharacters detected (pipes/chaining) — verify carefully")

    return cleaned, warnings


def _collect_context(mode: str) -> str:
    lines = []
    cwd = os.getcwd()
    _SHELL_META_RE = re.compile(r"[;&|`$(){}\\!><\n\r]")
    if _SHELL_META_RE.search(cwd):
        return f"Context: working directory contains special characters — skipping shell context collection"

    if mode == "git":
        for cmd in (["git", "status", "--short"], ["git", "branch", "--show-current"]):
            try:
                out = subprocess.check_output(
                    cmd, text=True, timeout=3, stderr=subprocess.DEVNULL,
                )
                lines.append(f"$ {' '.join(cmd)}\n{out.strip()}")
            except Exception:
                pass
    elif mode == "ls":
        try:
            out = subprocess.check_output(
                ["ls", "-la"], text=True, timeout=3, stderr=subprocess.DEVNULL,
            )
            lines.append(f"$ ls -la\n{out.strip()}")
        except Exception:
            pass
    elif mode == "env":
        safe_env = {k: v for k, v in os.environ.items()
                    if not any(s in k.lower() for s in ("secret", "key", "token", "pass", "pwd"))}
        lines.append("Environment:\n" + "\n".join(f"  {k}={v}" for k, v in safe_env.items()))
    elif mode:
        lines.append(mode)
    return "\n".join(lines)


_TEMPLATE_VAR_RE = re.compile(r"\{(\w+)\}")

# ── Auto-context detection ────────────────────────────────────────────────────

# Ordered list of (marker_file_or_dir, context_mode) — first match wins
_CONTEXT_MARKERS: list[tuple[str, str]] = [
    (".git",          "git"),
    (".env",          "env"),
    ("package.json",  "ls"),
    ("Dockerfile",    "ls"),
    ("docker-compose.yml", "ls"),
    ("Makefile",      "ls"),
    ("pyproject.toml","ls"),
    ("Cargo.toml",    "ls"),
    ("go.mod",        "ls"),
]


def _auto_detect_context() -> str:
    """Walk CWD and parents looking for known project markers.

    Returns the matching context mode string, or "" if nothing found.
    Only traverses up to the filesystem root (stops when parent == self).
    """
    cwd = Path.cwd().resolve()
    # Check CWD and up to 3 parent levels to handle nested project dirs
    search_dirs = [cwd] + list(cwd.parents)[:3]
    for directory in search_dirs:
        for marker, mode in _CONTEXT_MARKERS:
            if (directory / marker).exists():
                return mode
    return ""


_SAFE_TEMPLATE_VALUE_RE = re.compile(r'^[a-zA-Z0-9_./:\-@]+$')


def resolve_template_vars(task: str) -> str:
    vars_found = _TEMPLATE_VAR_RE.findall(task)
    if not vars_found:
        return task
    console.print(f"\n[bold yellow]Template variables:[/bold yellow]")
    substitutions = {}
    for var in dict.fromkeys(vars_found):
        try:
            value = console.input(f"  [bold cyan]{var}[/bold cyan] = ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Cancelled.[/dim]")
            sys.exit(0)

        if not value:
            console.print(f"  [yellow]Warning: Empty value for '{var}'[/yellow]")
            substitutions[var] = ""
            continue

        if not _SAFE_TEMPLATE_VALUE_RE.match(value):
            console.print(
                f"  [red]Error: Value '{value}' for '{var}' contains disallowed characters. "
                f"Only alphanumeric, ._/:@- are allowed.[/red]"
            )
            console.print(f"  [dim]The value will be shell-escaped for safety.[/dim]")
            substitutions[var] = shlex.quote(value)
        else:
            substitutions[var] = shlex.quote(value)

    result = task
    for var, value in substitutions.items():
        result = result.replace(f"{{{var}}}", value)
    return result


_TRASH_DIR = CONFIG_DIR / "trash"


def _ensure_trash_dir() -> Path:
    _TRASH_DIR.mkdir(parents=True, exist_ok=True)
    return _TRASH_DIR


def suggest_undo(command: str) -> Optional[str]:
    m = re.match(r"\bmv\s+(\S+)\s+(\S+)", command)
    if m:
        return f"mv {shlex.quote(m.group(2))} {shlex.quote(m.group(1))}"

    m = re.match(r"\bmkdir\s+(?:-p\s+)?(\S+)", command)
    if m:
        target = m.group(1)
        return f"mv {shlex.quote(target)} {shlex.quote(str(_ensure_trash_dir()))}"

    m = re.match(r"\btouch\s+(\S+)", command)
    if m:
        target = m.group(1)
        return f"mv {shlex.quote(target)} {shlex.quote(str(_ensure_trash_dir()))}"

    m = re.match(r"\bcp\s+\S+\s+(\S+)", command)
    if m:
        target = m.group(1)
        return f"mv {shlex.quote(target)} {shlex.quote(str(_ensure_trash_dir()))}"

    return None


# ── Prompt injection prevention ──────────────────────────────────────────────

MAX_TASK_LENGTH = 500  # Characters; guards against prompt-stuffing attacks

# Patterns that indicate an attempt to override the system prompt
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|context)", re.IGNORECASE),
    re.compile(r"\b(system\s*:|<\s*system\s*>|<\s*/?s\s*>)", re.IGNORECASE),
    re.compile(r"\b(assistant\s*:|<\s*assistant\s*>)", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(a\s+)?(different|new|unrestricted|jailbroken)", re.IGNORECASE),
    re.compile(r"\bdo\s+anything\s+now\b", re.IGNORECASE),         # DAN jailbreak
    re.compile(r"\bdan\s+mode\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+(you\s+are|to\s+be)\b.*\b(no\s+restrictions?|unrestricted|evil)", re.IGNORECASE),
    re.compile(r"\byour\s+(new\s+)?instructions?\s+(are|is)\b", re.IGNORECASE),
    re.compile(r"\bforget\s+(all\s+)?(previous|prior|your)\s+(instructions?|training)", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]|\{\{.*?\}\}", re.IGNORECASE),  # Llama/Mistral tokens
    re.compile(r"###\s*instruction", re.IGNORECASE),                 # Alpaca-style injection
]

# Patterns that suggest the LLM replied with prose instead of a command
_PROSE_PREFIXES: tuple[str, ...] = (
    "sure", "of course", "certainly", "absolutely", "i can", "i'll", "i will",
    "as an ai", "as a language model", "i'm sorry", "i am sorry",
    "i understand", "here is", "here's", "to accomplish", "the command",
    "you can use", "you should", "let me", "i'd be happy",
)


def _sanitize_task(task: str) -> tuple[str, list[str]]:
    """Strip injection attempts from the task string.

    Returns (sanitized_task, list_of_warnings).
    Raises ValueError if the task contains a clear injection attempt.
    """
    warnings: list[str] = []

    # Length guard
    if len(task) > MAX_TASK_LENGTH:
        warnings.append(f"Task truncated from {len(task)} to {MAX_TASK_LENGTH} chars")
        task = task[:MAX_TASK_LENGTH]

    # Injection pattern check
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(task):
            raise ValueError(
                f"Task rejected: possible prompt injection detected "
                f"(matched: {pattern.pattern[:60]}). "
                "If this is a legitimate request, rephrase it."
            )

    # Strip null bytes and control characters (common in injection payloads)
    sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", task)
    if sanitized != task:
        warnings.append("Control characters stripped from task")

    return sanitized.strip(), warnings


def _looks_like_prose(response: str) -> bool:
    """Return True if the LLM response looks like conversational prose rather than a command."""
    first_line = response.strip().splitlines()[0].lower() if response.strip() else ""
    # Strip leading punctuation/whitespace for comparison
    first_word_line = first_line.lstrip("\"'`- ")
    for prefix in _PROSE_PREFIXES:
        if first_word_line.startswith(prefix):
            return True
    # A response that is a full sentence (ends with period and has >8 words) is prose
    words = first_line.split()
    if len(words) > 8 and first_line.rstrip().endswith("."):
        return True
    return False


SHELL_COMMAND_PROMPT = """\
You are an expert terminal/shell assistant. The user will describe a task in \
natural language, and you must respond with ONLY the terminal command(s) needed.

STRICT RULES:
1. Output ONLY the command — no explanations, no markdown, no backticks, no "$" or ">".
2. If multiple sequential commands are needed, put each on its own line.
3. Target shell: {shell}.
4. Operating system: {os}.
5. Current directory: {cwd}.
6. If the task is impossible or unclear, output: ERROR: <brief reason>
7. Prefer common, standard commands.
8. Do NOT use sudo unless the user explicitly mentions admin/root.
9. On Windows prefer forward slashes in paths.
10. Never include interactive prompts that would hang the terminal.
11. Never use command substitution ($()), backticks, or pipe-to-shell patterns.
12. Never chain commands with && or ; — output each command on its own line.
{context_block}
"""

EXPLAIN_PROMPT = """\
You are an expert terminal/shell assistant. Explain the following {shell} command \
in simple, clear language. Be concise (2-4 sentences). No markdown formatting.

Command: {command}
"""

CHAT_PROMPT = """\
You are an expert terminal/shell assistant on {os} with {shell}.
Help with terminal commands, shell scripting, and system administration.
Be concise and practical.
Special slash commands the user may use:
  /ask <task>    -> respond ONLY with the raw shell command, prefixed CMD:
  /run <command> -> acknowledge what was run
"""

SAFETY_CHECK_PROMPT = """\
You are a shell command safety auditor. Assess the risk level of the following \
{shell} command on {os}.

Reply ONLY with valid JSON — no markdown, no code fences:
{{"risk":"LOW"|"MEDIUM"|"HIGH","reason":"<one sentence>"}}

Command: {command}
"""

REFINE_PROMPT = """\
You are an expert terminal/shell assistant. Revise the command based on the user's feedback.

Original task: {task}
Current command: {command}
Feedback: {feedback}
Shell: {shell}, OS: {os}

Respond with ONLY the revised command. No explanations, no backticks.
"""

FIX_PROMPT = """\
You are an expert terminal/shell assistant. A command failed — suggest a corrected version.

Shell: {shell}, OS: {os}
Failed command: {command}
Exit code: {rc}
Stderr: {stderr}

Respond with ONLY the corrected command. No explanations, no backticks.
If unfixable, output: ERROR: <brief reason>
"""


class LLMEngine:
    def __init__(self, config: AppConfig):
        self.config = config
        self._client: Optional[httpx.Client] = None
        self._call_count = 0

    @property
    def client(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=self.config.backend.base_url,
                headers={
                    "Authorization": f"Bearer {self.config.backend.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self.config.backend.timeout,
            )
        return self._client

    def _shell(self) -> str:
        s = self.config.shell.preferred_shell
        return get_default_shell() if s == "auto" else s

    def _os(self) -> str:
        return f"{platform.system()} {platform.release()}".strip()

    def _check_budget(self) -> None:
        self._call_count += 1
        if self._call_count > MAX_LLM_CALLS_PER_SESSION:
            raise RuntimeError(
                f"LLM call budget exceeded ({MAX_LLM_CALLS_PER_SESSION} calls/session). "
                "Start a new session or increase the limit."
            )

    def _chat(self, messages: list[dict], retries: int = 2) -> str:
        self._check_budget()
        payload = {
            "model": self.config.backend.model,
            "messages": messages,
            "temperature": self.config.backend.temperature,
            "max_tokens": self.config.backend.max_tokens,
            "stream": False,
        }
        logging.debug("Request: %s", _redact_for_logging(json.dumps(payload)))
        last_err = None
        for attempt in range(retries + 1):
            try:
                resp = self.client.post("/chat/completions", json=payload)
                resp.raise_for_status()
                result = resp.json()["choices"][0]["message"]["content"].strip()
                logging.debug("Response: %s", _redact_for_logging(result))
                return result
            except httpx.ConnectError as e:
                last_err = e
                if attempt < retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                pn = "Ollama" if self.config.backend.provider == "ollama" else "LM Studio"
                raise ConnectionError(
                    f"Cannot connect to {self.config.backend.base_url}. Is {pn} running?"
                )
            except httpx.HTTPStatusError as e:
                raise RuntimeError(f"API error ({e.response.status_code}): {e.response.text}")
            except KeyError:
                raise RuntimeError("Unexpected API response format.")
        raise RuntimeError(f"Failed after {retries + 1} attempts: {last_err}")

    def generate_command(self, task: str, context: str = "") -> tuple[str, list[str]]:
        context_block = f"\nAdditional context:\n{context}" if context else ""
        sys_msg = SHELL_COMMAND_PROMPT.format(
            shell=self._shell(), os=self._os(),
            cwd=os.getcwd(), context_block=context_block,
        )
        raw = self._chat([
            {"role": "system", "content": sys_msg},
            {"role": "user",   "content": task},
        ])
        command, warnings = _parse_and_validate_command(raw)
        return command, warnings

    def refine_command(self, task: str, command: str, feedback: str) -> tuple[str, list[str]]:
        sys_msg = REFINE_PROMPT.format(
            task=task, command=command, feedback=feedback,
            shell=self._shell(), os=self._os(),
        )
        raw = self._chat([{"role": "system", "content": sys_msg}])
        command, warnings = _parse_and_validate_command(raw)
        return command, warnings

    def fix_command(self, command: str, rc: int, stderr: str) -> tuple[str, list[str]]:
        sys_msg = FIX_PROMPT.format(
            shell=self._shell(), os=self._os(),
            command=command, rc=rc, stderr=stderr[:500],
        )
        raw = self._chat([{"role": "system", "content": sys_msg}])
        command, warnings = _parse_and_validate_command(raw)
        return command, warnings

    def explain_command(self, command: str) -> str:
        sys_msg = EXPLAIN_PROMPT.format(shell=self._shell(), command=command)
        return self._chat([{"role": "system", "content": sys_msg}])

    def safety_check(self, command: str) -> tuple[str, str]:
        sys_msg = SAFETY_CHECK_PROMPT.format(
            shell=self._shell(), os=self._os(), command=command
        )
        try:
            raw = self._chat([{"role": "system", "content": sys_msg}])
            raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
            raw = re.sub(r"\n?```$", "", raw).strip()
            data = json.loads(raw)
            return data.get("risk", "MEDIUM"), data.get("reason", "Unable to assess.")
        except Exception:
            return "MEDIUM", "Could not parse safety assessment."

    def chat(self, user_message: str, history: list[dict] | None = None) -> str:
        sys_msg = CHAT_PROMPT.format(os=self._os(), shell=self._shell())
        msgs = [{"role": "system", "content": sys_msg}]
        if history:
            msgs.extend(history)
        msgs.append({"role": "user", "content": user_message})
        return self._chat(msgs)

    def list_models(self) -> list[str]:
        try:
            resp = self.client.get("/models")
            resp.raise_for_status()
            return [m["id"] for m in resp.json().get("data", [])]
        except Exception:
            return []

    def check_connection(self) -> tuple[bool, str]:
        try:
            resp = self.client.get("/models")
            resp.raise_for_status()
            models = [m["id"] for m in resp.json().get("data", [])]
            if models:
                return True, f"Connected. Models: {', '.join(models)}"
            return True, "Connected — no models loaded yet."
        except httpx.ConnectError:
            pn = "Ollama" if self.config.backend.provider == "ollama" else "LM Studio"
            return False, f"Cannot connect to {self.config.backend.base_url}. Is {pn} running?"
        except Exception as e:
            return False, f"Error: {e}"

    def close(self):
        if self._client and not self._client.is_closed:
            self._client.close()


def display_command(command: str, shell: str, warnings: list[str] | None = None) -> None:
    lexer = "powershell" if shell in ("powershell", "pwsh") else "bash"
    console.print()
    console.print(Panel(
        Syntax(command, lexer, theme="monokai", word_wrap=True),
        title=f"[bold green]Generated Command[/bold green] ({shell})",
        border_style="green", padding=(1, 2),
    ))
    if warnings:
        for w in warnings:
            console.print(f"  [yellow]⚠ {w}[/yellow]")


def display_explanation(text: str) -> None:
    console.print()
    console.print(Panel(text, title="[bold cyan]Explanation[/bold cyan]",
                        border_style="cyan", padding=(1, 2)))


def display_risk_badge(risk: str, reason: str) -> None:
    color = RISK_COLORS.get(risk, "yellow")
    console.print()
    console.print(Panel(
        f"Risk: [{color}]{risk}[/{color}]\nReason: {reason}",
        title="[bold]Safety Assessment[/bold]",
        border_style=color, padding=(0, 2),
    ))


def display_danger_warning(reason: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold red]DANGEROUS COMMAND BLOCKED[/bold red]\n\n"
        f"Reason: [yellow]{reason}[/yellow]\n\n"
        f"This command has NOT been executed. If you are certain it is safe, "
        f"copy it manually from above and run it yourself.",
        title="[bold red]Security Block[/bold red]",
        border_style="red", padding=(1, 2),
    ))


def prompt_action_menu() -> str:
    console.print()
    console.print("[bold yellow]What would you like to do?[/bold yellow]")
    console.print("  [bold][E][/bold]xecute   [bold][C][/bold]opy   "
                  "[bold][R][/bold]efine   [bold][S][/bold]kip")
    console.print()
    while True:
        try:
            choice = console.input("[bold]> [/bold]").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "skip"
        if choice in ("e", "execute", ""):  return "execute"
        if choice in ("c", "copy"):         return "copy"
        if choice in ("r", "refine"):       return "refine"
        if choice in ("s", "skip", "q"):    return "skip"
        console.print("[dim]Enter E, C, R, or S.[/dim]")


def try_copy_to_clipboard(command: str) -> bool:
    try:
        pyperclip.copy(command)
        return True
    except Exception:
        return False


def execute_streaming(command: str, shell: str) -> tuple[int, str, str]:
    stdout_lines: list[str] = []
    try:
        if platform.system() == "Windows" and shell in ("powershell", "pwsh"):
            proc = subprocess.Popen(
                ["powershell", "-Command", command],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
            )
        else:
            try:
                args = shlex.split(command)
            except ValueError as e:
                return -1, "", f"Command parsing error: {e}"

            if not args:
                return -1, "", "Empty command"

            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1,
            )

        for line in iter(proc.stdout.readline, ""):
            console.print(line, end="")
            stdout_lines.append(line)
        proc.stdout.close()
        stderr_text = proc.stderr.read()
        proc.stderr.close()
        proc.wait(timeout=120)
        return proc.returncode, "".join(stdout_lines), stderr_text
    except subprocess.TimeoutExpired:
        proc.kill()
        return -1, "", "Command timed out after 120 seconds"
    except FileNotFoundError as e:
        return -1, "", f"Command not found: {e}"
    except Exception as e:
        return -1, "", str(e)


def run_steps(command: str, shell: str) -> tuple[int, str, str]:
    steps = [s.strip() for s in command.splitlines() if s.strip()]

    if len(steps) > MAX_STEPS:
        console.print(f"[red]Command has {len(steps)} steps — maximum is {MAX_STEPS}. "
                      f"Only the first {MAX_STEPS} will be executed.[/red]")
        steps = steps[:MAX_STEPS]

    if len(steps) <= 1:
        return execute_streaming(command, shell)

    console.print(f"\n[dim]Multi-step command ({len(steps)} steps)[/dim]")
    all_out, all_err = [], []
    last_rc = 0
    for i, step in enumerate(steps, 1):
        if len(step) > MAX_CMD_LENGTH:
            console.print(f"[red]Step {i} exceeds {MAX_CMD_LENGTH} chars — skipping.[/red]")
            continue

        is_danger, danger_reason = _static_danger_check(step)
        if is_danger:
            display_danger_warning(danger_reason)
            continue

        console.print(f"\n[bold cyan]Step {i}/{len(steps)}:[/bold cyan] [green]{step}[/green]")
        rc, out, err = execute_streaming(step, shell)
        all_out.append(out)
        if err:
            console.print(f"[red]{err}[/red]")
            all_err.append(err)
        last_rc = rc
        if rc != 0 and i < len(steps):
            console.print(f"[yellow]Step {i} exited with code {rc}.[/yellow]")
            try:
                if not Confirm.ask("Continue to next step?", default=False):
                    break
            except (EOFError, KeyboardInterrupt):
                break
    return last_rc, "".join(all_out), "".join(all_err)


def run_and_display(
    command: str,
    shell: str,
    engine: Optional[LLMEngine] = None,
    task_text: str = "",
) -> tuple[int, str, str]:
    console.print("\n[bold]Executing...[/bold]\n")
    rc, out, err = run_steps(command, shell)

    if rc == 0:
        console.print(f"\n[green]Done (exit 0)[/green]")
        undo = suggest_undo(command)
        if undo:
            console.print(f"[dim]Safe undo (moves to trash): {undo}[/dim]")
            try:
                if Confirm.ask("Run undo command?", default=False):
                    run_steps(undo, shell)
            except (EOFError, KeyboardInterrupt):
                pass
    else:
        console.print(f"\n[yellow]Exit code: {rc}[/yellow]")
        if err:
            console.print(f"[red]{err.strip()}[/red]")
        if engine:
            try:
                if Confirm.ask("\nAsk AI for a fix?", default=True):
                    with console.status("[bold yellow]Generating fix...", spinner="dots"):
                        fixed, fix_warnings = engine.fix_command(command, rc, err)
                    if fixed.startswith("ERROR:"):
                        console.print(f"[dim]{fixed}[/dim]")
                    else:
                        display_command(fixed, shell, fix_warnings)
                        if Confirm.ask("Execute fix?", default=False):
                            run_and_display(fixed, shell, engine, task_text)
            except (EOFError, KeyboardInterrupt):
                pass
    return rc, out, err


def _dedup_history(entries: list[dict]) -> list[dict]:
    if len(entries) < 2:
        return entries
    last, new = entries[-2], entries[-1]
    if last.get("task") == new.get("task") and last.get("command") == new.get("command"):
        return entries[:-1]
    return entries


def save_to_history(config: AppConfig, task: str, command: str,
                    executed: bool = False, blocked: bool = False,
                    exit_code: Optional[int] = None):
    if config.shell.no_history:
        return
    entries = load_history()
    entries.append({
        "timestamp": datetime.now().isoformat(),
        "task": task,
        "command": command,
        "executed": executed,
        "blocked": blocked,
        "exit_code": exit_code,
        "shell": config.shell.preferred_shell,
        "provider": config.backend.provider,
        "starred": False,
    })
    entries = _dedup_history(entries)
    save_history(entries)


def run_ask_flow(
    config: AppConfig,
    task_text: str,
    do_exec: bool = False,
    no_explain: bool = False,
    dry_run: bool = False,
    output_raw: bool = False,
    do_copy: bool = False,
    llm_safety: bool = False,
    context_mode: str = "",
    explain_only: bool = False,
):
    sec = load_security()
    engine = LLMEngine(config)
    try:
        task_text = resolve_template_vars(task_text)
        context_str = _collect_context(context_mode) if context_mode else ""

        with console.status("[bold green]Thinking...", spinner="dots"):
            command, cmd_warnings = engine.generate_command(task_text, context=context_str)

        cur_shell = config.shell.preferred_shell
        if cur_shell == "auto":
            cur_shell = get_default_shell()

        if command.startswith("ERROR:"):
            console.print(f"[bold red]Error:[/bold red] {command[6:].strip()}")
            return

        if output_raw:
            print(command)
            return

        display_command(command, cur_shell, cmd_warnings)

        if _is_allowlisted(command, sec.allowed_patterns):
            console.print("[dim]Matches your allowlist.[/dim]")
        else:
            is_danger, danger_reason = _static_danger_check(command)
            if is_danger:
                display_danger_warning(danger_reason)
                save_to_history(config, task_text, command, blocked=True)
                return
            if llm_safety:
                with console.status("[bold yellow]Safety check...", spinner="dots"):
                    risk, reason = engine.safety_check(command)
                display_risk_badge(risk, reason)
                if risk == "HIGH":
                    save_to_history(config, task_text, command, blocked=True)
                    return

        if explain_only or (config.shell.explain_commands and not no_explain and not dry_run):
            with console.status("[bold cyan]Explaining...", spinner="dots"):
                explanation = engine.explain_command(command)
            display_explanation(explanation)
            if explain_only:
                save_to_history(config, task_text, command)
                return

        if dry_run:
            console.print("\n[dim]Dry run — no execution.[/dim]")
            save_to_history(config, task_text, command)
            return

        if do_copy:
            if try_copy_to_clipboard(command):
                console.print("\n[green]Copied to clipboard.[/green]")
            else:
                console.print("\n[yellow]Clipboard unavailable:[/yellow]")
                console.print(command)
            save_to_history(config, task_text, command)
            return

        in_trusted = _is_trusted_dir(sec)
        while True:
            if do_exec or (in_trusted and not config.shell.confirm_before_execute):
                action = "execute"
                do_exec = False
            elif config.shell.confirm_before_execute:
                action = prompt_action_menu()
            else:
                save_to_history(config, task_text, command)
                return

            if action == "execute":
                rc, _, err = run_and_display(command, cur_shell, engine, task_text)
                save_to_history(config, task_text, command, executed=True, exit_code=rc)
                return
            elif action == "copy":
                if try_copy_to_clipboard(command):
                    console.print("[green]Copied to clipboard.[/green]")
                else:
                    console.print("[yellow]Clipboard unavailable:[/yellow]")
                    console.print(command)
                save_to_history(config, task_text, command)
                return
            elif action == "refine":
                try:
                    feedback = console.input("[bold cyan]How should I change it?[/bold cyan] ").strip()
                except (EOFError, KeyboardInterrupt):
                    console.print("\n[dim]Cancelled.[/dim]")
                    return
                if not feedback:
                    continue
                with console.status("[bold green]Refining...", spinner="dots"):
                    command, cmd_warnings = engine.refine_command(task_text, command, feedback)
                display_command(command, cur_shell, cmd_warnings)
                if not _is_allowlisted(command, sec.allowed_patterns):
                    is_danger, danger_reason = _static_danger_check(command)
                    if is_danger:
                        display_danger_warning(danger_reason)
                        save_to_history(config, task_text, command, blocked=True)
                        return
                if config.shell.explain_commands and not no_explain:
                    with console.status("[bold cyan]Explaining...", spinner="dots"):
                        explanation = engine.explain_command(command)
                    display_explanation(explanation)
            else:
                save_to_history(config, task_text, command)
                console.print("[dim]Skipped.[/dim]")
                return

    except ConnectionError as e:
        console.print(f"[bold red]Connection error:[/bold red] {e}")
    except RuntimeError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
    finally:
        engine.close()


@click.group(invoke_without_command=True)
@click.option("--version", "-v", is_flag=True, help="Show version.")
@click.pass_context
def cli(ctx, version):
    """O2Cli - AI-powered terminal command generator using local LLMs."""
    show_banner_if_first_run()
    if version:
        console.print(f"O2Cli v{__version__}")
        return
    if ctx.invoked_subcommand is None:
        if not CONFIG_FILE.exists():
            console.print("[yellow]No config found. Running setup wizard...[/yellow]\n")
            ctx.invoke(config_cmd, wizard=True)
        else:
            click.echo(ctx.get_help())


@cli.command("ask")
@click.argument("task", nargs=-1, required=False)
@click.option("--exec",         "-e", "do_exec",      is_flag=True, help="Execute immediately.")
@click.option("--no-explain",         is_flag=True,                 help="Skip explanation.")
@click.option("--explain-only",       is_flag=True,                 help="Show command + explanation only, never execute.")
@click.option("--dry-run",      "-d", is_flag=True,                 help="Show only, never execute.")
@click.option("--output",       "-o", "output_raw",   is_flag=True, help="Raw output for piping.")
@click.option("--copy",         "-c", "do_copy",      is_flag=True, help="Copy to clipboard.")
@click.option("--llm-safety",         is_flag=True,                 help="AI safety risk check.")
@click.option("--context",            default="",                   help="Context: git | ls | env | <text>.")
@click.option("--shell",        "-s", default=None,                 help="Override shell.")
@click.option("--model",        "-m", default=None,                 help="Override model.")
@click.option("--profile",      "-p", default=None,                 help="Use saved profile.")
@click.option("--no-history",         is_flag=True,                 help="Don't save to history.")
def ask(task, do_exec, no_explain, explain_only, dry_run, output_raw, do_copy,
        llm_safety, context, shell, model, profile, no_history):
    """Convert natural language TASK to a terminal command.

    \b
    TASK can also be piped via stdin:
        echo "list all python files" | o2cli ask
        echo "show disk usage" | o2cli ask --explain-only
    """
    config = load_config()
    if profile:    config = apply_profile(config, profile)
    if shell:      config.shell.preferred_shell = shell
    if model:      config.backend.model = model
    if no_history: config.shell.no_history = True

    # ── Resolve task from argument or stdin ───────────────────────────────
    task_text = " ".join(task).strip() if task else ""

    if not task_text:
        if not sys.stdin.isatty():
            task_text = sys.stdin.read().strip()
        if not task_text:
            console.print("[red]Error: No task provided. Pass a task as an argument or via stdin.[/red]")
            console.print("[dim]Example: o2cli ask \"list python files\"[/dim]")
            console.print("[dim]Example: echo \"list python files\" | o2cli ask[/dim]")
            sys.exit(1)

    if not output_raw:
        print_short_header()

    run_ask_flow(config, task_text, do_exec=do_exec, no_explain=no_explain,
                 explain_only=explain_only, dry_run=dry_run, output_raw=output_raw,
                 do_copy=do_copy, llm_safety=llm_safety, context_mode=context)


@cli.command("chat")
@click.option("--shell", "-s", default=None, help="Override shell.")
@click.option("--model", "-m", default=None, help="Override model.")
@click.option("--save",        default=None, help="Save session on exit.")
@click.option("--load",        default=None, help="Load a saved session.")
@click.option("--no-history",  is_flag=True, help="Don't save to history.")
def chat(shell, model, save, load, no_history):
    """Interactive AI chat with /ask and /run slash commands."""
    config = load_config()
    if shell:      config.shell.preferred_shell = shell
    if model:      config.backend.model = model
    if no_history: config.shell.no_history = True

    print_short_header()
    console.print("[dim]/ask <task>  /run <cmd>  /clear  /exit[/dim]\n")

    history: list[dict] = []

    if load:
        session_file = SESSIONS_DIR / f"{load}.json"
        if session_file.exists():
            try:
                history = json.loads(session_file.read_text())
                console.print(f"[dim]Session '{load}' loaded ({len(history)} messages).[/dim]\n")
            except Exception:
                console.print(f"[yellow]Could not load session '{load}'.[/yellow]\n")
        else:
            console.print(f"[yellow]Session '{load}' not found.[/yellow]\n")

    engine = LLMEngine(config)
    cur_shell = config.shell.preferred_shell if config.shell.preferred_shell != "auto" else get_default_shell()

    try:
        while True:
            try:
                user_input = console.input("[bold green]You:[/bold green] ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Goodbye![/dim]")
                break

            if not user_input:
                continue
            if user_input.lower() in ("/exit", "exit", "quit"):
                console.print("[dim]Goodbye![/dim]")
                break
            if user_input.lower() == "/clear":
                history.clear()
                console.print("[dim]Cleared.[/dim]\n")
                continue

            if user_input.lower().startswith("/ask "):
                slash_task = user_input[5:].strip()
                if slash_task:
                    with console.status("[bold green]Generating...", spinner="dots"):
                        cmd, cmd_warnings = engine.generate_command(slash_task)
                    display_command(cmd, cur_shell, cmd_warnings)
                    is_danger, reason = _static_danger_check(cmd)
                    if is_danger:
                        display_danger_warning(reason)
                    else:
                        try:
                            if Confirm.ask("Execute?", default=False):
                                run_and_display(cmd, cur_shell, engine, slash_task)
                        except (EOFError, KeyboardInterrupt):
                            pass
                    history.append({"role": "user", "content": user_input})
                    history.append({"role": "assistant", "content": f"Generated: {cmd}"})
                continue

            if user_input.lower().startswith("/run "):
                cmd = user_input[5:].strip()
                if cmd:
                    is_danger, reason = _static_danger_check(cmd)
                    if is_danger:
                        display_danger_warning(reason)
                    else:
                        display_command(cmd, cur_shell)
                        try:
                            if Confirm.ask("Execute this command?", default=False):
                                rc, out, err = run_and_display(cmd, cur_shell, engine)
                                combined = out + (f"\nSTDERR: {err}" if err else "")
                                history.append({"role": "user", "content": f"Ran: {cmd}"})
                                history.append({"role": "assistant",
                                                "content": f"Output:\n{combined[:1000]}"})
                            else:
                                console.print("[dim]Command not executed.[/dim]")
                        except (EOFError, KeyboardInterrupt):
                            console.print("[dim]Cancelled.[/dim]")
                continue

            history.append({"role": "user", "content": user_input})
            try:
                with console.status("[bold green]Thinking...", spinner="dots"):
                    reply = engine.chat(user_input, history[:-1])
                console.print(f"[bold cyan]AI:[/bold cyan] {reply}\n")
                history.append({"role": "assistant", "content": reply})
            except (ConnectionError, RuntimeError) as e:
                console.print(f"[bold red]Error:[/bold red] {e}")

    finally:
        engine.close()
        if save and history:
            SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
            session_file = SESSIONS_DIR / f"{save}.json"
            _secure_write_json(session_file, history)
            console.print(f"\n[dim]Session saved as '{save}'.[/dim]")


@cli.command("config")
@click.option("--provider",    "-p", type=click.Choice(["ollama", "lmstudio"]))
@click.option("--url",         "-u")
@click.option("--model",       "-m")
@click.option("--shell",       "-s", type=click.Choice(["auto", "powershell", "cmd", "bash", "zsh"]))
@click.option("--no-confirm",        is_flag=True)
@click.option("--no-explain",        is_flag=True)
@click.option("--show",        "show_cfg",    is_flag=True)
@click.option("--wizard",             is_flag=True)
@click.option("--reset",              is_flag=True,  help="Reset config to defaults.")
@click.option("--profile",            default=None,  help="Save/update a named profile.")
@click.option("--export",      "do_export", is_flag=True, help="Export full config bundle to stdout.")
@click.option("--import-file", "import_file", default=None, help="Import config bundle from file.")
@click.option("--allow",              default=None,  help="Add a command allow pattern.")
@click.option("--trust-dir",          default=None,  help="Mark a directory as trusted.")
def config_cmd(provider, url, model, shell, no_confirm, no_explain, show_cfg,
               wizard, reset, profile, do_export, import_file, allow, trust_dir):
    """View or change O2Cli configuration."""
    cfg = load_config()
    sec = load_security()

    if do_export:
        print(json.dumps(export_config_bundle(), indent=2))
        return

    if import_file:
        try:
            bundle = json.loads(Path(import_file).read_text())
            import_config_bundle(bundle)
            console.print(f"[green]Config imported from {import_file}.[/green]")
        except ValueError as e:
            console.print(f"[red]Import validation failed: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Import failed: {e}[/red]")
        return

    if reset:
        if Confirm.ask("Reset all configuration to defaults?", default=False):
            save_config(AppConfig())
            console.print("[green]Configuration reset to defaults.[/green]")
        return

    if allow:
        if allow == "*" or allow.strip() == "*":
            console.print("[red]Pattern '*' is too permissive — rejected.[/red]")
            return
        sec.allowed_patterns.append(allow)
        save_security(sec)
        console.print(f"[green]Allow pattern added: {allow}[/green]")
        return

    if trust_dir:
        trust_path = Path(trust_dir).resolve()
        if not trust_path.exists():
            console.print(f"[yellow]Warning: Directory '{trust_dir}' does not exist.[/yellow]")
            if not Confirm.ask("Add anyway?", default=False):
                return
        resolved = str(trust_path)
        if resolved not in sec.trusted_dirs:
            sec.trusted_dirs.append(resolved)
            save_security(sec)
            console.print(f"[green]Trusted directory: {resolved}[/green]")
        else:
            console.print(f"[dim]Already trusted: {resolved}[/dim]")
        return

    if wizard:
        console.print("\n[bold cyan]O2Cli Setup Wizard[/bold cyan]\n")
        detected = []
        for name, base_url in [("ollama", OLLAMA_DEFAULT_URL), ("lmstudio", LMSTUDIO_DEFAULT_URL)]:
            try:
                r = httpx.get(f"{base_url}/models", timeout=2.0)
                if r.status_code == 200:
                    models = [m["id"] for m in r.json().get("data", [])]
                    detected.append((name, base_url, models))
                    console.print(f"[green]✓[/green] {name} at {base_url}")
            except Exception:
                console.print(f"[dim]X {name} not reachable[/dim]")

        if not detected:
            console.print("\n[yellow]No backends detected. Use --provider to configure manually.[/yellow]")
            return

        chosen = detected[0]
        if len(detected) > 1:
            names = [d[0] for d in detected]
            pick = Prompt.ask("Which provider?", choices=names, default=names[0])
            chosen = next(d for d in detected if d[0] == pick)

        cfg.backend.provider = chosen[0]
        cfg.backend.base_url = chosen[1]
        if chosen[2]:
            for i, m in enumerate(chosen[2], 1):
                console.print(f"  {i}. {m}")
            cfg.backend.model = Prompt.ask("Model name", default=chosen[2][0])

        shell_default = get_default_shell()
        cfg.shell.preferred_shell = Prompt.ask(
            "Preferred shell",
            choices=["auto", "bash", "zsh", "powershell", "cmd"],
            default=shell_default if shell_default in ("bash", "zsh", "powershell", "cmd") else "auto",
        )
        cfg.shell.confirm_before_execute = Confirm.ask("Confirm before executing?", default=True)
        cfg.shell.explain_commands = Confirm.ask("Show explanations?", default=True)
        save_config(cfg)
        console.print("\n[bold green]Configuration saved![/bold green]")
        return

    if profile and any([provider, url, model]):
        profiles = load_profiles()
        entry = profiles.get(profile, {})
        for k, v in [("provider", provider), ("base_url", url), ("model", model)]:
            if v:
                if k == "base_url":
                    is_valid, err = validate_backend_url(v)
                    if not is_valid:
                        console.print(f"[red]URL rejected: {err}[/red]")
                        continue
                if k == "provider" and v not in ("ollama", "lmstudio"):
                    console.print(f"[red]Invalid provider: {v}[/red]")
                    continue
                entry[k] = v
        profiles[profile] = entry
        save_profiles(profiles)
        console.print(f"[green]Profile '{profile}' saved.[/green]")
        return

    if show_cfg or not any([provider, url, model, shell, no_confirm, no_explain]):
        t = Table(title="O2Cli Configuration")
        t.add_column("Setting", style="bold cyan")
        t.add_column("Value", style="green")
        for label, val in [
            ("Provider",             cfg.backend.provider),
            ("Base URL",             cfg.backend.base_url),
            ("Model",                cfg.backend.model or "(auto)"),
            ("Shell",                cfg.shell.preferred_shell),
            ("Confirm before exec",  str(cfg.shell.confirm_before_execute)),
            ("Explain commands",     str(cfg.shell.explain_commands)),
            ("No history",           str(cfg.shell.no_history)),
            ("Auto context",         str(cfg.shell.auto_context)),
            ("Temperature",          str(cfg.backend.temperature)),
            ("Config file",          str(CONFIG_FILE)),
        ]:
            t.add_row(label, val)
        console.print(t)

        if sec.trusted_dirs or sec.allowed_patterns:
            st = Table(title="Security Settings")
            st.add_column("Type", style="bold cyan")
            st.add_column("Value", style="yellow")
            for d in sec.trusted_dirs:
                st.add_row("Trusted dir", d)
            for p in sec.allowed_patterns:
                st.add_row("Allow pattern", p)
            console.print(st)

        profiles = load_profiles()
        if profiles:
            pt = Table(title="Saved Profiles")
            pt.add_column("Name", style="bold cyan")
            pt.add_column("Details", style="green")
            for name, vals in profiles.items():
                pt.add_row(name, json.dumps(vals))
            console.print(pt)

        active = {k: os.environ[k] for k in ("O2CLI_MODEL", "O2CLI_PROVIDER", "O2CLI_BASE_URL")
                  if k in os.environ}
        if active:
            console.print("\n[yellow]Active env overrides:[/yellow]")
            for k, v in active.items():
                console.print(f"  {k}={v}")
        return

    changed = False
    if provider:
        cfg.backend.provider = provider
        d = resolve_provider_defaults(provider)
        cfg.backend.base_url = d["base_url"]
        if not model and d["model"]: cfg.backend.model = d["model"]
        changed = True
    if url:
        is_valid, err = validate_backend_url(url)
        if not is_valid:
            console.print(f"[red]URL rejected: {err}[/red]")
            return
        cfg.backend.base_url = url
        changed = True
    if model:      cfg.backend.model = model;                changed = True
    if shell:      cfg.shell.preferred_shell = shell;        changed = True
    if no_confirm: cfg.shell.confirm_before_execute = False; changed = True
    if no_explain: cfg.shell.explain_commands = False;       changed = True
    if changed:
        save_config(cfg)
        console.print("[bold green]Configuration saved.[/bold green]")


@cli.command("history")
@click.option("--limit",  "-n", default=20)
@click.option("--clear",  "clear_hist", is_flag=True)
@click.option("--search", "-f", default=None)
@click.option("--rerun",  "-r", default=None, type=int)
@click.option("--copy",   "-y", default=None, type=int, help="Copy command #N to clipboard.")
@click.option("--star",         default=None, type=int, help="Toggle star on entry #N.")
@click.option("--starred",      is_flag=True,           help="Show only starred entries.")
@click.option("--stats",        is_flag=True,           help="Usage statistics.")
@click.option("--export", "export_fmt", type=click.Choice(["json", "csv"]), default=None)
def history_cmd(limit, clear_hist, search, rerun, copy, star, starred, stats, export_fmt):
    """View, search, star, re-run, copy, export, or analyse history."""
    if clear_hist:
        save_history([])
        console.print("[green]History cleared.[/green]")
        return

    entries = load_history()

    if star is not None:
        visible_start = max(0, len(entries) - limit)
        abs_idx = visible_start + (star - 1)
        if 0 <= abs_idx < len(entries):
            entries[abs_idx]["starred"] = not entries[abs_idx].get("starred", False)
            state = "starred" if entries[abs_idx]["starred"] else "unstarred"
            save_history(entries)
            console.print(f"[green]Entry #{star} {state}.[/green]")
        else:
            console.print(f"[red]No entry #{star}.[/red]")
        return

    if starred:
        entries = [e for e in entries if e.get("starred")]

    if search:
        kw = search.lower()
        entries = [e for e in entries
                   if kw in e.get("task", "").lower() or kw in e.get("command", "").lower()]

    if stats:
        from collections import Counter
        total    = len(entries)
        executed = sum(1 for e in entries if e.get("executed"))
        blocked  = sum(1 for e in entries if e.get("blocked"))
        top_cmds = Counter(
            e.get("command", "").split()[0] for e in entries if e.get("command")
        ).most_common(5)
        days: dict[str, int] = {}
        for e in entries:
            day = e.get("timestamp", "")[:10]
            if day: days[day] = days.get(day, 0) + 1

        t = Table(title="History Statistics")
        t.add_column("Metric", style="bold cyan")
        t.add_column("Value", style="green")
        t.add_row("Total",    str(total))
        t.add_row("Executed", str(executed))
        t.add_row("Blocked",  str(blocked))
        t.add_row("Skipped",  str(total - executed - blocked))
        console.print(t)

        if top_cmds:
            ct = Table(title="Top Commands")
            ct.add_column("Command", style="bold cyan")
            ct.add_column("Count",   style="green")
            for cmd, cnt in top_cmds:
                ct.add_row(cmd, str(cnt))
            console.print(ct)

        if days:
            dt = Table(title="Activity (last 7 days)")
            dt.add_column("Date",     style="bold cyan")
            dt.add_column("Commands", style="green")
            for day in sorted(days)[-7:]:
                dt.add_row(day, str(days[day]))
            console.print(dt)
        return

    if export_fmt == "json":
        print(json.dumps(entries, indent=2))
        return
    if export_fmt == "csv":
        buf = io.StringIO()
        fields = ["timestamp", "task", "command", "executed", "blocked", "shell", "exit_code"]
        w = csv.DictWriter(buf, fieldnames=fields)
        w.writeheader()
        for e in entries:
            w.writerow({k: e.get(k, "") for k in fields})
        print(buf.getvalue())
        return

    if copy is not None:
        visible = entries[-limit:]
        idx = copy - 1
        if idx < 0 or idx >= len(visible):
            console.print(f"[red]No entry #{copy} in last {limit}.[/red]")
            return
        cmd = visible[idx].get("command", "")
        if not cmd:
            console.print(f"[red]Entry #{copy} has no command.[/red]")
            return
        if try_copy_to_clipboard(cmd):
            console.print(f"[green]Copied to clipboard:[/green] [dim]{cmd[:80]}{'...' if len(cmd) > 80 else ''}[/dim]")
        else:
            console.print(f"[yellow]Clipboard unavailable. Command:[/yellow]\n{cmd}")
        return

    if rerun is not None:
        visible = entries[-limit:]
        idx = rerun - 1
        if idx < 0 or idx >= len(visible):
            console.print(f"[red]No entry #{rerun} in last {limit}.[/red]")
            return
        entry = visible[idx]
        cmd   = entry.get("command", "")
        sh    = entry.get("shell", get_default_shell())
        is_danger, reason = _static_danger_check(cmd)
        if is_danger:
            display_danger_warning(reason)
            console.print("[yellow]Refusing to re-run blocked/dangerous command.[/yellow]")
            return
        console.print(f"[dim]Re-running:[/dim] [green]{cmd}[/green]")
        run_and_display(cmd, sh)
        return

    if not entries:
        console.print("[dim]No history yet.[/dim]")
        return

    t = Table(title="Command History")
    t.add_column("#",       style="dim",    width=4)
    t.add_column("Star",    style="yellow", width=4)
    t.add_column("Time",    style="cyan",   width=19)
    t.add_column("Task",    style="white",  max_width=38)
    t.add_column("Command", style="green",  max_width=45)
    t.add_column("Status",  style="yellow")

    for i, e in enumerate(entries[-limit:], 1):
        star_mark = "*" if e.get("starred") else ""
        ts     = e.get("timestamp", "")[:19]
        task   = e.get("task", "")[:38]
        cmd    = e.get("command", "")[:45]
        status = "blocked" if e.get("blocked") else ("exec" if e.get("executed") else "skip")
        t.add_row(str(i), star_mark, ts, task, cmd, status)

    console.print(t)
    console.print("[dim]Tip: use --copy N to copy entry #N to clipboard[/dim]")


@cli.group("alias")
def alias():
    """Manage task aliases (with {template} variable support)."""
    pass


@alias.command("set")
@click.argument("name")
@click.argument("task", nargs=-1, required=True)
def alias_set(name, task):
    """Save an alias."""
    task_text = " ".join(task)
    _SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9_-]+$')
    if not _SAFE_NAME_RE.match(name):
        console.print(f"[red]Invalid alias name '{name}'. Use only alphanumeric, dash, underscore.[/red]")
        return
    aliases = load_aliases()
    aliases[name] = task_text
    save_aliases(aliases)
    console.print(f"[green]Alias '[bold]{name}[/bold]' saved.[/green]")


@alias.command("run")
@click.argument("name")
@click.option("--exec",    "-e", "do_exec", is_flag=True)
@click.option("--dry-run", "-d", is_flag=True)
@click.option("--copy",    "-c", "do_copy", is_flag=True)
def alias_run(name, do_exec, dry_run, do_copy):
    """Run a saved alias."""
    aliases = load_aliases()
    if name not in aliases:
        console.print(f"[red]Alias '{name}' not found.[/red]")
        return
    task_text = aliases[name]
    console.print(f"[dim]Alias '{name}' -> {task_text}[/dim]\n")
    config = load_config()
    print_short_header()
    run_ask_flow(config, task_text, do_exec=do_exec, dry_run=dry_run, do_copy=do_copy)


@alias.command("list")
def alias_list():
    """List all saved aliases."""
    aliases = load_aliases()
    if not aliases:
        console.print('[dim]No aliases. Use: o2cli alias set <name> "<task>"[/dim]')
        return
    t = Table(title="Saved Aliases")
    t.add_column("Name", style="bold cyan")
    t.add_column("Task", style="green")
    for name, task in aliases.items():
        t.add_row(name, task)
    console.print(t)


@alias.command("remove")
@click.argument("name")
def alias_remove(name):
    """Remove a saved alias."""
    aliases = load_aliases()
    if name not in aliases:
        console.print(f"[red]Alias '{name}' not found.[/red]")
        return
    del aliases[name]
    save_aliases(aliases)
    console.print(f"[green]Alias '{name}' removed.[/green]")


@cli.command("check")
def check():
    """Check connection to the configured LLM backend."""
    config = load_config()
    engine = LLMEngine(config)
    print_short_header()
    console.print(f"Provider : [bold]{config.backend.provider}[/bold]")
    console.print(f"Base URL : [bold]{config.backend.base_url}[/bold]")
    console.print(f"Model    : [bold]{config.backend.model or '(auto)'}[/bold]\n")
    with console.status("[bold green]Connecting...", spinner="dots"):
        ok, message = engine.check_connection()
    icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
    console.print(f"{icon} {message}")
    engine.close()


@cli.command("doctor")
def doctor():
    """Full diagnostic checklist."""
    print_short_header()
    console.print("\n[bold cyan]O2Cli Diagnostics[/bold cyan]\n")

    checks: list[tuple[str, bool, str]] = []

    vi = sys.version_info
    checks.append(("Python >= 3.10", vi.major == 3 and vi.minor >= 10,
                   f"{vi.major}.{vi.minor}.{vi.micro}"))

    for mod, spec in REQUIRED_PACKAGES.items():
        try:
            __import__(mod)
            checks.append((f"Package: {mod}", True, "installed"))
        except ImportError:
            checks.append((f"Package: {mod}", False, f"MISSING — pip install {spec}"))

    checks.append(("Config file exists", CONFIG_FILE.exists(), str(CONFIG_FILE)))

    cfg_valid = True
    cfg = None
    try:
        cfg = load_config()
    except Exception:
        cfg_valid = False
    checks.append(("Config file valid", cfg_valid,
                   "" if cfg_valid else "Corrupted — run: o2cli config --reset"))

    hist_ok = True
    try:
        load_history()
    except Exception:
        hist_ok = False
    checks.append(("History readable", hist_ok, str(HISTORY_FILE)))

    for fpath, label in [(CONFIG_FILE, "Config"), (HISTORY_FILE, "History"),
                         (SECURITY_FILE, "Security")]:
        if fpath.exists():
            try:
                mode = oct(os.stat(fpath).st_mode & 0o777)
                perms_ok = mode in ("0o600", "0o400")
                checks.append((f"{label} file permissions", perms_ok,
                               f"{mode} {'(secure)' if perms_ok else '(should be 0o600)'}"))
            except Exception:
                pass

    backend_ok, backend_msg = False, "N/A"
    if cfg:
        engine = LLMEngine(cfg)
        backend_ok, backend_msg = engine.check_connection()
        engine.close()
    checks.append(("Backend reachable", backend_ok, backend_msg))

    model_ok = backend_ok and cfg and bool(cfg.backend.model)
    checks.append(("Model configured", model_ok, cfg.backend.model if cfg else ""))

    clip_ok = True
    try:
        pyperclip.copy("")
    except Exception:
        clip_ok = False
    checks.append(("Clipboard available", clip_ok,
                   "" if clip_ok else "May need xclip or xsel on Linux"))

    t = Table(show_header=True)
    t.add_column("Check",  style="bold cyan")
    t.add_column("",       width=3)
    t.add_column("Detail", style="dim")
    for label, ok, detail in checks:
        t.add_row(label, "[green]✓[/green]" if ok else "[red]✗[/red]", detail)
    console.print(t)

    failures = [l for l, ok, _ in checks if not ok]
    if not failures:
        console.print("\n[bold green]All checks passed![/bold green]")
    else:
        console.print(f"\n[bold red]{len(failures)} check(s) failed.[/bold red]")


@cli.command("completion")
@click.argument("shell_name", type=click.Choice(["bash", "zsh", "fish"]))
def completion(shell_name):
    """Print shell completion script."""
    try:
        prog_name = APP_NAME
        if shell_name == "bash":
            script = (
                f'_o2cli_completion() {{\n'
                f'  local IFS=$\'\\n\'\n'
                f'  COMPREPLY=($(COMP_WORDS="${{COMP_WORDS[*]}}" '
                f'COMP_CWORD=$COMP_CWORD '
                f'OPTPARSE_AUTO_COMPLETE=1 $1))\n'
                f'}}\n'
                f'complete -F _o2cli_completion {prog_name}\n'
            )
        elif shell_name == "zsh":
            script = (
                f'#compdef {prog_name}\n'
                f'_o2cli() {{\n'
                f'  local -a commands\n'
                f'  commands=(\n'
                f'    \'ask:Convert natural language to terminal command\'\n'
                f'    \'chat:Interactive AI chat\'\n'
                f'    \'config:View or change configuration\'\n'
                f'    \'history:View command history\'\n'
                f'    \'alias:Manage task aliases\'\n'
                f'    \'check:Check backend connection\'\n'
                f'    \'doctor:Full diagnostic\'\n'
                f'    \'completion:Print completion script\'\n'
                f'  )\n'
                f'  _describe \'command\' commands\n'
                f'}}\n'
                f'compdef _o2cli {prog_name}\n'
            )
        elif shell_name == "fish":
            script = (
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'ask\' -d \'Convert natural language to terminal command\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'chat\' -d \'Interactive AI chat\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'config\' -d \'View or change configuration\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'history\' -d \'View command history\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'alias\' -d \'Manage task aliases\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'check\' -d \'Check backend connection\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'doctor\' -d \'Full diagnostic\'\n'
                f'complete -c {prog_name} -n \'__fish_use_subcommand\' -a \'completion\' -d \'Print completion script\'\n'
            )
        else:
            script = f"# Completion not available for {shell_name}\n"
        print(script)
    except Exception as e:
        console.print(f"[red]Completion generation failed: {e}[/red]")


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)
