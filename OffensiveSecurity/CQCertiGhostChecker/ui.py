"""
UI module for CQCertiGhostChecker — banner, colors, dependency check, formatted output.
"""

import importlib
import logging
import os
import shutil
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[38;5;82m"
RED = "\033[38;5;196m"
ORANGE = "\033[38;5;214m"
DARK_ORANGE = "\033[38;5;208m"
DARK_RED = "\033[38;5;160m"
YELLOW = "\033[38;5;220m"
GRAY = "\033[38;5;240m"
WHITE = "\033[38;5;255m"

_no_color = False


def set_no_color(value: bool):
    global _no_color
    _no_color = value


def _c(color, text):
    if _no_color:
        return text
    return f"{color}{text}{RESET}"


BANNER_LINES = [
    r" ██████╗  ██████╗     ██████╗███████╗██████╗ ████████╗██╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗",
    r"██╔════╝ ██╔═══██╗   ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝",
    r"██║      ██║   ██║   ██║     █████╗  ██████╔╝   ██║   ██║██║  ███╗███████║██║   ██║███████╗   ██║   ",
    r"██║      ██║▄▄ ██║   ██║     ██╔══╝  ██╔══██╗   ██║   ██║██║   ██║██╔══██║██║   ██║╚════██║   ██║   ",
    r"╚██████╗ ╚██████╔╝   ╚██████╗███████╗██║  ██║   ██║   ██║╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ",
    r" ╚═════╝  ╚══▀▀═╝    ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ",
    r"",
    r"         ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ",
    r"        ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗",
    r"        ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝",
    r"        ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗",
    r"        ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║",
    r"         ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝",
]

GRADIENT = [214, 214, 208, 208, 202, 196, 196, 160, 160, 124, 124, 124, 124]


def print_banner():
    out = sys.stderr
    for i, line in enumerate(BANNER_LINES):
        color_code = GRADIENT[i % len(GRADIENT)]
        if _no_color:
            out.write(line + "\n")
        else:
            out.write(f"\033[38;5;{color_code}m{line}{RESET}\n")
    out.write("\n")
    tagline = "CQCertiGhostChecker  CVE-2026-54121  |  CQURE Academy  |  For authorized testing only"
    out.write(_c(DARK_ORANGE, tagline) + "\n\n")
    out.flush()


DEPENDENCIES = [
    ("ldap3", "module", "ldap3", "pip install ldap3"),
    ("impacket", "module", "impacket", "pip install impacket"),
    ("impacket-full", "binary", "impacket-secretsdump", "pip install impacket"),
    ("pycryptodome", "module", "Crypto", "pip install pycryptodome"),
    ("certipy-ad", "binary", "certipy-ad", "pip install certipy-ad"),
    ("cryptography", "module", "cryptography", "pip install cryptography"),
    ("pyasn1", "module", "pyasn1", "pip install pyasn1"),
]


def check_dependencies(mode="attack"):
    out = sys.stderr
    header = f" Dependency Check ({mode.title()} Mode) "
    pad = 70 - len(header)
    left = pad // 2
    right = pad - left
    out.write("\n" + _c(GRAY, "─" * left + header + "─" * right) + "\n")

    all_ok = True
    for name, kind, target, install_hint in DEPENDENCIES:
        available = False
        if kind == "module":
            try:
                importlib.import_module(target)
                available = True
            except ImportError:
                pass
        elif kind == "binary":
            available = shutil.which(target) is not None

        status_tag = _c(GREEN, "[+]") if available else _c(RED, "[-]")
        status_text = _c(GREEN, "available") if available else _c(RED, f"MISSING ({install_hint})")
        out.write(f"{status_tag} {name:<18s} {status_text}\n")

        if not available:
            all_ok = False

    out.write("\n")
    out.flush()
    return all_ok


def print_step(num, total, title):
    out = sys.stderr
    header = f" Step {num}/{total}: {title} "
    pad = 70 - len(header)
    left = 2
    right = max(pad - left, 2)
    out.write("\n" + _c(f"{BOLD}\033[38;5;208m", "─" * left + header + "─" * right) + "\n")
    out.flush()


def print_success(msg):
    sys.stderr.write(_c(GREEN, f"[+] {msg}") + "\n")
    sys.stderr.flush()


def print_fail(msg):
    sys.stderr.write(_c(RED, f"[-] {msg}") + "\n")
    sys.stderr.flush()


def print_info(msg):
    sys.stderr.write(_c(ORANGE, f"[*] {msg}") + "\n")
    sys.stderr.flush()


def print_warning(msg):
    sys.stderr.write(_c(YELLOW, f"[!] {msg}") + "\n")
    sys.stderr.flush()


def print_config(config):
    out = sys.stderr
    out.write("\n" + _c(GRAY, "─" * 2 + " Configuration " + "─" * 53) + "\n")
    fields = [
        ("Domain", config.domain),
        ("Username", config.username),
        ("DC IP", config.dc_ip),
        ("CA Name", config.ca_name or "auto-discover"),
        ("CA IP", config.ca_ip or "same as DC"),
        ("Template", config.template),
        ("Target DC", config.target_dc or "auto"),
        ("Machine Acct", config.machine_account_name),
        ("Rogue SMB", "445"),
        ("Rogue LDAP", str(config.ldap_port)),
        ("Output", config.output_file),
    ]
    for label, value in fields:
        out.write(f"  {_c(WHITE, label + ':')} {' ' * (14 - len(label))}{_c(DARK_ORANGE, value)}\n")
    out.write("\n")
    out.flush()


def print_summary(results):
    out = sys.stderr
    out.write("\n")
    out.write(_c(f"{BOLD}\033[38;5;82m", "═" * 70) + "\n")
    out.write(_c(f"{BOLD}\033[38;5;82m", "  ATTACK COMPLETE") + "\n")
    out.write(_c(f"{BOLD}\033[38;5;82m", "═" * 70) + "\n")
    fields = [
        ("Credential Cache", results.get("ccache", "?")),
        ("Impersonated DC", results.get("dc", "?")),
        ("krbtgt hash", results.get("krbtgt", "?")),
        ("Administrator", results.get("administrator", "?")),
        ("Accounts dumped", str(results.get("total_accounts", "?"))),
        ("Elapsed", results.get("elapsed", "?")),
    ]
    for label, value in fields:
        out.write(f"  {_c(WHITE, label + ':')} {' ' * (18 - len(label))}{_c(GREEN, value)}\n")
    out.write(_c(f"{BOLD}\033[38;5;82m", "═" * 70) + "\n\n")
    out.flush()


class ColoredLogHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        if _no_color:
            sys.stderr.write(msg + "\n")
            sys.stderr.flush()
            return

        if record.levelno <= logging.DEBUG:
            sys.stderr.write(f"{GRAY}{msg}{RESET}\n")
        elif record.levelno >= logging.ERROR:
            sys.stderr.write(f"{RED}{msg}{RESET}\n")
        else:
            stripped = msg.lstrip()
            if stripped.startswith("[+]"):
                sys.stderr.write(f"{GREEN}{msg}{RESET}\n")
            elif stripped.startswith("[-]"):
                sys.stderr.write(f"{RED}{msg}{RESET}\n")
            elif stripped.startswith("[*]"):
                sys.stderr.write(f"{ORANGE}{msg}{RESET}\n")
            elif stripped.startswith("[!]"):
                sys.stderr.write(f"{YELLOW}{msg}{RESET}\n")
            else:
                sys.stderr.write(f"{WHITE}{msg}{RESET}\n")
        sys.stderr.flush()


def setup_logging(verbose=False, no_color=False, log_file=None):
    set_no_color(no_color)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = ColoredLogHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S"))
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(handler)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        fh.setLevel(logging.DEBUG)
        root.addHandler(fh)
