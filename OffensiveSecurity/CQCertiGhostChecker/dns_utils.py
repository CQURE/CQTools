import socket
import logging

logger = logging.getLogger(__name__)


def ensure_dc_resolves(dc_fqdn: str, dc_ip: str) -> str:
    """
    Check if dc_fqdn resolves to dc_ip. If not, add or update /etc/hosts.
    Returns dc_fqdn.
    """
    try:
        resolved = socket.gethostbyname(dc_fqdn)
        if resolved == dc_ip:
            return dc_fqdn
        logger.warning(f"{dc_fqdn} resolves to {resolved}, expected {dc_ip} — updating /etc/hosts")
        _update_hosts_entry(dc_fqdn, dc_ip)
        return dc_fqdn
    except socket.gaierror:
        _update_hosts_entry(dc_fqdn, dc_ip)
        return dc_fqdn


def _update_hosts_entry(fqdn: str, ip: str):
    """Add or update entry in /etc/hosts."""
    try:
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()

        short = fqdn.split(".")[0]
        new_entry = f"{ip} {fqdn} {short}\n"
        updated = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if fqdn in stripped:
                lines[i] = new_entry
                updated = True
                break

        if not updated:
            lines.append(new_entry)

        with open("/etc/hosts", "w") as f:
            f.writelines(lines)
        logger.info(f"Updated /etc/hosts: {new_entry.strip()}")
    except PermissionError:
        logger.warning(f"No permission for /etc/hosts. Add manually: {ip} {fqdn}")


def remove_hosts_entry(fqdn: str):
    """Remove entry for fqdn from /etc/hosts (cleanup)."""
    try:
        with open("/etc/hosts", "r") as f:
            lines = f.readlines()

        original_count = len(lines)
        lines = [l for l in lines if fqdn not in l]

        if len(lines) < original_count:
            with open("/etc/hosts", "w") as f:
                f.writelines(lines)
            logger.info(f"Removed {fqdn} from /etc/hosts")
    except PermissionError:
        logger.debug(f"Cannot clean /etc/hosts (no permission)")
    except Exception:
        pass
