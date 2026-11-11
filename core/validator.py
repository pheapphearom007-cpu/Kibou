"""
Input Validation and Security Sanitization for Kibuo.

Provides strict defense-in-depth validation for IP addresses, CIDR blocks,
domain names, port specifications, and network interface names to prevent
command injection, argument injection, and invalid operational execution.
"""

import ipaddress
import re
from typing import Optional, Tuple, Union


# RFC 1123 compliant domain regex
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# Common interface naming convention (Linux: eth0, wlan0, ens33, enp0s3, tun0, br0, etc.)
INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,16}$")

# Dangerous shell metacharacters that must never appear in unescaped user inputs
DANGEROUS_CHARS = set(";&|`$><\\!{}[]\"'\n\r\t")


class ValidationError(ValueError):
    """Raised when an input fails security validation checks."""
    pass


def contains_dangerous_characters(text: str) -> bool:
    """Check if input text contains dangerous shell metacharacters."""
    if not isinstance(text, str):
        return True
    return any(char in DANGEROUS_CHARS for char in text)


def validate_ipv4(ip_str: str) -> ipaddress.IPv4Address:
    """
    Validate and return a standard IPv4 address.
    
    Raises:
        ValidationError: If the input is not a valid IPv4 address.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValidationError("IP address cannot be empty.")
    
    cleaned = ip_str.strip()
    if contains_dangerous_characters(cleaned):
        raise ValidationError(f"Invalid characters detected in IP address: '{cleaned}'")
    
    try:
        addr = ipaddress.IPv4Address(cleaned)
        return addr
    except ipaddress.AddressValueError as err:
        raise ValidationError(f"Invalid IPv4 address format: '{cleaned}' ({err})") from err


def validate_cidr(cidr_str: str) -> ipaddress.IPv4Network:
    """
    Validate and return an IPv4 CIDR network range.
    
    Raises:
        ValidationError: If the input is not a valid IPv4 network.
    """
    if not cidr_str or not isinstance(cidr_str, str):
        raise ValidationError("CIDR range cannot be empty.")
    
    cleaned = cidr_str.strip()
    if contains_dangerous_characters(cleaned):
        raise ValidationError(f"Invalid characters detected in CIDR range: '{cleaned}'")
    
    try:
        # strict=False allows host bits to be set e.g. 192.168.1.5/24 -> 192.168.1.0/24
        net = ipaddress.IPv4Network(cleaned, strict=False)
        return net
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
        raise ValidationError(f"Invalid IPv4 CIDR format: '{cleaned}' ({err})") from err


def validate_domain(domain_str: str) -> str:
    """
    Validate a fully qualified or relative domain name (RFC 1123).
    
    Raises:
        ValidationError: If the domain name is invalid or contains malicious characters.
    """
    if not domain_str or not isinstance(domain_str, str):
        raise ValidationError("Domain name cannot be empty.")
    
    cleaned = domain_str.strip().lower()
    if contains_dangerous_characters(cleaned):
        raise ValidationError(f"Invalid characters detected in domain name: '{cleaned}'")
    
    if len(cleaned) > 253:
        raise ValidationError("Domain name exceeds maximum length of 253 characters.")
        
    if not DOMAIN_REGEX.match(cleaned):
        raise ValidationError(f"Invalid domain name format: '{cleaned}'")

    # Under RFC 3696 and ICANN standards, TLD cannot be purely numeric,
    # and all-numeric dotted strings are IP attempts rather than domains.
    if re.match(r"^[\d\.]+$", cleaned):
        raise ValidationError(f"Invalid domain name: numeric address '{cleaned}' is not a valid domain.")

    labels = cleaned.rstrip(".").split(".")
    if len(labels) > 1 and labels[-1].isdigit():
        raise ValidationError(f"Invalid domain name: top-level domain '{labels[-1]}' cannot be purely numeric.")
        
    return cleaned


def validate_target(target_str: str) -> Tuple[str, str]:
    """
    Determine and validate target type: 'ipv4', 'cidr', or 'domain'.
    
    Returns:
        Tuple of (target_type, validated_target_string)
        
    Raises:
        ValidationError: If target cannot be validated as any acceptable type.
    """
    if not target_str or not isinstance(target_str, str):
        raise ValidationError("Target cannot be empty.")
        
    cleaned = target_str.strip()
    if contains_dangerous_characters(cleaned):
        raise ValidationError(f"Target contains forbidden characters: '{cleaned}'")
    
    # Check if target starts with '-' to prevent command-line option injection (e.g. -oX)
    if cleaned.startswith("-"):
        raise ValidationError("Target cannot begin with a dash ('-') to avoid option injection.")

    # 1. Check if CIDR
    if "/" in cleaned:
        net = validate_cidr(cleaned)
        return ("cidr", str(net))
        
    # 2. Check if IPv4 or IP-like format (purely numeric octets and dots)
    if re.match(r"^[\d\.]+$", cleaned):
        ip = validate_ipv4(cleaned)
        return ("ipv4", str(ip))
        
    # 3. Check if Domain
    try:
        domain = validate_domain(cleaned)
        return ("domain", domain)
    except ValidationError:
        pass
        
    raise ValidationError(
        f"Target '{cleaned}' is not a valid IPv4 address, CIDR subnet, or domain name."
    )


def validate_port_specification(ports_str: str) -> str:
    """
    Validate a port or port list/range specification (e.g., '80', '80,443', '1-1024', 'top100').
    
    Raises:
        ValidationError: If the port specification is invalid.
    """
    if not ports_str or not isinstance(ports_str, str):
        raise ValidationError("Port specification cannot be empty.")
        
    cleaned = ports_str.strip()
    if contains_dangerous_characters(cleaned):
        raise ValidationError(f"Invalid characters in port specification: '{cleaned}'")
        
    if cleaned.lower() in ("-", "all", "1-65535"):
        return "1-65535"
        
    parts = cleaned.split(",")
    for part in parts:
        part = part.strip()
        if "-" in part:
            sub = part.split("-")
            if len(sub) != 2:
                raise ValidationError(f"Invalid port range syntax: '{part}'")
            try:
                start_p, end_p = int(sub[0]), int(sub[1])
                if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
                    raise ValidationError(f"Port range out of bounds [1-65535]: '{part}'")
            except ValueError:
                raise ValidationError(f"Non-numeric port range: '{part}'")
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValidationError(f"Port number out of bounds [1-65535]: {p}")
            except ValueError:
                raise ValidationError(f"Non-numeric port: '{part}'")
                
    return cleaned


def validate_interface_name(iface_str: str) -> str:
    """
    Validate a Linux network interface name.
    
    Raises:
        ValidationError: If interface name is malformed.
    """
    if not iface_str or not isinstance(iface_str, str):
        raise ValidationError("Interface name cannot be empty.")
        
    cleaned = iface_str.strip()
    if not INTERFACE_REGEX.match(cleaned):
        raise ValidationError(f"Invalid network interface name: '{cleaned}'")
        
    return cleaned


def is_private_ip(ip_str: str) -> bool:
    """
    Determine if an IPv4 address belongs to a private, loopback, or link-local range.
    """
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except Exception:
        return False
