#!/usr/bin/env python3
"""
Local SIP Registration Test Script for Siedle Integration.

This script tests the SIP registration with Siedle servers directly,
bypassing Home Assistant to isolate and debug SIP issues.
"""
import socket
import ssl
import hashlib
import uuid
import re
import time
import sys
import os
import requests
from requests_oauthlib import OAuth2Session

# Siedle API base URL
BASE_URL = "https://sus2.siedle.com/sus2"

# Config from HA
CONFIG = {
    "endpoint_id": "0e48a755-e4d0-4ee2-9e86-5ae6c0d7a00d",
    "setup_data": "d06bb3eef2858efeb3a9efdce86aa8c3ce5b0ef62fc58b5331dda6ceaf2bc1147b786592be79de242cfb6eec29de61b4",
    "setup_info": {
        "endpointSetupKey": "971f82064a6b3e731c8f3e115589415504d48aa9f8169c05b034b2b4b5e3a4e2",
        "endpointTransferSecret": "cb6cc4b3755f10123ef9601ce5264cd9e7742259b8f9db2c5b9a35e12108a301",
        "susUrl": "https://sus2.siedle.com/"
    },
    "shared_secret": "28957d35b4b23f2c487f447b726ba60087c61568e9f9ba10d2d2d1c39cbca24e",
    "token": {
        "access_token": "cea3023b-2f9a-4f7a-a83e-a560c17ef8cc",
        "expires_at": 1770302676.2821956,
        "expires_in": "-30",
        "refresh_token": "a5bb83e7-4ae4-40c0-8a07-49a28b4dd97f",
        "scope": "read write",
        "token_type": "bearer"
    },
    "transfer_secret": "cb6cc4b3755f10123ef9601ce5264cd9e7742259b8f9db2c5b9a35e12108a301"
}


def get_local_ip():
    """Get local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.100"


def compute_digest(username, password, realm, nonce, method, uri):
    """Compute Digest authentication response."""
    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return response


def create_register(sip_config, cseq, call_id, from_tag, local_ip, local_port=5060, 
                    with_auth=False, realm=None, nonce=None):
    """Create SIP REGISTER message."""
    username = sip_config['username']
    host = sip_config['host']
    uri = f"sip:{host}"
    branch = uuid.uuid4().hex[:8]
    
    lines = [
        f"REGISTER {uri} SIP/2.0",
        f"Via: SIP/2.0/TLS {local_ip}:{local_port};rport;branch=z9hG4bK-{branch}",
        "Max-Forwards: 70",
        f"From: <sip:{username}@{host}>;tag={from_tag}",
        f"To: <sip:{username}@{host}>",
        f"Call-ID: {call_id}@{local_ip}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{username}@{local_ip}:{local_port};transport=tls>",
        "User-Agent: Siedle-HA/1.0",
        "Expires: 3600",
        "Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, MESSAGE, OPTIONS, INFO, SUBSCRIBE",
    ]
    
    if with_auth and realm and nonce:
        response = compute_digest(
            username=username,
            password=sip_config['password'],
            realm=realm,
            nonce=nonce,
            method="REGISTER",
            uri=uri
        )
        lines.append(
            f'Authorization: Digest username="{username}", '
            f'realm="{realm}", '
            f'nonce="{nonce}", '
            f'uri="{uri}", '
            f'response="{response}", '
            f'algorithm=MD5'
        )
    
    lines.append("Content-Length: 0")
    lines.append("")
    lines.append("")
    
    return "\r\n".join(lines).encode('utf-8')


def parse_sip_response(data):
    """Parse SIP response."""
    try:
        text = data.decode('utf-8', errors='replace')
        lines = text.split('\r\n')
        
        result = {
            "raw": text,
            "status_line": lines[0] if lines else "",
            "status_code": 0,
            "method": None,
            "headers": {},
        }
        
        if lines and lines[0].startswith("SIP/2.0"):
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2:
                result["status_code"] = int(parts[1])
        elif lines:
            parts = lines[0].split(" ")
            result["method"] = parts[0]
        
        for line in lines[1:]:
            if line == "":
                break
            if ":" in line:
                name, value = line.split(":", 1)
                result["headers"][name.strip()] = value.strip()
        
        return result
    except Exception as e:
        print(f"Error parsing SIP: {e}")
        return {"error": str(e)}


def test_sip_registration(sip_config):
    """Test SIP registration with Siedle server."""
    print("\n" + "="*60)
    print("SIP Registration Test")
    print("="*60)
    
    host = sip_config['host']
    port = sip_config['port']
    username = sip_config['username']
    
    print(f"\nServer: {host}:{port}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(sip_config['password'])}")
    
    local_ip = get_local_ip()
    print(f"Local IP: {local_ip}")
    
    # Generate consistent identifiers
    call_id = str(uuid.uuid4())
    from_tag = uuid.uuid4().hex[:8]
    cseq = 1
    
    print(f"\nCall-ID: {call_id}")
    print(f"From-Tag: {from_tag}")
    
    # Connect with TLS
    print(f"\n[1] Connecting to {host}:{port} (TLS)...")
    try:
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        print("    ✓ TLS connection established")
    except Exception as e:
        print(f"    ✗ Connection failed: {e}")
        return False
    
    # Send initial REGISTER (expect 401)
    print(f"\n[2] Sending initial REGISTER (CSeq: {cseq})...")
    register_msg = create_register(sip_config, cseq, call_id, from_tag, local_ip)
    print(f"    Request:\n{register_msg.decode()[:500]}...")
    
    ssl_sock.send(register_msg)
    
    response = ssl_sock.recv(4096)
    parsed = parse_sip_response(response)
    
    print(f"\n    Response: {parsed.get('status_code')} {parsed.get('status_line', '').split(' ', 2)[-1] if parsed.get('status_line') else ''}")
    print(f"    Headers: {list(parsed.get('headers', {}).keys())}")
    
    if parsed.get("status_code") != 401:
        if parsed.get("status_code") == 200:
            print("    ✓ Registration successful (no auth needed)!")
            return True
        else:
            print(f"    ✗ Unexpected response: {parsed.get('status_code')}")
            print(f"    Raw: {parsed.get('raw', '')[:500]}")
            return False
    
    # Extract auth parameters
    www_auth = parsed.get("headers", {}).get("WWW-Authenticate", "")
    print(f"\n    WWW-Authenticate: {www_auth}")
    
    realm_match = re.search(r'realm="([^"]+)"', www_auth)
    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
    
    if not realm_match or not nonce_match:
        print(f"    ✗ Could not extract realm/nonce from auth header!")
        return False
    
    realm = realm_match.group(1)
    nonce = nonce_match.group(1)
    print(f"    Realm: {realm}")
    print(f"    Nonce: {nonce[:30]}...")
    
    # Send authenticated REGISTER
    cseq += 1
    print(f"\n[3] Sending authenticated REGISTER (CSeq: {cseq})...")
    
    auth_register = create_register(
        sip_config, cseq, call_id, from_tag, local_ip,
        with_auth=True, realm=realm, nonce=nonce
    )
    print(f"    Request:\n{auth_register.decode()[:800]}...")
    
    ssl_sock.send(auth_register)
    
    response = ssl_sock.recv(4096)
    parsed = parse_sip_response(response)
    
    print(f"\n    Response: {parsed.get('status_code')} {parsed.get('status_line', '').split(' ', 2)[-1] if parsed.get('status_line') else ''}")
    
    if parsed.get("status_code") == 200:
        print("\n    ✓ Registration SUCCESSFUL!")
        
        # Now listen for incoming INVITE
        print("\n[4] Listening for incoming INVITE (doorbell)...")
        print("    Press Ctrl+C to stop or ring the doorbell...")
        
        ssl_sock.setblocking(False)
        
        try:
            while True:
                try:
                    data = ssl_sock.recv(4096)
                    if data:
                        parsed = parse_sip_response(data)
                        method = parsed.get("method")
                        
                        if method == "INVITE":
                            print(f"\n    🔔 INVITE received! DOORBELL!")
                            print(f"    From: {parsed.get('headers', {}).get('From', 'unknown')}")
                            print(f"    Call-ID: {parsed.get('headers', {}).get('Call-ID', 'unknown')}")
                        elif method:
                            print(f"\n    Received: {method}")
                
                except ssl.SSLWantReadError:
                    pass
                except BlockingIOError:
                    pass
                
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n    Stopped listening.")
        
        return True
    else:
        print(f"\n    ✗ Registration FAILED: {parsed.get('status_code')}")
        print(f"    Response: {parsed.get('raw', '')[:500]}")
        return False


def main():
    print("Siedle SIP Local Test")
    print("=====================")
    
    # Check if SIP credentials provided as arguments
    if len(sys.argv) >= 5:
        sip_config = {
            "host": sys.argv[1],
            "port": int(sys.argv[2]),
            "username": sys.argv[3],
            "password": sys.argv[4],
        }
        print(f"\n[0] Using SIP credentials from command line")
        print(f"    Host: {sip_config['host']}")
        print(f"    Port: {sip_config['port']}")
        print(f"    Username: {sip_config['username']}")
        print(f"    Password: {'*' * len(sip_config['password'])}")
        
        # Test SIP registration
        test_sip_registration(sip_config)
        return
    
    # Otherwise try to get from Siedle API
    print("\n[0] Initializing Siedle API...")
    print("\nUsage: python test_sip_local.py <host> <port> <username> <password>")
    print("Example: python test_sip_local.py sus2-sip.siedle.com 5061 user@example.com mypassword")
    print("\nTo get the SIP credentials, check Home Assistant logs with debug enabled:")
    print("  Look for: 'SIP config loaded: host=... port=... username=...'")
    print("\nOr add this to configuration.yaml:")
    print("  logger:")
    print("    logs:")
    print("      custom_components.siedle: debug")
    print("      custom_components.siedle.sip_manager: debug")


if __name__ == "__main__":
    main()
