import socket
import argparse
import logging
import requests
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def probe_http(host, port):
    """
    Probes an HTTP service.
    
    Args:
        host (str): The hostname or IP address.
        port (int): The port number.

    Returns:
        str: Service information if identified, None otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)  # Set a timeout for the connection
            s.connect((host, port))

            # Send a simple HTTP GET request
            request = b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n"
            s.sendall(request)
            response = s.recv(4096)
            
            response_str = response.decode('utf-8', errors='ignore')  # Decode response

            if "HTTP" in response_str:
                if "Server:" in response_str:
                    server_info = response_str.split("Server:")[1].split("\r\n")[0].strip()
                    return f"HTTP Server: {server_info}"
                else:
                    return "HTTP Server (no version info)"
            else:
                return None

    except socket.timeout:
        logging.warning(f"Connection to {host}:{port} timed out.")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused by {host}:{port}.")
        return None
    except Exception as e:
        logging.error(f"Error probing HTTP on {host}:{port}: {e}")
        return None


def probe_ssh(host, port):
    """
    Probes an SSH service.

    Args:
        host (str): The hostname or IP address.
        port (int): The port number.

    Returns:
        str: Service information if identified, None otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()  # Receive the SSH banner

            if "SSH-" in banner:
                return f"SSH Server: {banner}"
            else:
                return None

    except socket.timeout:
        logging.warning(f"Connection to {host}:{port} timed out.")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused by {host}:{port}.")
        return None
    except Exception as e:
        logging.error(f"Error probing SSH on {host}:{port}: {e}")
        return None

def probe_smtp(host, port):
    """
    Probes an SMTP service.

    Args:
        host (str): The hostname or IP address.
        port (int): The port number.

    Returns:
        str: Service information if identified, None otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((host, port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()

            if "220" in banner:  # SMTP banner usually starts with 220
                s.sendall(b"EHLO example.com\r\n")
                ehlo_response = s.recv(1024).decode('utf-8', errors='ignore').strip()
                if "250" in ehlo_response: #Check for successful EHLO response
                    return f"SMTP Server: {banner} (Supports EHLO)"
                else:
                    return f"SMTP Server: {banner}"
            else:
                return None

    except socket.timeout:
        logging.warning(f"Connection to {host}:{port} timed out.")
        return None
    except ConnectionRefusedError:
        logging.error(f"Connection refused by {host}:{port}.")
        return None
    except Exception as e:
        logging.error(f"Error probing SMTP on {host}:{port}: {e}")
        return None


def fingerprint_service(host, port):
    """
    Attempts to fingerprint the service running on the specified port.

    Args:
        host (str): The hostname or IP address.
        port (int): The port number.

    Returns:
        str: Service information if identified, None otherwise.
    """
    try:
        # Try HTTP first
        http_info = probe_http(host, port)
        if http_info:
            return http_info

        # Then try SSH
        ssh_info = probe_ssh(host, port)
        if ssh_info:
            return ssh_info

        # Then try SMTP
        smtp_info = probe_smtp(host, port)
        if smtp_info:
            return smtp_info


        # If no specific protocol is detected, return a generic message
        return f"Unknown service running on {host}:{port}"

    except Exception as e:
        logging.error(f"Error fingerprinting service on {host}:{port}: {e}")
        return None


def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Attempts to fingerprint services running on specific ports.")
    parser.add_argument("host", help="The hostname or IP address to scan.")
    parser.add_argument("port", type=int, help="The port number to scan.")
    return parser


def validate_input(host, port):
    """
    Validates the input parameters.

    Args:
        host (str): The hostname or IP address.
        port (int): The port number.

    Returns:
        bool: True if the input is valid, False otherwise.
    """
    try:
        socket.inet_aton(host) #Verify the host is a valid ip address.
    except socket.error:
        try:
            socket.gethostbyname(host)
        except socket.gaierror:
            logging.error("Invalid host. Please provide a valid IP address or hostname.")
            return False
        
    if not (1 <= port <= 65535):
        logging.error("Invalid port number. Port must be between 1 and 65535.")
        return False

    return True



def main():
    """
    The main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    host = args.host
    port = args.port

    if not validate_input(host, port):
        sys.exit(1)  # Exit if input is invalid

    logging.info(f"Starting service fingerprinting on {host}:{port}...")
    service_info = fingerprint_service(host, port)

    if service_info:
        print(service_info)
    else:
        print(f"Could not determine service running on {host}:{port}.")
    logging.info("Service fingerprinting complete.")


if __name__ == "__main__":
    main()