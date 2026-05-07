######### Router Access Function : to access + apply the configs on a specific router in GNS3 #########
#########################################################################################################
import os
import re
import time
import random
import telnetlib

from Helpers.Finder import *

# ## send the config to GNS3 must be done here

def apply_config_GNS3(hostname: str, configs, devices: list) -> str:
    """
    configs may be:
      - list[str]   -> preferred for incremental deployment
      - str         -> legacy full config text
    """
    device_ip, device_port = get_device_info(hostname, devices)

    print(device_ip, device_port)

    # Router_Access(D_IP, D_Port, configs, hostname)
    if device_ip is None or device_port is None:
        raise ValueError(f"Device {hostname!r} not found in devices list")

    return Router_Access(device_ip, device_port, configs, hostname)


def Router_Access(IP: str, Port: str, configs, hostname: str) -> str:
    user = "admin"
    password = "cisco"
    output_file_name = hostname + "_output.txt"

    telnet_connection = telnetlib.Telnet(IP, Port, timeout=10)
    time.sleep(0.5)

    try:
        print(
            telnet_connection.read_very_eager().decode(
                "ascii",
                errors="ignore",
            )
        )

    except EOFError:
        pass

    def _normalize_commands(configs) -> list:
        """
        Accept either:
          - list/tuple of commands
          - multi-line string
        Return clean list[str]
        """
        if configs is None:
            return []

        if isinstance(configs, (list, tuple)):
            commands = []

            for item in configs:
                if item is None:
                    continue

                command = str(item).rstrip()

                if command.strip():
                    commands.append(command)

            return commands

        if isinstance(configs, str):
            commands = []

            for line in configs.splitlines():
                command = line.rstrip()

                if command.strip():
                    commands.append(command)

            return commands

        raise TypeError(f"Unsupported configs type: {type(configs)}")

    commands = _normalize_commands(configs)

    if not commands:
        print(f"No commands to send to {hostname}.")
        telnet_connection.close()

        return ""

    output = ""

    for line in commands:
        command = f"{line.strip()}\r\n"

        print(f"Sending command: {line.strip()}")
        telnet_connection.write(command.encode("ascii"))

        command_output = ""
        start_time = time.time()

        while time.time() - start_time < 3:
            try:
                chunk = telnet_connection.read_very_eager().decode(
                    "ascii",
                    errors="ignore",
                )

            except EOFError:
                chunk = ""

            if chunk:
                command_output += chunk

            time.sleep(0.1)

        filtered_output = (
            f"Command: {line.strip()}\n"
            f"{command_output.strip()}\n"
        )
        output += filtered_output

    with open(output_file_name, "w", encoding="utf-8") as file:
        file.write(output)

    print(f"Filtered Telnet output saved to {output_file_name}")

    telnet_connection.write(b"\r\n")
    telnet_connection.close()

    return output
    
def gns3_output_has_error(output: str) -> bool:
    """Basic Cisco IOS CLI error detector for deployment validation."""
    s = (output or "").lower()
    error_tokens = [
       "% invalid input",
       "% incomplete command",
        "% ambiguous command",
       "% unknown command",
        "error",
        "traceback",
    ]
    return any(tok in s for tok in error_tokens)

