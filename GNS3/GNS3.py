######### Router Access Function : to access + apply the configs on a specific router in GNS3 #########
#########################################################################################################
import os
import re
import time
import random
import telnetlib

from Helpers.Finder import *

# ## send the config to GNS3 must be done here

def apply_config_GNS3(hostname, configs, devices):
    """
    configs may be:
      - list[str]   -> preferred for incremental deployment
      - str         -> legacy full config text
    """
    D_IP, D_Port = get_device_info(hostname, devices)
    print(D_IP, D_Port)
    # Router_Access(D_IP, D_Port, configs, hostname)
    if D_IP is None or D_Port is None:
        raise ValueError(f"Device {hostname!r} not found in devices list")
    return Router_Access(D_IP, D_Port, configs, hostname)

def Router_Access(IP, Port, configs, hostname):
    user = "admin"
    password = "cisco"
    F_OP_name = hostname + "_output.txt"

    tn = telnetlib.Telnet(IP, Port, timeout=10)
    time.sleep(0.5)
    try:
        print(tn.read_very_eager().decode("ascii", errors="ignore"))
    except EOFError:
        pass

    def _normalize_commands(configs):
        """
        Accept either:
          - list/tuple of commands
          - multi-line string
        Return clean list[str]
        """
        if configs is None:
            return []

        if isinstance(configs, (list, tuple)):
            cmds = []
            for item in configs:
                if item is None:
                    continue
                s = str(item).rstrip()
                if s.strip():
                    cmds.append(s)
            return cmds

        if isinstance(configs, str):
            cmds = []
            for line in configs.splitlines():
                s = line.rstrip()
                if s.strip():
                    cmds.append(s)
            return cmds

        raise TypeError(f"Unsupported configs type: {type(configs)}")

    commands = _normalize_commands(configs)

    if not commands:
        print(f"No commands to send to {hostname}.")
        tn.close()
        return ""

    output = ""

    for line in commands:
        command = f"{line.strip()}\r\n"
        print(f"Sending command: {line.strip()}")
        tn.write(command.encode("ascii"))

        command_output = ""
        start_time = time.time()

        while time.time() - start_time < 3:
            try:
                chunk = tn.read_very_eager().decode("ascii", errors="ignore")
            except EOFError:
                chunk = ""
            if chunk:
                command_output += chunk
            time.sleep(0.1)

        filtered_output = f"Command: {line.strip()}\n{command_output.strip()}\n"
        output += filtered_output

    with open(F_OP_name, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"Filtered Telnet output saved to {F_OP_name}")

    tn.write(b"\r\n")
    tn.close()
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

