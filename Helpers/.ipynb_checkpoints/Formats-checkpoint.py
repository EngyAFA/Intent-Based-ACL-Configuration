import os
import sys
import re
import json
import random
import subprocess
import time

import pandas as pd
from tabulate import tabulate
from typing import Any, Dict, Optional, Tuple



############### Helping function : Set pandas display options to show all columns + extract information from a DataFrame + normalize texts (intents)###############
########################################################################################################################################

pd.set_option('display.max_columns', None)  # Show all columns
pd.set_option('display.width', 100)        # Adjust the width of the output
pd.set_option('display.max_colwidth', None)

# Function to wrap text within a cell
def wrap_text(text, width):
    return '\n'.join([text[i:i+width] for i in range(0, len(text), width)])

# Function to apply wrapping to each cell in the DataFrame
def wrap_dataframe(df, width):
    return df.applymap(lambda x: wrap_text(str(x), width))

#### Helping Function ####

# Function to extract information from a DataFrame and return as formatted text
def extract_table_info(table: pd.DataFrame) -> str:
    output_lines = []
    headers = table.columns.tolist()
    output_lines.append(" | ".join(headers))  # Add header row

    for index, row in table.iterrows():
        row_data = [str(item) for item in row]
        output_lines.append(" | ".join(row_data))  # Add each row

    return "\n".join(output_lines)

def parse_kv_response(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out

def strip_code_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return text 
    
def csv_to_list(s: str):
    if not s or s.lower() == "none":
        return []
    return [x.strip() for x in s.split(",") if x.strip()]

def _norm_nl(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)                 # collapse spaces
    s = re.sub(r"[^\w\s/]", "", s)             # remove punctuation (.,!? etc)
    return s

def _norm_str(x: Any) -> str:
    return "" if x is None else str(x).strip()
    
def to_none_if_noneish(x: Any) -> Optional[str]:
    """
    Normalize "none"/"no"/"" to None, else return stripped string.
    """
    s = _norm_str(x)
    if s == "":
        return None
    if s.strip().lower() in ("none", "no", "null", "n/a", "na", "false"):
        return None
    return s

import re

def normalize_interface_name(name: str) -> str:
    name = (name or "").strip().lower()

    if name.startswith("interface "):
        name = name.split(None, 1)[1].strip()

    # remove extra spaces like "serial 0/0" -> "serial0/0"
    name = re.sub(r"\s+", "", name)

    # expand common abbreviations
    repl = [
        ("fa", "fastethernet"),
        ("f",  "fastethernet"),
        ("gi", "gigabitethernet"),
        ("g",  "gigabitethernet"),
        ("te", "tengigabitethernet"),
        ("t",  "tengigabitethernet"),
        ("se", "serial"),
        ("s",  "serial"),
        ("e",  "ethernet"),
        ("lo", "loopback"),
    ]

    for short, full in repl:
        if name.startswith(short) and (len(name) == len(short) or name[len(short)].isdigit()):
            name = full + name[len(short):]
            break

    return name


def _norm(s):
    return (s or "").strip()

def _norm_lower(s):
    return _norm(s).lower()
    
def normalize_action(action):
    if not action:
        return ""
    a = _norm_lower(action)
    if a in ("allow", "permit", "permitted","accept","allowed"):
        return "permit"
    if a in ("deny", "block", "blocked", "denied","drop"):
        return "deny"
    return a