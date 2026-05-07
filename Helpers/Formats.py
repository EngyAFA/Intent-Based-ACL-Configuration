import os
import sys
import re
import json
import random
import time
import subprocess

import pandas as pd
from tabulate import tabulate
from typing import Any, Dict, Optional, Tuple



############### Helping function : Set pandas display options to show all columns + extract information from a DataFrame + normalize texts (intents)###############
########################################################################################################################################

pd.set_option('display.max_columns', None)  # Show all columns
pd.set_option('display.width', 100)        # Adjust the width of the output
pd.set_option('display.max_colwidth', None)

# Function to wrap text within a cell
def wrap_text(text: str, width: int) -> str:
    wrapped_lines = []

    for i in range(0, len(text), width):
        wrapped_lines.append(text[i:i + width])

    return "\n".join(wrapped_lines)

# Function to apply wrapping to each cell in the DataFrame
def wrap_dataframe(df: pd.DataFrame, width: int) -> pd.DataFrame:
    wrapped_df = df.copy()

    for column in wrapped_df.columns:
        wrapped_df[column] = wrapped_df[column].apply(
            lambda cell: wrap_text(str(cell), width)
        )

    return wrapped_df

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
    
def csv_to_list(s: str) -> list:
    values = []

    if not s or s.lower() == "none":
        return values

    for item in s.split(","):
        cleaned_item = item.strip()

        if cleaned_item:
            values.append(cleaned_item)

    return values

########### Helping function: normalization functions ###########
#################################################################

# def normalize_interface_name(name):
#     if name is None:
#         return None

#     name = str(name).strip()
#     if not name:
#         return None

#     name = name.splitlines()[0].strip()
#     name = name.lower()

#     if name.startswith("interface "):
#         name = name[len("interface "):].strip()

#     return name
    
def clean_single_line(text: str):
    if text is None:
        return None

    cleaned_text = str(text).strip()

    if not cleaned_text:
        return None

    lines = cleaned_text.splitlines()

    return lines[0].strip()

def normalize_direction_token(text: str) -> str:
    t = clean_single_line(text).lower()
    if t.startswith("in"):
        return "in"
    if t.startswith("out"):
        return "out"
    return "None"

def normalize_acl_name_token(text: str) -> Optional[str]:
    t = clean_single_line(text)
    if t.lower() == "none":
        return None
    return t


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


def _norm(s: str) -> str:
    normalized_value = (s or "").strip()

    return normalized_value


def _norm_lower(s: str) -> str:
    normalized_value = _norm(s)

    return normalized_value.lower()


def normalize_action(action: str) -> str:
    if not action:
        return ""

    normalized_action = _norm_lower(action)

    permit_actions = {
        "allow",
        "permit",
        "permitted",
        "accept",
        "allowed",
    }

    deny_actions = {
        "deny",
        "block",
        "blocked",
        "denied",
        "drop",
    }

    if normalized_action in permit_actions:
        return "permit"

    if normalized_action in deny_actions:
        return "deny"

    return normalized_action