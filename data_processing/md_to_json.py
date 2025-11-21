import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from html import unescape
from typing import Dict, List, Optional, Tuple


def ensure_project_root_on_syspath() -> None:
    """
    Keep available for future relative imports if needed, but this script is self-contained
    and does not import repository schemas by default.
    """
    script_dir = os.path.dirname(os.path.realpath(__file__))
    project_root = os.path.dirname(script_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)


@dataclass
class CodeBlock:
    language: str
    content: str


EXECUTOR_BACK_FROM_LANG = {
    "cmd": "command_prompt",
    "powershell": "powershell",
    "bash": "bash",
    "sh": "sh",
    "": "manual",
}

PLATFORM_REVERSE_MAP = {
    "Windows": "windows",
    "Linux": "linux",
    "macOS": "macos",
    "Office 365": "office-365",
    "Azure AD": "azure-ad",
    "IaaS": "iaas",
    "SaaS": "saas",
    "AWS": "iaas:aws",
    "Azure": "iaas:azure",
    "GCP": "iaas:gcp",
    "Google Workspace": "google-workspace",
    "Containers": "containers",
    "ESXi": "esxi",
}


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def parse_technique_header(text: str) -> Tuple[str, str]:
    """
    Parses the first H1 line: "# Txxxx - Display Name"
    Returns (attack_technique, display_name)
    """
    # Match beginning of file heading
    m = re.search(r"^#\s+([Tt]\d{4}(?:\.\d{3})?)\s*-\s*(.+?)\s*$", text, re.MULTILINE)
    if not m:
        raise ValueError("Unable to find technique header '# Txxxx - Name' in markdown.")
    return m.group(1).upper(), m.group(2).strip()


def split_atomic_tests_sections(text: str) -> List[Tuple[str, str]]:
    """
    Splits the document into atomic test sections.
    Returns list of tuples: (section_title_line, section_text)
    Section title line looks like: '## Atomic Test #<n> - <name>'
    """
    pattern = re.compile(r"^##\s+Atomic Test\s+#\d+\s+-\s+.+$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    sections: List[Tuple[str, str]] = []
    for i, match in enumerate(matches):
        start = match.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        section_text = text[start:end]
        first_line = section_text.splitlines()[0]
        sections.append((first_line, section_text))
    return sections


def extract_between(section: str, start_regex: str, end_regexes: List[str]) -> Tuple[Optional[str], int, int]:
    """
    Extracts text after the first line that matches start_regex until the next line that matches any of end_regexes,
    or until the end of the section. Returns (content or None if not found, start_index, end_index).
    Indices are positions in the section string (0-based).
    """
    start_match = re.search(start_regex, section, re.MULTILINE)
    if not start_match:
        return None, -1, -1
    search_start = start_match.end()
    # Find earliest end among end_regexes after search_start
    end_positions = []
    for er in end_regexes:
        m = re.search(er, section[search_start:], re.MULTILINE)
        if m:
            end_positions.append(search_start + m.start())
    end_pos = min(end_positions) if end_positions else len(section)
    content = section[search_start:end_pos]
    return content.strip(), start_match.start(), end_pos

def restructure_input_arguments_in_technique(technique: dict) -> dict:
    """
    Convert each test's input_arguments from a dict{name: {...}} into a list of
    objects: [{"arg_name": name, ...}, ...]. If empty, becomes [].
    This is non-destructive for other fields.
    """
    atomic_tests = technique.get("atomic_tests") or []
    for t in atomic_tests:
        args_map = t.get("input_arguments")
        if isinstance(args_map, dict):
            items: List[dict] = []
            for name, meta in args_map.items():
                item = {"arg_name": name}
                if isinstance(meta, dict):
                    # preserve keys: description, type, default
                    for k, v in meta.items():
                        item[k] = v
                items.append(item)
            t["input_arguments"] = items
        elif args_map in (None, {}):
            t["input_arguments"] = []
        # If already a list, leave as-is
    return technique


def restructure_executor_in_technique(technique: dict) -> dict:
    """
    For each test, normalize executor fields so that either 'steps' (manual)
    or 'command' (others) is moved into a single 'procedure' key.
    Keeps 'name', 'elevation_required', and 'cleanup_command' (if present).
    """
    atomic_tests = technique.get("atomic_tests") or []
    for t in atomic_tests:
        executor = t.get("executor")
        if not isinstance(executor, dict):
            continue
        if "steps" in executor and isinstance(executor.get("steps"), str):
            executor["procedure"] = executor["steps"]
            del executor["steps"]
        elif "command" in executor and isinstance(executor.get("command"), str):
            executor["procedure"] = executor["command"]
            del executor["command"]
        t["executor"] = executor
    return technique


def parse_supported_platforms(section: str) -> List[str]:
    # Example: "**Supported Platforms:** Windows, Linux"
    m = re.search(r"^\*\*Supported Platforms:\*\*\s*(.+?)\s*$", section, re.MULTILINE)
    if not m:
        return []
    raw = m.group(1).strip()
    parts = [p.strip() for p in raw.split(",")]
    platforms: List[str] = []
    for p in parts:
        if not p:
            continue
        # Some templates may print each on its own line, handle that too
        if p in PLATFORM_REVERSE_MAP:
            platforms.append(PLATFORM_REVERSE_MAP[p])
        else:
            # Fallback: normalize by lowercase; this covers windows/linux and others if already lowercased
            platforms.append(p.lower())
    return platforms


def parse_auto_generated_guid(section: str) -> Optional[str]:
    m = re.search(r"^\*\*auto_generated_guid:\*\*\s*([0-9a-fA-F-]{36})\s*$", section, re.MULTILINE)
    return m.group(1) if m else None


def parse_inputs_table(section: str) -> Dict[str, Dict[str, Optional[str]]]:
    """
    Parses the optional Inputs table.
    Returns dict: name -> { description, type, default }
    """
    # Find the heading first
    if not re.search(r"^####\s+Inputs:", section, re.MULTILINE):
        return {}
    # Capture table block: lines starting with '|' until a blank line or next heading
    table_match = re.search(
        r"^####\s+Inputs:\s*\n(?P<header>\|.+\|\s*\n\|[-\s|]+\|\s*\n)(?P<body>(?:\|.*\|\s*\n)+)",
        section,
        re.MULTILINE,
    )
    if not table_match:
        return {}
    body = table_match.group("body")
    args: Dict[str, Dict[str, Optional[str]]] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        # Split and strip borders
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        name, desc, typ, default = cells[:4]
        name = unescape(name)
        desc = unescape(desc)
        typ = unescape(typ)
        default = unescape(default)
        # Rows often end without trailing space before '|', ensure we strip it
        if default.endswith("\\"):
            # nothing special, keep as is; backslashes were unescaped via html earlier
            pass
        args[name] = {
            "description": desc,
            "type": typ,
            "default": default if default != "" else None,
        }
    return args


def parse_next_code_block(after_index: int, section: str) -> Optional[CodeBlock]:
    """
    Finds the next fenced code block (```lang ... ```).
    Returns CodeBlock or None if not found.
    """
    m = re.search(r"```([a-zA-Z0-9_-]*)\s*\n", section[after_index:], re.MULTILINE)
    if not m:
        return None
    lang = m.group(1)
    code_start = after_index + m.end()
    m_end = re.search(r"^\s*```", section[code_start:], re.MULTILINE)
    if not m_end:
        return None
    code_end = code_start + m_end.start()
    content = section[code_start:code_end]
    return CodeBlock(language=lang, content=unescape(content.strip()))


def parse_executor_block(section: str) -> Tuple[Dict, int]:
    """
    Parses executor configuration and command/steps.
    Returns (executor_dict, last_parsed_index)
    """
    # Manual steps heading
    manual_heading = re.search(
        r"^####\s+Run it with these steps!\s*(?P<elev>Elevation Required.*)?$",
        section,
        re.MULTILINE,
    )
    if manual_heading:
        steps_text, _, end_idx = extract_between(
            section,
            r"^####\s+Run it with these steps!.*$",
            end_regexes=[r"^####\s", r"^##\s"],
        )
        executor = {
            "name": "manual",
            "elevation_required": manual_heading.group("elev") is not None,
            "steps": steps_text or "",
        }
        return executor, end_idx

    # Command-based executor heading
    cmd_heading = re.search(
        r"^####\s+Attack Commands:\s+Run with\s+`(?P<exec>[^`]+)`!\s*(?P<elev>Elevation Required.*)?$",
        section,
        re.MULTILINE,
    )
    if not cmd_heading:
        raise ValueError("Executor heading not found in test section.")
    exec_name_display = cmd_heading.group("exec").strip()
    is_elev = cmd_heading.group("elev") is not None

    # The language in the code fence maps to executor; but template prints code fence language from executor.
    # The backticked name is the canonical executor we want (e.g., 'command_prompt').
    exec_name = exec_name_display
    # Extract the first code block after this heading as command
    command_block = parse_next_code_block(cmd_heading.end(), section)
    if not command_block:
        raise ValueError("Command code block not found after executor heading.")
    cleanup_cmd: Optional[str] = None

    # Optionally a cleanup section appears after
    cleanup_heading = re.search(r"^####\s+Cleanup Commands:\s*$", section[cmd_heading.end():], re.MULTILINE)
    last_index = cmd_heading.end()
    if cleanup_heading:
        cleanup_abs_index = cmd_heading.end() + cleanup_heading.end()
        cleanup_block = parse_next_code_block(cmd_heading.end() + cleanup_heading.start(), section)
        if cleanup_block:
            cleanup_cmd = cleanup_block.content
            last_index = cmd_heading.end() + cleanup_heading.start() + len(cleanup_block.content)
        else:
            last_index = cleanup_abs_index
    else:
        last_index = cmd_heading.end()

    # Map code fence language back to executor if needed (primarily for 'cmd' → 'command_prompt')
    # Prefer the canonical name in the backticks, but normalize if it's 'cmd'.
    if exec_name.lower() == "cmd":
        exec_name = "command_prompt"

    executor = {
        "name": exec_name,
        "elevation_required": is_elev,
        "command": command_block.content,
    }
    if cleanup_cmd:
        executor["cleanup_command"] = cleanup_cmd
    return executor, last_index


def parse_dependencies(section: str, test_executor_name: str) -> Tuple[Optional[str], List[Dict]]:
    """
    Parses optional dependencies block.
    Returns (dependency_executor_name or None, dependencies list)
    """
    dep_heading = re.search(
        r"^####\s+Dependencies:\s+Run with\s+`(?P<dep_exec>[^`]+)`!",
        section,
        re.MULTILINE,
    )
    if not dep_heading:
        return None, []
    dep_exec_printed = dep_heading.group("dep_exec").strip()
    dependency_executor_name: Optional[str] = dep_exec_printed if dep_exec_printed != test_executor_name else None

    deps: List[Dict] = []
    # Each dependency block is a trio of '##### Description:', '##### Check Prereq Commands:' (code), '##### Get Prereq Commands:' (code)
    # We'll iterate sequentially after the heading
    pos = dep_heading.end()
    while True:
        m_desc = re.search(r"^#####\s+Description:\s*(?P<desc>.+)$", section[pos:], re.MULTILINE)
        if not m_desc:
            break
        desc_abs_start = pos + m_desc.start()
        desc_text = m_desc.group("desc").strip()
        # Check prereq block
        m_check = re.search(r"^#####\s+Check Prereq Commands:\s*$", section[desc_abs_start:], re.MULTILINE)
        if not m_check:
            break
        check_block = parse_next_code_block(desc_abs_start + m_check.end(), section)
        # Get prereq block
        m_get = re.search(r"^#####\s+Get Prereq Commands:\s*$", section[desc_abs_start + m_check.end():], re.MULTILINE)
        get_block = None
        if m_get:
            get_block = parse_next_code_block(desc_abs_start + m_check.end() + m_get.end(), section)

        deps.append(
            {
                "description": unescape(desc_text),
                "prereq_command": check_block.content if check_block else "",
                "get_prereq_command": (get_block.content if get_block else None),
            }
        )
        # Advance position beyond the get prereq block if present; otherwise beyond check block
        advance_from = desc_abs_start + m_check.end()
        if m_get and get_block:
            # find the end fence after get_block; we already consumed its content length, but safer to shift a bit
            advance_from = desc_abs_start + m_check.end() + m_get.end()
        pos = advance_from + 1
    return dependency_executor_name, deps


def parse_test_section(title_line: str, section: str) -> Dict:
    # Name from title line
    m = re.match(r"^##\s+Atomic Test\s+#\d+\s+-\s+(.+)$", title_line)
    name = m.group(1).strip() if m else "Unknown"

    # Description is text between title and the Supported Platforms line
    desc_text, _, _ = extract_between(
        section,
        r"^##\s+Atomic Test\s+#\d+\s+-\s+.+$",
        end_regexes=[r"^\*\*Supported Platforms:\*\*", r"^##\s", r"^####\s"],
    )
    description = (desc_text or "").strip()

    supported_platforms = parse_supported_platforms(section)
    auto_guid = parse_auto_generated_guid(section)
    input_arguments = parse_inputs_table(section)
    executor, last_idx = parse_executor_block(section)
    dep_executor_name, dependencies = parse_dependencies(section, executor["name"])

    atomic_obj: Dict = {
        "name": name,
        "description": description,
        "supported_platforms": supported_platforms,
        "executor": executor,
    }
    if input_arguments:
        atomic_obj["input_arguments"] = input_arguments
    else:
        atomic_obj["input_arguments"] = {}
    if dependencies:
        atomic_obj["dependencies"] = dependencies
    if dep_executor_name:
        atomic_obj["dependency_executor_name"] = dep_executor_name
    if auto_guid:
        atomic_obj["auto_generated_guid"] = auto_guid
    return atomic_obj


def parse_markdown_to_technique(md_text: str) -> Dict:
    attack_technique, display_name = parse_technique_header(md_text)
    sections = split_atomic_tests_sections(md_text)
    atomic_tests = [parse_test_section(title, sec) for title, sec in sections]
    technique: Dict = {
        "attack_technique": attack_technique,
        "display_name": display_name,
        "atomic_tests": atomic_tests,
    }
    return technique


def validate_with_json_schema(obj: dict, schema_path: str) -> None:
    try:
        from jsonschema import validate as jsonschema_validate  # type: ignore
        from jsonschema.exceptions import ValidationError as JSONSchemaValidationError  # type: ignore
    except Exception as e:
        raise RuntimeError("jsonschema package is required for --schema validation") from e
    with open(schema_path, "r", encoding="utf-8") as f:
        schema = json.load(f)
    try:
        jsonschema_validate(instance=obj, schema=schema)
    except JSONSchemaValidationError as e:
        raise ValueError(f"JSON Schema validation failed: {e.message}") from e


def process_file(md_path: str, out_path: Optional[str], stdout: bool, schema_path: Optional[str]) -> Optional[str]:
    text = read_text(md_path)
    technique_obj = parse_markdown_to_technique(text)
    if getattr(process_file, "_restruct_args", False):
        technique_obj = restructure_input_arguments_in_technique(technique_obj)
    if getattr(process_file, "_restruct_executor", False):
        technique_obj = restructure_executor_in_technique(technique_obj)
    if schema_path:
        validate_with_json_schema(technique_obj, schema_path)
    if stdout:
        print(json.dumps(technique_obj, indent=2, ensure_ascii=False))
        return None
    output_path = out_path or f"{md_path}.json"
    write_json(output_path, technique_obj)
    return output_path


def process_directory(dir_path: str, out_dir: Optional[str], schema_path: Optional[str]) -> List[Tuple[str, Optional[str]]]:
    """
    Processes all T*/T*.md files under dir_path.
    Returns list of (md_file, json_output_path)
    """
    results: List[Tuple[str, Optional[str]]] = []
    for root, dirs, files in os.walk(dir_path):
        # Only consider technique folders (Txxxx or Txxxx.xxx)
        base = os.path.basename(root)
        if not re.match(r"^T\d{4}(?:\.\d{3})?$", base):
            continue
        for fn in files:
            if not fn.lower().endswith(".md"):
                continue
            if not re.match(r"^T\d{4}(?:\.\d{3})?\.md$", fn, re.IGNORECASE):
                continue
            md_path = os.path.join(root, fn)
            json_name = f"{os.path.splitext(fn)[0]}.json"
            out_path = os.path.join(out_dir, base, json_name) if out_dir else os.path.join(root, json_name)
            if out_dir:
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
            try:
                produced = process_file(md_path, out_path, stdout=False, schema_path=schema_path)
                results.append((md_path, produced))
            except Exception as e:
                # Record failure with None output
                sys.stderr.write(f"Failed to process {md_path}: {e}\n")
                results.append((md_path, None))
    return results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert Atomic Red Team markdown files back into JSON objects.")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", "-i", help="Path to a single markdown file to convert.")
    src.add_argument("--dir", "-d", help="Path to a directory (e.g., atomics/) to process recursively.")
    parser.add_argument("--output", "-o", help="Output JSON path (only for --input). Defaults to <input>.json")
    parser.add_argument(
        "--out-dir",
        help="Base output directory for JSON files when using --dir. Defaults to writing alongside each md file.",
    )
    parser.add_argument("--stdout", action="store_true", help="Print JSON to stdout (only for --input).")
    parser.add_argument(
        "--schema",
        help="Optional path to a JSON Schema file to validate the produced JSON object. Keeps this tool independent of repo models.",
    )
    parser.add_argument(
        "--restruct-args",
        action="store_true",
        help="Restructure input_arguments from a mapping into an array of objects with 'arg_name'.",
    )
    parser.add_argument(
        "--restruct-executor",
        action="store_true",
        help="Normalize executor: move 'steps' (manual) or 'command' into unified 'procedure' key.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.input:
        if args.out_dir:
            parser.error("--out-dir is only valid with --dir.")
        if args.output and args.stdout:
            parser.error("--output and --stdout are mutually exclusive.")
        out_path = None
        if args.output:
            out_path = args.output
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        try:
            # Pass restruct flag via function attribute to avoid expanding signatures deeply
            setattr(process_file, "_restruct_args", bool(args.restruct_args))
            setattr(process_file, "_restruct_executor", bool(args.restruct_executor))
            process_file(args.input, out_path, stdout=args.stdout, schema_path=args.schema)
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            return 1
        return 0

    if args.dir:
        setattr(process_file, "_restruct_args", bool(args.restruct_args))
        setattr(process_file, "_restruct_executor", bool(args.restruct_executor))
        results = process_directory(args.dir, args.out_dir, schema_path=args.schema)
        failed = [r for r in results if r[1] is None]
        if failed:
            sys.stderr.write(f"{len(failed)} file(s) failed to convert.\n")
            return 1
        return 0

    parser.error("Either --input or --dir must be provided.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())




