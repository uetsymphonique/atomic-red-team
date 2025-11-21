import argparse
import json
import os
import re
from typing import Dict, List, Optional


def read_json(path: str) -> dict:
	"""Read a JSON file and return the parsed object."""
	with open(path, "r", encoding="utf-8") as f:
		return json.load(f)


def write_text(path: str, content: str) -> None:
	"""Write text content to a file."""
	with open(path, "w", encoding="utf-8") as f:
		f.write(content)


def get_language(executor_name: str) -> str:
	"""Map executor name to code fence language."""
	if executor_name == "command_prompt":
		return "cmd"
	if executor_name == "manual":
		return ""
	return executor_name


def format_supported_platforms(platforms: List[str]) -> str:
	"""Render supported platforms like the ERB template (macOS special case, others capitalize)."""
	display = []
	for p in platforms:
		if p == "macos":
			display.append("macOS")
		else:
			display.append(p.capitalize())
	return ", ".join(display)


def slugify_anchor(title: str) -> str:
	"""
	Build an anchor like the ERB template:
	- lowercase
	- spaces -> '-'
	- strip the set of punctuation used in template
	"""
	lower = title.lower().replace(" ", "-")
	# remove characters: [`~!@#$%^&*()+=<>?,./:;"'|{}\[\]\\–—]
	return re.sub(r"[`~!@#$%^&*()+=<>?,\./:;\"'\|\{\}\[\]\\\\–—]", "", lower)


def escape_table_cell(value: Optional[str]) -> str:
	"""
	Match the template behavior: escape backslashes in table cells.
	Also keep None as empty string.
	"""
	if value is None:
		return ""
	return value.replace("\\", "&#92;")


def render_inputs_table(input_arguments: Optional[List[Dict]]) -> str:
	if not input_arguments:
		return ""
	lines: List[str] = []
	lines.append("#### Inputs:")
	lines.append("| Name | Description | Type | Default Value |")
	lines.append("|------|-------------|------|---------------|")
	for arg in input_arguments:
		name = escape_table_cell(arg.get("arg_name"))
		desc = escape_table_cell(arg.get("description"))
		typ = escape_table_cell(arg.get("type"))
		default = escape_table_cell(arg.get("default"))
		lines.append(f"| {name} | {desc} | {typ} | {default}|")
	return "\n".join(lines) + "\n"


def render_executor_block(executor: Dict) -> str:
	"""Render executor section similar to ERB output."""
	name = executor.get("name", "")
	elev = bool(executor.get("elevation_required", False))
	procedure = executor.get("procedure", "") or ""
	cleanup = executor.get("cleanup_command")

	parts: List[str] = []
	if name == "manual":
		heading = "#### Run it with these steps!"
		if elev:
			heading += "  Elevation Required (e.g. root or admin) "
		parts.append(heading)
		parts.append("")
		parts.append(procedure.strip())
	else:
		heading = f"#### Attack Commands: Run with `{name}`!"
		if elev:
			heading += "  Elevation Required (e.g. root or admin) "
		parts.append(heading)
		parts.append("")
		lang = get_language(name)
		parts.append(f"```{lang}")
		parts.append(procedure.strip())
		parts.append("```")
		if cleanup:
			parts.append("")
			parts.append("#### Cleanup Commands:")
			parts.append(f"```{lang}")
			parts.append(str(cleanup).strip())
			parts.append("```")
	return "\n".join(parts) + "\n"


def render_dependencies(dependencies: Optional[List[Dict]], executor_name: str, dep_executor_name: Optional[str]) -> str:
	if not dependencies:
		return ""
	parts: List[str] = []
	exec_to_use = dep_executor_name or executor_name
	parts.append(f"#### Dependencies:  Run with `{exec_to_use}`!")
	lang = get_language(exec_to_use)
	for dep in dependencies:
		desc = dep.get("description", "").strip()
		prereq = dep.get("prereq_command", "")
		get_prereq = dep.get("get_prereq_command")
		parts.append(f"##### Description: {desc}")
		parts.append("##### Check Prereq Commands:")
		parts.append(f"```{lang}")
		parts.append(str(prereq).strip())
		parts.append("```")
		if get_prereq:
			parts.append("##### Get Prereq Commands:")
			parts.append(f"```{lang}")
			parts.append(str(get_prereq).strip())
			parts.append("```")
	return "\n".join(parts) + "\n"


def render_atomic_markdown(obj: dict) -> str:
	"""
	Render the Markdown for a single technique object following the Atomic docs style.
	Note: top-level ATT&CK description block is emitted only if 'description' is provided.
	"""
	attack_technique = obj.get("attack_technique", "")
	display_name = obj.get("display_name", "")
	technique_desc = obj.get("description")  # optional
	atomic_tests: List[Dict] = obj.get("atomic_tests", [])

	out: List[str] = []
	out.append(f"# {attack_technique} - {display_name}")
	if attack_technique:
		link_id = attack_technique.replace(".", "/")
		out.append(f"## [Description from ATT&CK](https://attack.mitre.org/techniques/{link_id})")
		out.append("<blockquote>")
		out.append("")
		if technique_desc:
			out.append(str(technique_desc))
			out.append("")
		out.append("</blockquote>")
	out.append("")
	out.append("## Atomic Tests")
	out.append("")
	# Index of tests
	for idx, test in enumerate(atomic_tests, start=1):
		title = f"Atomic Test #{idx} - {test.get('name', '')}"
		anchor = f"#{slugify_anchor(title)}"
		out.append(f"- [{title}]({anchor})")
	out.append("")
	# Each test
	for idx, test in enumerate(atomic_tests, start=1):
		out.append("<br/>")
		out.append("")
		out.append(f"## Atomic Test #{idx} - {test.get('name', '')}")
		desc = (test.get("description") or "").strip()
		if desc:
			out.append(desc)
		out.append("")
		# Supported platforms
		plats = test.get("supported_platforms") or []
		out.append(f"**Supported Platforms:** {format_supported_platforms(plats)}")
		out.append("")
		# auto_generated_guid (optional if present)
		if "auto_generated_guid" in test and test.get("auto_generated_guid"):
			out.append(f"**auto_generated_guid:** {test['auto_generated_guid']}")
			out.append("")
		# Inputs table
		inputs_section = render_inputs_table(test.get("input_arguments"))
		if inputs_section:
			out.append(inputs_section.rstrip())
			out.append("")
		# Executor
		out.append(render_executor_block(test.get("executor") or {}).rstrip())
		out.append("")
		# Dependencies
		dep_block = render_dependencies(
			test.get("dependencies"),
			(test.get("executor") or {}).get("name", ""),
			test.get("dependency_executor_name"),
		)
		if dep_block:
			out.append(dep_block.rstrip())
			out.append("")
		out.append("<br/>")
	return "\n".join(out).rstrip() + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Convert normalized Atomic JSON (atomic_schema) into Markdown.")
	parser.add_argument("--input", "-i", required=True, help="Path to the input JSON file.")
	parser.add_argument("--output", "-o", help="Path to write the generated Markdown. Defaults to <attack_technique>.md next to input.")
	parser.add_argument("--stdout", action="store_true", help="Print markdown to stdout instead of writing a file.")
	return parser


def main(argv: Optional[List[str]] = None) -> int:
	parser = build_arg_parser()
	args = parser.parse_args(argv)
	obj = read_json(args.input)
	md = render_atomic_markdown(obj)
	if args.stdout:
		print(md, end="")
		return 0
	out_path = args.output
	if not out_path:
		attack_technique = obj.get("attack_technique") or "TECHNIQUE"
		base_dir = os.path.dirname(args.input)
		out_path = os.path.join(base_dir, f"{attack_technique}.md")
	os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
	write_text(out_path, md)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())


