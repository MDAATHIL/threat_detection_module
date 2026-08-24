#!/usr/bin/env python3

"""
Artifact Reader — recursively reads and displays contents of sensitive
artifact directories (.aws, .azure, .steampipe).

Dynamically resolves paths based on the current user's home directory.

Usage:
    python artifact_reader.py                    # Read all artifact dirs
    python artifact_reader.py --dir .aws         # Read only .aws
    python artifact_reader.py --dir .azure .ssh  # Read multiple dirs
    python artifact_reader.py --json             # Output as JSON
"""

import json
import sys
from pathlib import Path
from typing import Any


# Artifact directories to scan (relative to home)
ARTIFACT_DIRS = [".aws", ".azure", ".steampipe"]


def get_home_dir() -> Path:
    """Get the current user's home directory dynamically."""
    return Path.home()


def read_artifact_dir(dir_name: str, home_dir: Path | None = None) -> dict[str, Any]:
    """Recursively read all files in an artifact directory.

    Args:
        dir_name: Name of the directory (e.g., ".aws", ".azure")
        home_dir: Home directory path (defaults to Path.home())

    Returns:
        Dictionary with directory info and file contents
    """
    if home_dir is None:
        home_dir = get_home_dir()

    artifact_path = home_dir / dir_name
    result = {
        "directory": dir_name,
        "full_path": str(artifact_path),
        "exists": artifact_path.exists(),
        "files": [],
        "total_files": 0,
        "total_size": 0,
        "errors": [],
    }

    if not artifact_path.exists():
        result["errors"].append(f"Directory does not exist: {artifact_path}")
        return result

    if not artifact_path.is_dir():
        result["errors"].append(f"Path is not a directory: {artifact_path}")
        return result

    # Recursively read all files
    try:
        for file_path in sorted(artifact_path.rglob("*")):
            if not file_path.is_file():
                continue

            # Skip binary files and large files
            try:
                file_size = file_path.stat().st_size
                result["total_size"] += file_size

                # Skip files larger than 1MB (likely binary or logs)
                if file_size > 1_000_000:
                    result["files"].append({
                        "path": str(file_path.relative_to(home_dir)),
                        "size": file_size,
                        "content": None,
                        "error": "File too large (>1MB), skipped",
                    })
                    result["total_files"] += 1
                    continue

                # Try to read file content
                try:
                    content = file_path.read_text(encoding="utf-8")
                    result["files"].append({
                        "path": str(file_path.relative_to(home_dir)),
                        "size": file_size,
                        "content": content,
                        "error": None,
                    })
                except UnicodeDecodeError:
                    # Binary file - show hex preview
                    try:
                        with open(file_path, "rb") as f:
                            raw = f.read(256)
                        preview = raw.hex()[:200] + "..." if len(raw) > 200 else raw.hex()
                        result["files"].append({
                            "path": str(file_path.relative_to(home_dir)),
                            "size": file_size,
                            "content": f"[Binary file - hex preview: {preview}]",
                            "error": "Binary file, content not displayed",
                        })
                    except Exception as e:
                        result["files"].append({
                            "path": str(file_path.relative_to(home_dir)),
                            "size": file_size,
                            "content": None,
                            "error": f"Cannot read binary file: {e}",
                        })

                result["total_files"] += 1

            except PermissionError:
                result["files"].append({
                    "path": str(file_path.relative_to(home_dir)),
                    "size": 0,
                    "content": None,
                    "error": "Permission denied",
                })
                result["total_files"] += 1
            except Exception as e:
                result["errors"].append(f"Error reading {file_path}: {e}")

    except Exception as e:
        result["errors"].append(f"Error traversing directory: {e}")

    return result


def print_artifact_info(artifact: dict[str, Any], verbose: bool = False) -> None:
    """Pretty-print artifact directory information."""
    print(f"\n{'='*70}")
    print(f"📁 {artifact['directory']}")
    print(f"   Path: {artifact['full_path']}")
    print(f"   Files: {artifact['total_files']}")
    print(f"   Size:  {artifact['total_size']:,} bytes")
    print(f"{'='*70}")

    if not artifact["exists"]:
        print(f"   ⚠️  Directory does not exist")
        return

    if artifact["errors"]:
        for err in artifact["errors"]:
            print(f"   ❌ {err}")

    for file_info in artifact["files"]:
        print(f"\n📄 {file_info['path']} ({file_info['size']:,} bytes)")
        if file_info["error"]:
            print(f"   ⚠️  {file_info['error']}")
        if file_info["content"] and verbose:
            # Show first 500 chars of content
            content_preview = file_info["content"][:500]
            if len(file_info["content"]) > 500:
                content_preview += "\n   ... (truncated)"
            print(f"   Content:\n{content_preview}")
        elif file_info["content"]:
            # Just show first 200 chars
            content_preview = file_info["content"][:200]
            if len(file_info["content"]) > 200:
                content_preview += "..."
            print(f"   Preview: {content_preview}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Recursively read artifact directories (.aws, .azure, .steampipe)"
    )
    parser.add_argument(
        "--dir", "-d",
        nargs="+",
        default=ARTIFACT_DIRS,
        help=f"Directories to scan (default: {ARTIFACT_DIRS})"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output results as JSON"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full file contents (not just preview)"
    )
    args = parser.parse_args()

    home_dir = get_home_dir()
    print(f"🏠 Home directory: {home_dir}")
    print(f"📂 Scanning directories: {args.dir}")

    all_results = []
    total_files = 0
    total_size = 0
    total_errors = 0

    for dir_name in args.dir:
        artifact = read_artifact_dir(dir_name, home_dir)
        all_results.append(artifact)

        if not args.json:
            print_artifact_info(artifact, verbose=args.verbose)

        total_files += artifact["total_files"]
        total_size += artifact["total_size"]
        total_errors += len(artifact["errors"])

    if args.json:
        print(json.dumps(all_results, indent=2, default=str))
    else:
        print(f"\n{'='*70}")
        print(f"📊 Summary")
        print(f"{'='*70}")
        print(f"   Directories scanned: {len(args.dir)}")
        print(f"   Total files:         {total_files}")
        print(f"   Total size:          {total_size:,} bytes")
        print(f"   Errors:              {total_errors}")
        print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
