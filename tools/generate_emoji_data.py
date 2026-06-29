#!/usr/bin/env python3
"""Generate tabbed emoji picker data from Unicode emoji-test.txt."""

import argparse
import datetime
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request


DATA_LINE_RE = re.compile(
    r"^\s*([0-9A-F ]+)\s*;\s*([a-z-]+)\s*#\s*(\S+)\s+"
    r"(E[0-9.]+)\s+(.+?)\s*$"
)


def slug(label):
    slugged = re.sub(r"[^a-z0-9]+", "_", label.lower())
    return slugged.strip("_")


def source_url(args):
    if args.source_url:
        return args.source_url
    if args.unicode_version == "latest":
        return "https://www.unicode.org/Public/emoji/latest/emoji-test.txt"
    return (
        "https://www.unicode.org/Public/"
        f"{args.unicode_version}/emoji/emoji-test.txt"
    )


def read_input(args):
    if args.input:
        path = pathlib.Path(args.input)
        return path.read_text(encoding="utf-8"), f"file:{path}"

    url = source_url(args)
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"failed to download {url}: {exc}") from exc
    if not data:
        raise RuntimeError(f"downloaded emoji data is empty: {url}")
    return data.decode("utf-8"), url


def parse_emoji_test(text):
    categories = []
    current_category = None
    current_subgroup = None

    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("# group: "):
            label = line.removeprefix("# group: ").strip()
            current_category = {
                "id": slug(label),
                "label": label,
                "subgroups": [],
            }
            categories.append(current_category)
            current_subgroup = None
            continue

        if line.startswith("# subgroup: "):
            if current_category is None:
                raise RuntimeError(
                    f"subgroup before group at line {line_number}"
                )
            label = line.removeprefix("# subgroup: ").strip()
            current_subgroup = {
                "id": slug(label),
                "label": label,
                "emoji": [],
            }
            current_category["subgroups"].append(current_subgroup)
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        match = DATA_LINE_RE.match(line)
        if match is None:
            raise RuntimeError(f"could not parse emoji line {line_number}")

        if current_category is None:
            raise RuntimeError(f"emoji before group at line {line_number}")
        if current_subgroup is None:
            raise RuntimeError(f"emoji before subgroup at line {line_number}")

        _, status, emoji, version, name = match.groups()
        if status != "fully-qualified":
            continue
        current_subgroup["emoji"].append({
            "emoji": emoji,
            "name": name,
            "version": version,
        })

    for category in categories:
        category["subgroups"] = [
            subgroup for subgroup in category["subgroups"]
            if subgroup["emoji"]
        ]
        if category["subgroups"]:
            category["representative_emoji"] = (
                category["subgroups"][0]["emoji"][0]["emoji"]
            )
    categories = [
        category for category in categories if category["subgroups"]
    ]
    if not categories:
        raise RuntimeError("no emoji categories were produced")
    return categories


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--unicode-version")
    parser.add_argument("--source-url")
    parser.add_argument("--input")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if not (args.input or args.source_url or args.unicode_version):
        parser.error(
            "one of --input, --source-url, or --unicode-version is required"
        )

    try:
        text, url = read_input(args)
        if not text:
            raise RuntimeError("input emoji data is empty")
        categories = parse_emoji_test(text)
        output = pathlib.Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        unicode_version = args.unicode_version or "unknown"
        data = {
            "source": {
                "unicode_version": unicode_version,
                "url": url,
                "generated_at": datetime.date.today().isoformat(),
            },
            "categories": categories,
        }
        tmp = output.with_suffix(output.suffix + ".tmp")
        tmp.write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        tmp.replace(output)
    except OSError as exc:
        print(f"generate_emoji_data.py: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"generate_emoji_data.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
