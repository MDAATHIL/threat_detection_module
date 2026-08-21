#!/usr/bin/env python3

import curses
import os
import yaml
from pathlib import Path


OUTPUT_FILE = "policy.yaml"


class FileBrowser:
    def __init__(self):
        self.current_path = Path("/")
        self.selected = set()
        self.cursor = 0
        self.entries = []

    def load_entries(self):
        try:
            entries = list(self.current_path.iterdir())
            entries.sort(key=lambda p: (not p.is_dir(), p.name.lower()))
            self.entries = entries
        except PermissionError:
            self.entries = []

        self.cursor = min(self.cursor, max(0, len(self.entries) - 1))

    def toggle_selection(self):
        if not self.entries:
            return

        path = self.entries[self.cursor]

        path_str = str(path)

        if path_str in self.selected:
            self.selected.remove(path_str)
        else:
            self.selected.add(path_str)

    def go_into(self):
        if not self.entries:
            return

        path = self.entries[self.cursor]

        if path.is_dir():
            self.current_path = path
            self.cursor = 0
            self.load_entries()

    def go_back(self):
        if self.current_path == Path("/"):
            return

        self.current_path = self.current_path.parent
        self.cursor = 0
        self.load_entries()

    def generate_policy(self):
        artifacts = []

        for path_str in sorted(self.selected):
            path = Path(path_str)

            try:
                is_dir = path.is_dir()
            except PermissionError:
                is_dir = False

            artifacts.append({
                "path": path_str,
                "type": "directory" if is_dir else "file",
                "recursive": is_dir,
                "category": "user_defined"
            })

        policy = {
            "version": 1,
            "monitoring": artifacts
        }

        with open(OUTPUT_FILE, "w") as f:
            yaml.safe_dump(
                policy,
                f,
                sort_keys=False,
                default_flow_style=False
            )

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)

        self.load_entries()

        while True:
            stdscr.clear()

            height, width = stdscr.getmaxyx()

            # Header
            stdscr.addstr(
                0,
                0,
                "Artifact Monitor - Filesystem Browser",
                curses.A_BOLD
            )

            stdscr.addstr(
                1,
                0,
                f"Current: {self.current_path}"
            )

            stdscr.addstr(
                2,
                0,
                "↑↓ Navigate | Enter Open | Space Select | Backspace Parent | S Save | Q Quit"
            )

            # Files
            start_row = 4

            for i, path in enumerate(self.entries):

                if start_row + i >= height - 2:
                    break

                prefix = "[DIR]" if path.is_dir() else "[FILE]"

                selected = str(path) in self.selected

                marker = "[✓]" if selected else "[ ]"

                name = path.name

                text = f"{marker} {prefix} {name}"

                if i == self.cursor:
                    attr = curses.A_REVERSE
                else:
                    attr = curses.A_NORMAL

                try:
                    stdscr.addstr(
                        start_row + i,
                        0,
                        text[:width - 1],
                        attr
                    )
                except curses.error:
                    pass

            # Footer
            footer = f"Selected: {len(self.selected)}"

            try:
                stdscr.addstr(
                    height - 1,
                    0,
                    footer[:width - 1],
                    curses.A_BOLD
                )
            except curses.error:
                pass

            key = stdscr.getch()

            if key == curses.KEY_UP:
                self.cursor = max(0, self.cursor - 1)

            elif key == curses.KEY_DOWN:
                self.cursor = min(
                    len(self.entries) - 1,
                    self.cursor + 1
                )

            elif key in (curses.KEY_ENTER, 10, 13):
                self.go_into()

            elif key == ord(" "):
                self.toggle_selection()

            elif key in (curses.KEY_BACKSPACE, 127, 8):
                self.go_back()

            elif key in (ord("s"), ord("S")):
                self.generate_policy()

                stdscr.clear()
                stdscr.addstr(
                    2,
                    2,
                    f"Policy saved to {OUTPUT_FILE}",
                    curses.A_BOLD
                )

                stdscr.addstr(
                    4,
                    2,
                    "Press any key to continue..."
                )

                stdscr.refresh()
                stdscr.getch()

            elif key in (ord("q"), ord("Q")):
                break


def main():
    browser = FileBrowser()
    curses.wrapper(browser.run)


if __name__ == "__main__":
    main()
