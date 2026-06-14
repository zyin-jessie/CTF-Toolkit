# Contributing to PwnStar-Toolkit

## Contributors

Thanks for your interest in contributing. This project is a modular Python CLI for CTF and security workflows — every tool is a self-contained class wired into a shared menu system.

<a href="https://github.com/zyin-jessie/PwnStar-Toolkit/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=zyin-jessie/PwnStar-Toolkit" />
</a>

## Prerequisites

- **Python** 3.14.0 or higher
- **Git** 2.45.1 or higher

No third-party dependencies are required for the core toolkit.

## Getting Started

```bash
git clone https://github.com/zyin-jessie/PwnStar-Toolkit.git
cd PwnStar-Toolkit
chmod +x pwnstar
./pwnstar
```

Run directly during development:

```bash
python3 src/main.py
```

## Project Layout

```
toolkit/
├── pwnstar              # Bash launcher (Linux / macOS)
├── pwnstar.bat          # Batch launcher (Windows)
├── LICENSE
├── README.md
├── public/
│   ├── toolkit.png
│   └── payload/
│       └── rockyou.txt  # Default wordlist for dictionary attacks
└── src/
    ├── main.py          # Entry point — wires all tools into menus
    ├── decryption/      # Hash cracking, cipher identification, Vigenère
    ├── encoding/        # Codecs and cipher transforms (EncDec)
    ├── encryption/      # Low-level crypto (XOR)
    ├── forensics/       # File analysis, hex dump, strings
    ├── steganography/   # LSB, EXIF metadata
    ├── misc/            # JWT decode, converter, password generator
    └── utils/           # Menu, banner, payload loader
```

## Architecture

Each tool follows the same pattern:

1. **One class per module** — e.g. `JWTDecode`, `FileAnalyzer`, `HashCrack`
2. **`run()`** — interactive CLI entry point; prompts for input and prints results
3. **`get_result()`** — returns a dict describing the tool (used for registration/discovery)
4. **Menu integration** — interactive tools use `Menu` from `utils/menu.py` for arrow-key navigation

`PwnStarToolkit` in `src/main.py` instantiates every tool and routes the top-level menus. New tools must be imported and wired into the appropriate submenu there.

### Where to put new code

| Kind of tool | Directory |
|--------------|-----------|
| Hash or cipher cracking/identification | `src/decryption/` |
| Encoding, decoding, classical ciphers | `src/encoding/` or `src/encryption/` |
| Binary / file forensics | `src/forensics/` |
| Image steganography or metadata | `src/steganography/` |
| General utilities | `src/misc/` |
| Shared UI or helpers | `src/utils/` |

## Adding a New Tool

1. Create a new module in the appropriate directory under `src/`.
2. Implement a class with at least `run()` and `get_result()`.
3. Import and instantiate it in `PwnStarToolkit.__init__()` in `src/main.py`.
4. Add a menu entry in the relevant `_…_menu()` method.
5. Test manually via `./pwnstar` or `python3 src/main.py`.

Minimal example:

```python
# src/misc/my_tool.py
class MyTool:
    def run(self):
        print("\n=== My Tool ===")
        value = input("Input: ").strip()
        print(f"Result: {value}")

    def get_result(self):
        return {'tool': 'My Tool'}
```

Then in `src/main.py`:

```python
from misc.my_tool import MyTool

# in __init__:
self.my_tool = MyTool()

# in the appropriate submenu:
elif choice == N:
    self.my_tool.run()
```

For menu-driven tools, follow `src/misc/converter.py` or `src/steganography/lsb.py` — use `Menu(items, back=True)` and handle `None` as "Back".

For hash tools that need wordlists, use `Payload` from `utils/payload.py` to locate files under `public/payload/`.

## Code Style

Match the existing codebase:

- Plain Python classes, no framework
- Keep imports at the top of each file
- Use relative-style imports from `src/` (e.g. `from utils.menu import Menu`)
- Interactive output via `print()` and `input()`
- Terminal colors via ANSI escape codes where needed (see `utils/menu.py`, `misc/jwt_decode.py`)
- No unnecessary abstractions — one file, one tool, one class

## Pull Requests

1. Fork the repo and create a feature branch from `main`.
2. Keep changes focused — one tool or one fix per PR when possible.
3. Test your changes on Linux or macOS (Windows via `pwnstar.bat` if applicable).
4. Update `README.md` if you add a user-facing feature.
5. Open a PR with a clear description of what the change does and how to test it.

## Ideas Welcome

The README lists planned work that contributors can pick up:

- Additional classical ciphers (Affine, Beaufort, etc.)
- Frequency analysis and pattern detection
- Workspace mode for saving outputs
- Modular plugin system for community extensions

If you plan something larger, open an issue first so we can align on design before you invest significant time.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
