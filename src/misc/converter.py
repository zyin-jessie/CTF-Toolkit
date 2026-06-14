from utils.menu import Menu

class Converter:
    def run(self):
        print("\n=== Number / Base Converter ===")
        items = [
            "Hex -> Dec",
            "Dec -> Hex",
            "Bin -> Dec",
            "Dec -> Bin",
            "ASCII -> Hex",
            "Hex -> ASCII",
            "Dec -> ASCII",
            "ASCII -> Bin",
            "Any base to decimal",
        ]
        menu = Menu(items)
        choice = menu.run()
        print()

        if choice == 0:
            v = input("Hex: ").strip()
            try:
                print(f"Dec: {int(v, 16)}")
            except ValueError:
                print("Invalid hex.")
        elif choice == 1:
            v = input("Dec: ").strip()
            try:
                print(f"Hex: {int(v):#x}")
            except ValueError:
                print("Invalid decimal.")
        elif choice == 2:
            v = input("Bin: ").strip()
            try:
                print(f"Dec: {int(v, 2)}")
            except ValueError:
                print("Invalid binary.")
        elif choice == 3:
            v = input("Dec: ").strip()
            try:
                print(f"Bin: {int(v):b}")
            except ValueError:
                print("Invalid decimal.")
        elif choice == 4:
            v = input("ASCII: ").strip()
            print(f"Hex: {v.encode().hex()}")
        elif choice == 5:
            v = input("Hex: ").strip()
            try:
                print(f"ASCII: {bytes.fromhex(v).decode('latin-1')}")
            except ValueError:
                print("Invalid hex.")
        elif choice == 6:
            v = input("Dec (space-separated): ").strip()
            try:
                chars = [chr(int(x)) for x in v.split()]
                print(f"ASCII: {''.join(chars)}")
            except ValueError:
                print("Invalid decimal codes.")
        elif choice == 7:
            v = input("ASCII: ").strip()
            print(f"Bin: {' '.join(format(ord(c), '08b') for c in v)}")
        elif choice == 8:
            v = input("Value: ").strip()
            base_s = input("Source base: ").strip()
            try:
                base = int(base_s)
                print(f"Decimal: {int(v, base)}")
            except ValueError:
                print("Invalid.")

    def get_result(self):
        return {'tool': 'Number Converter'}
