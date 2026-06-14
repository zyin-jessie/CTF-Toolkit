import sys
import tty
import termios

class Menu:
    def __init__(self, items, back=False):
        self.original_items = list(items)
        self.back = back
        self.items = list(items)
        if back:
            self.items.append("Back")
        self.selected = 0
        self._rendered = False

    def run(self):
        self._enable_raw_mode()

        try:
            self._render()
            while True:
                key = self._get_key()
                if key == 'up':
                    self.selected = (self.selected - 1) % len(self.items)
                    self._render()
                elif key == 'down':
                    self.selected = (self.selected + 1) % len(self.items)
                    self._render()
                elif key == 'enter':
                    break
        finally:
            self._disable_raw_mode()

        if self.back and self.selected >= len(self.original_items):
            return None
        return self.selected

    def _render(self):
        if self._rendered:
            sys.stdout.write(f"\033[{len(self.items)}A")
        self._rendered = True

        for i, item in enumerate(self.items):
            sys.stdout.write(f"\r\033[K")
            if i == self.selected:
                sys.stdout.write(f"[\033[92m*\033[0m] {item}\n")
            else:
                sys.stdout.write(f"[ ] {item}\n")
        sys.stdout.flush()

    def _enable_raw_mode(self):
        self._fd = sys.stdin.fileno()
        self._old = termios.tcgetattr(self._fd)
        tty.setraw(self._fd)

    def _disable_raw_mode(self):
        termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old)
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    def _get_key(self):
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()
        byte = sys.stdin.read(1)
        if byte == '\x1b':
            seq = sys.stdin.read(2)
            if seq == '[A':
                return 'up'
            elif seq == '[B':
                return 'down'
        elif byte == '\r':
            return 'enter'
        elif byte == '\x03':
            raise KeyboardInterrupt
        return ''
