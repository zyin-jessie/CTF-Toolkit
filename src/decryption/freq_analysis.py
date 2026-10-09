import string

ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074,
}

class FreqAnalysis:
    def run(self):
        print("\n=== Frequency Analysis ===")
        text = input("Enter text: ")
        if not text:
            print("No input.")
            return

        letters = [c.lower() for c in text if c.isalpha()]
        total = len(letters)
        if total == 0:
            print("No letters to analyze.")
            return

        counts = {c: 0 for c in string.ascii_lowercase}
        for c in letters:
            counts[c] += 1

        print(f"\nLetters: {total}  |  Unique: {sum(1 for v in counts.values() if v)}")
        print("Letter  Count   Freq%    English%   Bar")
        print("-" * 56)
        for c in sorted(counts, key=lambda k: counts[k], reverse=True):
            if counts[c] == 0:
                continue
            pct = counts[c] / total * 100
            bar = '#' * int(pct / 2)
            print(f"  {c}     {counts[c]:5d}   {pct:5.2f}    {ENGLISH_FREQ[c]:5.2f}      {bar}")

        print(f"\nIndex of Coincidence: {self._ioc(counts, total):.4f}")
        print("  (English text ~0.0667, random ~0.0385)")
        self._suggest_caesar(counts, total)

    def _ioc(self, counts, total):
        if total < 2:
            return 0.0
        return sum(n * (n - 1) for n in counts.values()) / (total * (total - 1))

    def _suggest_caesar(self, counts, total):
        # chi-squared fit against English for each Caesar shift; lowest = best guess
        observed = [counts[chr(ord('a') + i)] for i in range(26)]
        expected = [ENGLISH_FREQ[chr(ord('a') + i)] / 100 * total for i in range(26)]
        scores = []
        for shift in range(26):
            chi = 0.0
            for i in range(26):
                o = observed[(i + shift) % 26]
                e = expected[i]
                if e > 0:
                    chi += (o - e) ** 2 / e
            scores.append((chi, shift))
        scores.sort()
        print("\nLikely Caesar shifts (chi-squared, lower = better):")
        for chi, shift in scores[:3]:
            print(f"  shift {shift:2d}  (score {chi:8.2f})")
