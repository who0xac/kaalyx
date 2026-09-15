#!/usr/bin/env python3
"""Manual test for the OSINT live board's resistance to terminal interaction.

Run this in a real terminal (Kali), then WHILE it runs for ~20s:
  * press random keys (they should NOT echo onto the screen), and
  * resize the terminal window a few times.
The board must remain ONE frame updating in place — it must NOT reprint as
stacked duplicate frames. Ctrl-C to stop early.

    python3 scripts/test_board_robustness.py
"""
import asyncio, random, time
from kaalyx.ui.osint_ui import OsintProgress

LABELS = {f"src{i}": f"Source {i:02d}" for i in range(1, 13)}


async def main():
    p = OsintProgress(LABELS)
    names = list(LABELS)
    with p.live():
        # Kick everything into 'running', then finish them one by one over ~20s.
        for n in names:
            p.hook("start", n, None)
        for i, n in enumerate(names):
            await asyncio.sleep(random.uniform(1.2, 2.0))
            res = type("R", (), {"total": random.randint(0, 40), "ok": True,
                                 "skipped": False, "note": ""})()
            p.hook("finish", n, res)
    print("\nDone. Did the board stay a SINGLE updating frame the whole time? "
          "(no stacked duplicates, no echoed keystrokes)")


if __name__ == "__main__":
    asyncio.run(main())
