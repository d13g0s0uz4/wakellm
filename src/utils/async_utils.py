from __future__ import annotations

import asyncio


async def sleep(ms: int) -> None:
    await asyncio.sleep(ms / 1000.0)
