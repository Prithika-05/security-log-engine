import asyncio

import pytest


async def slow_operation() -> str:
    await asyncio.sleep(0.01)
    return "finished"


@pytest.mark.asyncio
async def test_slow_operation():
    result = await slow_operation()

    assert result == "finished"