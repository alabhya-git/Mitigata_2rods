from __future__ import annotations

import io
import zipfile


def archive_members(raw, limit):
    """Read bounded ZIP members in memory. Never extract paths or execute contents."""
    total = 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for item in archive.infolist()[:24]:
            if (
                item.is_dir()
                or item.flag_bits & 1
                or item.file_size > limit
                or item.file_size > max(1, item.compress_size) * 100
            ):
                continue
            if total + item.file_size > limit:
                break
            with archive.open(item) as source:
                content = source.read(min(limit - total, item.file_size) + 1)
            if len(content) > item.file_size:
                continue
            total += len(content)
            yield item.filename[:200], content
