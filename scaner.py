
"""Adapter connecting VulFin's upload interface to the existing scanner."""

import io
import os
import tempfile
import uuid
import zipfile
from pathlib import Path

from Security_Scanner.Scanner import (
    MAX_ZIP_BYTES,
    MAX_ZIP_FILES,
    MAX_ZIP_UNPACKED_BYTES,
    _safe_zip_members,
    scan_project as _scan_project,
)


def scan_project(zip_bytes: bytes, filename: str) -> dict:
    """Scan an uploaded ZIP and return VulFin-compatible results."""

    if not isinstance(zip_bytes, bytes) or not zip_bytes:
        raise ValueError("The uploaded ZIP file is empty or invalid.")

    if len(zip_bytes) > MAX_ZIP_BYTES:
        raise ValueError("The uploaded ZIP exceeds the size limit.")

    if not filename.lower().endswith(".zip"):
        raise ValueError("Please upload a ZIP archive.")

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            safe, reason = _safe_zip_members(archive)
            if not safe:
                raise ValueError(reason)

            with tempfile.TemporaryDirectory(prefix="vulfin_scan_") as temp_dir:
                archive.extractall(temp_dir)

                report = _scan_project(temp_dir)

                # The temporary directory disappears after this block.
                # Replace its path with the uploaded filename.
                report["target"] = Path(filename).name
                report["target_type"] = "zip_archive"
                report["scan_id"] = str(uuid.uuid4())

                if not isinstance(report.get("findings"), list):
                    raise ValueError("Scanner returned invalid findings.")

                return report

    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc
