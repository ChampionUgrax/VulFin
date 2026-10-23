
def compare_findings(before: list[dict], after: list[dict]) -> dict:
    """
    Compare findings from two scans.

    before: findings from the original scan
    after: findings from the corrected scan

    Returns resolved, still_present, and new findings.
    """

    # Convert each list into a dictionary indexed by finding ID.
    before_by_id = {item["id"]: item for item in before}
    after_by_id = {item["id"]: item for item in after}

    before_ids = set(before_by_id)
    after_ids = set(after_by_id)

    resolved = [
        before_by_id[finding_id]
        for finding_id in sorted(before_ids - after_ids)
    ]

    still_present = [
        after_by_id[finding_id]
        for finding_id in sorted(before_ids & after_ids)
    ]

    new = [
        after_by_id[finding_id]
        for finding_id in sorted(after_ids - before_ids)
    ]

    return {
        "summary": {
            "resolved": len(resolved),
            "still_present": len(still_present),
            "new": len(new),
        },
        "resolved": resolved,
        "still_present": still_present,
        "new": new,
    }
