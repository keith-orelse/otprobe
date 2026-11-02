import uuid_utils


def new_id() -> str:
    """UUIDv7: time-ordered, so ids sort by creation time."""
    return str(uuid_utils.uuid7())
