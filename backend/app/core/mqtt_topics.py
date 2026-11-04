def topic_matches(topic_filter: str, topic: str) -> bool:
    """MQTT topic filter matching with + (one level) and # (remaining levels)."""
    f_parts, t_parts = topic_filter.split("/"), topic.split("/")
    for i, f in enumerate(f_parts):
        if f == "#":
            return True
        if i >= len(t_parts) or (f != "+" and f != t_parts[i]):
            return False
    return len(f_parts) == len(t_parts)
