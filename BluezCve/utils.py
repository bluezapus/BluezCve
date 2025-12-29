def get_severity_from_score(score):
    try:
        score = float(score)
    except (ValueError, TypeError):
        return "UNKNOWN"

    if score == 0.0:
        return "NONE"
    elif score <= 3.9:
        return "LOW"
    elif score <= 6.9:
        return "MEDIUM"
    elif score <= 8.9:
        return "HIGH"
    else:
        return "CRITICAL"

