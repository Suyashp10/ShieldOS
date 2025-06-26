#Utility Module for HTML Export
def format_check_result(name, description, status, recommendations=None) -> dict:
    """
        Helper function to create a standardized result dictionary.
    Status can be: pass, fail, warn, info
    """
    return  {
        "name": name,
        "description": description,
        "status": status,
        "recommendations": recommendations if recommendations else ""
    }

def summarize_results(sections):
    passed = failed = warning = info = 0

    for section in sections:
        for item in section['items']:
            if not isinstance(item, dict):
                continue  
            if item['status'] == 'pass':
                passed += 1
            elif item['status'] == 'fail':
                failed += 1
            elif item['status'] == 'warn':
                warning += 1
            elif item['status'] == 'info':
                info += 1

    total = passed + failed + warning + info
    return {
        "total_items": total,
        "passed": passed,
        "failed": failed,
        "warnings": warning,
        "info": info
    }

