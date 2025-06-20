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

def summarize_results(sections: list) -> dict:
    """
         Count result statuses across all sections for summary display.
    """
    passed = failed = warnings = info = 0

    for section in sections:
        for item in section['items']:
            if item['status'] == 'pass':
                passed += 1
            elif item['status'] == 'fail':
                failed += 1
            elif item['status'] == 'warn':
                warnings += 1
            elif item['status'] == 'info':
                info += 1
    
    total = passed + failed + warnings + info
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "warnings": warnings,
        "info": info
    }
