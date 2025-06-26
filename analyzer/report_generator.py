# analyzer/report_generator.py
import os
from analyzer.utils import DEST_DIR

# In-memory structured report holder
report_data = {
    "APKs": [],
    "PDFs": [],
    "Texts": [],
    "Images": []
}

def store_result(category, result_dict):
    """
    Stores a single result in the appropriate category.

    Parameters:
    - category (str): One of 'APKs', 'PDFs', 'Texts', 'Images'
    - result_dict (dict): {
          'filename': str,
          'score': int,
          'risk_level': str,
          'path': str
      }
    """
    if category in report_data:
        report_data[category].append(result_dict)
    else:
        print(f"⚠️ Unknown category '{category}' passed to store_result.")

def get_final_report():
    """
    Returns the entire report dictionary categorized by file types.
    """
    return report_data

def reset_report():
    """
    Clears all stored scan results before a fresh scan.
    """
    for k in report_data:
        report_data[k].clear()
