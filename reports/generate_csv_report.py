import csv
import os
from datetime import datetime

def generate_csv_report(results, output_dir='../generados'):
    # Get the current date
    current_date = datetime.now().strftime('%Y-%m-%d_%H_%M')

    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create the output file path with the current date suffix
    output_file = os.path.join(output_dir, f'reporte_{current_date}.csv')

    # Define the CSV column headers
    headers = ['TITLE', 'NUMBER', 'PROFILE', 'DESCRIPTION', 'PASSED']

    # Write the results to the CSV file
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file, delimiter=';')
        writer.writerow(headers)
        for result in results:
            writer.writerow([
                result['TITLE'],
                result['NUMBER'],
                ', '.join(result['PROFILE']),
                result['DESCRIPTION'],
                'Yes' if result['PASSED'] else 'No'
            ])

    print(f"CSV report generated: {output_file}")