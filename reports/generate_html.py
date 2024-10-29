import os
import pandas as pd
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def generate_html_report(results, output_dir='../generados', template_file='html_report_template.html'):
    # Create a DataFrame of the results
    df = pd.DataFrame(results)

    # Get the current directory
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # Configure Jinja2 Environment with the current directory
    env = Environment(loader=FileSystemLoader(current_dir))
    template = env.get_template(template_file)

    # Get the current date
    current_date = datetime.now().strftime('%Y-%m-%d_%H_%M')

    # Render the template with the data
    html_content = template.render(results=df.to_dict(orient='records'), execution_date=current_date)

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Create the output file path with the current date suffix
    output_file = os.path.join(output_dir, f'report_{current_date}.html')

    # Save the HTML content to a file with UTF-8 encoding
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(html_content)
    print(f"HTML report generated: {output_file}")

if __name__ == '__main__':
    # Example usage
    results = [
        {'TITLE': 'Example Title', 'NUMBER': '1.1.1.1', 'COMMANDS': 'example_command', 'PROFILE': 'Level 1 - Server', 'DESCRIPTION': 'Example description', 'PASSED': 'true'},
        # Add more results here...
    ]
    generate_html_report(results)
