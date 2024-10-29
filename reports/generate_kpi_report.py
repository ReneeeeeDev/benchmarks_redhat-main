import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Image, Spacer
from reportlab.lib import colors
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            super().showPage()
        super().save()

    def draw_page_number(self, page_count):
        self.drawRightString(200 * mm, 10 * mm, f"Page {self._pageNumber} of {page_count}")


def generate_kpi_pdf_report(results: dict, output_dir='../generados'):
    # Get the current date
    current_date = datetime.now().strftime('%Y-%m-%d_%H_%M')

    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create the output file path with the current date suffix
    output_file = os.path.join(output_dir, f'reporte_kpi_{current_date}.pdf')

    # Create the document
    doc = SimpleDocTemplate(output_file, pagesize=letter,
                            leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=2 * cm, bottomMargin=2 * cm)
    elements = []

    # Add logo
    logo_path = '../resources/ivera_logo.jpg'  # Ensure this path is correct and the file exists
    if os.path.exists(logo_path):
        logo = Image(logo_path)
        logo.drawHeight = 1 * inch
        logo.drawWidth = 2 * inch
        elements.append(logo)

    # Add the title and date
    styles = getSampleStyleSheet()
    title_style = styles['Heading1']
    title = Paragraph("KPI Compliance Report", title_style)
    elements.append(title)

    date_style = styles['Normal']
    execution_date = Paragraph(f"Execution Date: {current_date}", date_style)
    elements.append(execution_date)

    # Calculate overall scoring
    passed_count = sum(1 for result in results if result['PASSED'] is True)
    total_count = len(results)
    overall_score = (passed_count / total_count * 100) if total_count > 0 else 0
    overall_scoring = Paragraph(f"Overall Scoring: {overall_score:.2f}%", date_style)
    elements.append(overall_scoring)

    # Add space
    elements.append(Spacer(1, 0.5 * cm))

    # Calculate scoring per profile
    profile_scores = {}
    for result in results:
        for profile in result['PROFILE']:
            if profile not in profile_scores:
                profile_scores[profile] = {'passed': 0, 'total': 0}
            profile_scores[profile]['total'] += 1
            if result['PASSED']:
                profile_scores[profile]['passed'] += 1

    # Create the table data
    table_data = [['Profile', 'Passed', 'Total', 'Score (%)']]
    for profile, counts in profile_scores.items():
        score = (counts['passed'] / counts['total'] * 100) if counts['total'] > 0 else 0
        table_data.append([
            profile,
            counts['passed'],
            counts['total'],
            f"{score:.2f}"
        ])

    # Create the table
    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkcyan),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
    ])

    # Apply alternating row background colors
    for row_index in range(1, len(table_data)):
        bg_color = colors.beige if row_index % 2 == 0 else colors.white
        table_style.add('BACKGROUND', (0, row_index), (-1, row_index), bg_color)

    table = Table(table_data, colWidths=[2 * inch, 1 * inch, 1 * inch, 1 * inch])
    table.setStyle(table_style)
    elements.append(table)

    # Build the PDF
    doc.build(elements, canvasmaker=NumberedCanvas)
    print(f"KPI PDF report generated: {output_file}")
