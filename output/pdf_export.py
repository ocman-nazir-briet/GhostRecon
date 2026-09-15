"""
PDF Export — renders the HTML report to PDF.

Primary path: a headless Chromium instance via Playwright (already a project
dependency, used for screenshots too) opens the exact HTML report and prints
it straight to PDF, preserving the dark theme, gradients and layout
pixel-for-pixel. Falls back to WeasyPrint, then to a print-ready HTML file
the user can print manually if neither is available.
"""

import asyncio
import os
import time

# JS run inside the report page before it's captured: expand every finding
# accordion and hide the interactive-only chrome (sidebar/search/fabs — see
# the `.pdf-export` rules in output/report.py's CSS_BLOCK).
_PDF_PREP_JS = """
() => {
  document.body.classList.add('pdf-export');
  document.querySelectorAll('.fc-body').forEach(el => el.classList.add('open'));
  document.querySelectorAll('.fc-arrow').forEach(el => el.style.transform = 'rotate(180deg)');
}
"""

_PDF_FOOTER_TEMPLATE = (
    "<div style='width:100%;font-size:8px;color:#8b949e;font-family:monospace;"
    "padding:0 12mm;display:flex;justify-content:space-between'>"
    "<span>GhostRecon Security Report</span>"
    "<span>Page <span class='pageNumber'></span> / <span class='totalPages'></span></span>"
    "</div>"
)


async def _render_with_playwright(html_path: str, pdf_path: str) -> bool:
    from playwright.async_api import async_playwright

    file_url = "file://" + os.path.abspath(html_path)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        try:
            page = await browser.new_page()
            await page.goto(file_url, wait_until="networkidle")
            # Let the counter/progress-bar JS animations settle before
            # switching to the static, fully-expanded print layout.
            await page.wait_for_timeout(1200)
            await page.evaluate(_PDF_PREP_JS)
            await page.emulate_media(media="screen")
            await page.pdf(
                path=pdf_path,
                format="A4",
                print_background=True,
                margin={"top": "12mm", "bottom": "16mm", "left": "10mm", "right": "10mm"},
                display_header_footer=True,
                header_template="<div></div>",
                footer_template=_PDF_FOOTER_TEMPLATE,
            )
        finally:
            await browser.close()

    return os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0


def _render_with_weasyprint(html_path: str, pdf_path: str) -> bool:
    from weasyprint import HTML
    HTML(filename=html_path).write_pdf(pdf_path)
    return os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0


async def export_pdf(html_path: str, output_dir: str, target: str, console=None) -> str:
    """
    Convert the HTML report to PDF.
    Returns path to the output file, or "" on failure.
    """
    def log(msg):
        if console:
            console.print(f"  [dim]→[/dim] {msg}")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")
    pdf_path = os.path.join(output_dir, f"report_{safe_target}_{timestamp}.pdf")
    os.makedirs(output_dir, exist_ok=True)

    try:
        log("Rendering PDF with headless Chromium (Playwright)...")
        if await _render_with_playwright(html_path, pdf_path):
            log(f"PDF saved: {pdf_path}")
            return pdf_path
        log("Playwright produced no output — trying WeasyPrint")
    except ImportError:
        log("Playwright not installed — trying WeasyPrint")
    except Exception as e:
        log(f"Playwright PDF render failed: {e} — trying WeasyPrint")

    try:
        log("Generating PDF with WeasyPrint...")
        if await asyncio.to_thread(_render_with_weasyprint, html_path, pdf_path):
            log(f"PDF saved: {pdf_path}")
            return pdf_path
    except ImportError:
        log("WeasyPrint not installed — falling back to a print-ready HTML file")
    except Exception as e:
        log(f"WeasyPrint error: {e} — falling back to a print-ready HTML file")

    # Last resort: a copy of the report that auto-expands its findings and
    # opens the browser's print dialog on load, for a manual "Save as PDF".
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        print_script = (
            "<script>window.addEventListener('load', function(){"
            "document.body.classList.add('pdf-export');"
            "document.querySelectorAll('.fc-body').forEach(function(el){el.classList.add('open');});"
            "setTimeout(function(){ window.print(); }, 600);"
            "});</script>"
        )
        html_content = html_content.replace("</head>", print_script + "</head>", 1)

        printable_path = pdf_path.replace(".pdf", "_printable.html")
        with open(printable_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        log(f"Print-ready HTML saved: {printable_path}")
        log("Open it in a browser — it expands every finding and opens the print dialog (choose 'Save as PDF').")
        if console:
            console.print(
                "  [yellow]⚠[/yellow] For automatic PDF generation, install Playwright's browser: "
                "[dim]playwright install chromium[/dim] (or [dim]pip install weasyprint[/dim])"
            )
        return printable_path

    except Exception as e:
        log(f"PDF export failed: {e}")
        return ""
