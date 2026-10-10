"""Build the paper PDF from its Markdown source (source file is not modified).

    python3 build/build_pdf.py [--src SARWP_working_paper_v1.2.md] [--out file.pdf] [--doi 10.5281/zenodo.NNNN]

Pipeline: preprocess Markdown (Mermaid diagram -> inline SVG; optional DOI in status line)
-> pandoc (MathML, standalone HTML with print CSS) -> headless Chrome print to PDF.
"""
import argparse
import html
import os
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE  # in the repository the sources sit next to this script
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")

BUILD = pathlib.Path(os.environ.get("BUILD_DIR", "/tmp/sarwp-build"))

CSS = r"""
@page { size: A4; margin: 22mm 20mm 22mm 20mm; }
html { font-size: 10.5pt; }
body { font-family: "Charter", "Georgia", "Times New Roman", serif; line-height: 1.42; color: #111;
       max-width: none; margin: 0; padding: 0; hyphens: auto; text-align: justify; }
h1 { font-size: 17pt; line-height: 1.25; text-align: center; margin: 0 0 10pt; font-weight: 700; }
h2 { font-size: 13pt; margin: 18pt 0 6pt; break-after: avoid; }
h3 { font-size: 11pt; margin: 12pt 0 4pt; break-after: avoid; }
h4 { font-size: 10.5pt; margin: 10pt 0 3pt; font-style: italic; break-after: avoid; }
p { margin: 0 0 6pt; orphans: 3; widows: 3; }
.frontmatter p { text-align: center; margin: 0 0 2pt; }
.frontmatter { margin-bottom: 14pt; }
ul, ol { margin: 0 0 6pt; padding-left: 18pt; }
li { margin: 0 0 2pt; }
code { font-family: "Menlo", "SFMono-Regular", monospace; font-size: 8.6pt; }
pre { font-size: 8.4pt; line-height: 1.3; background: #f5f5f5; border: 0.5pt solid #ddd;
      padding: 6pt 8pt; white-space: pre-wrap; break-inside: avoid; text-align: left; }
table { border-collapse: collapse; width: 100%; margin: 6pt 0 10pt; font-size: 9pt;
        break-inside: auto; text-align: left; }
th, td { border-top: 0.5pt solid #999; border-bottom: 0.5pt solid #999; padding: 3pt 5pt;
         vertical-align: top; }
th { background: #efefef; }
tr { break-inside: avoid; }
blockquote { margin: 6pt 18pt; color: #333; }
hr { border: none; border-top: 0.5pt solid #999; margin: 14pt 0; }
math { font-size: 1.05em; }
math[display="block"] { margin: 6pt 0; }
figure.flow { margin: 8pt auto 10pt; text-align: center; break-inside: avoid; }
.keep { break-inside: avoid; }
a { color: #0b4f8a; text-decoration: none; word-break: break-word; }
"""


def flow_svg(labels):
    w, bh, gap, x0 = 300, 26, 14, 10
    h = len(labels) * (bh + gap) - gap + 2
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w + 2 * x0}" height="{h}" '
             f'viewBox="0 0 {w + 2 * x0} {h}" font-family="Georgia, serif" font-size="11">',
             '<defs><marker id="ar" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">'
             '<path d="M0,0 L8,4 L0,8 z" fill="#333"/></marker></defs>']
    for i, lab in enumerate(labels):
        y = 1 + i * (bh + gap)
        parts.append(f'<rect x="{x0}" y="{y}" width="{w}" height="{bh}" rx="4" fill="#f4f6f8" stroke="#333" stroke-width="0.8"/>')
        parts.append(f'<text x="{x0 + w / 2}" y="{y + bh / 2 + 4}" text-anchor="middle">{html.escape(lab)}</text>')
        if i < len(labels) - 1:
            parts.append(f'<line x1="{x0 + w / 2}" y1="{y + bh}" x2="{x0 + w / 2}" y2="{y + bh + gap - 2}" '
                         'stroke="#333" stroke-width="0.8" marker-end="url(#ar)"/>')
    parts.append("</svg>")
    return "".join(parts)


def replace_mermaid(md):
    def repl(m):
        labels, seen = [], set()
        for a, b in re.findall(r"(\w+)\[([^\]]+)\]", m.group(1)):
            if a not in seen:
                seen.add(a)
                labels.append(b)
        return f'\n<figure class="flow">{flow_svg(labels)}</figure>\n'
    md = re.sub(r"```mermaid\n(.*?)```", repl, md, flags=re.S)
    # keep the sentence introducing the figure on the same page as the figure
    return re.sub(r"\n([^\n]+:)\n\n?(<figure class=\"flow\">.*?</figure>)",
                  r'\n<div class="keep">\n\n\1\n\n\2\n\n</div>', md, flags=re.S)


def wrap_frontmatter(md):
    # lines 3-6 of the source (version/date/author/status) become a centred block
    lines = md.split("\n")
    i = 2
    block = []
    while i < len(lines) and lines[i].startswith("**"):
        block.append(lines[i].rstrip())
        i += 1
    fm = '<div class="frontmatter">\n\n' + "\n\n".join(b.rstrip(" ") for b in block) + "\n\n</div>\n"
    return "\n".join(lines[:2]) + "\n" + fm + "\n".join(lines[i:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--doi")
    ap.add_argument("--src", default=str(ROOT / "SARWP_working_paper_v1.2.md"))
    ap.add_argument("--out")
    args = ap.parse_args()
    SRC = pathlib.Path(args.src).resolve()
    OUT = (pathlib.Path(args.out) if args.out else SRC.with_suffix(".pdf")).resolve()
    BUILD.mkdir(parents=True, exist_ok=True)
    md = SRC.read_text(encoding="utf-8")
    if args.doi:
        old = "**Status:** Preprint draft, not yet submitted"
        assert old in md
        md = md.replace(old, f"**Status:** Preprint · DOI: [{args.doi}](https://doi.org/{args.doi})")
    md = wrap_frontmatter(replace_mermaid(md))
    (BUILD / "paper.css").write_text(CSS, encoding="utf-8")
    pre = BUILD / "paper_pre.md"
    pre.write_text(md, encoding="utf-8")
    out_html = BUILD / "paper.html"
    title = md.split("\n", 1)[0].lstrip("# ").strip()
    subprocess.run(["pandoc", str(pre), "-f", "markdown+tex_math_dollars+pipe_tables+lists_without_preceding_blankline", "-t", "html5", "-s",
                    "--mathml", "--metadata", f"pagetitle={title}", "--css", "paper.css",
                    "-o", str(out_html)], check=True, cwd=BUILD)
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                    "--generate-pdf-document-outline", f"--print-to-pdf={OUT}", out_html.as_uri()],
                   check=True, cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    sys.exit(main())
