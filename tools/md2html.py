#!/usr/bin/env python3
"""Minimal markdown -> styled HTML converter for the two paper files.
Supports: headings, tables, fenced code, ordered/unordered lists, blockquote-free
paragraphs, inline bold/italic/code/links. Good enough for this repo's MD style."""
import html, re, sys

def inline(s):
    s = html.escape(s, quote=False)
    s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)
    s = re.sub(r'(?<!\w)\*([^*]+)\*(?!\w)', r'<em>\1</em>', s)
    s = re.sub(r'`([^`]+)`', r'<code>\1</code>', s)
    s = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', s)
    return s

def convert(md_text):
    out, lines, i = [], md_text.splitlines(), 0
    in_code = False
    para, list_open, table_buf = [], None, []

    def flush_para():
        nonlocal para
        if para:
            out.append('<p>' + '<br>'.join(inline(l) for l in para) + '</p>')
            para = []

    def flush_list():
        nonlocal list_open
        if list_open:
            out.append(f'</{list_open}>')
            list_open = None

    def flush_table():
        nonlocal table_buf
        if not table_buf:
            return
        rows = [r for r in table_buf if not re.match(r'^\s*\|?[\s:|-]+\|?\s*$', r)]
        head, *body = [ [c.strip() for c in r.strip().strip('|').split('|')] for r in rows ]
        out.append('<table><thead><tr>' + ''.join(f'<th>{inline(c)}</th>' for c in head) + '</tr></thead><tbody>')
        for r in body:
            out.append('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>')
        out.append('</tbody></table>')
        table_buf = []

    while i < len(lines):
        ln = lines[i]
        if ln.startswith('```'):
            flush_para(); flush_list(); flush_table()
            in_code = not in_code
            out.append('<pre><code>' if in_code else '</code></pre>')
            i += 1; continue
        if in_code:
            out.append(html.escape(ln)); i += 1; continue
        if ln.strip().startswith('|'):
            flush_para(); flush_list(); table_buf.append(ln); i += 1; continue
        elif table_buf:
            flush_table()
        m = re.match(r'^(#{1,4})\s+(.*)', ln)
        if m:
            flush_para(); flush_list()
            lvl = len(m.group(1)) + 1
            out.append(f'<h{lvl}>{inline(m.group(2))}</h{lvl}>')
            i += 1; continue
        if ln.strip() == '---':
            flush_para(); flush_list(); out.append('<hr>'); i += 1; continue
        m = re.match(r'^\s*[-*]\s+(.*)', ln)
        if m:
            flush_para()
            if list_open != 'ul':
                flush_list(); out.append('<ul>'); list_open = 'ul'
            out.append('<li>' + inline(m.group(1)) + '</li>'); i += 1; continue
        m = re.match(r'^\s*(\d+)\.\s+(.*)', ln)
        if m:
            flush_para()
            if list_open != 'ol':
                flush_list(); out.append('<ol>'); list_open = 'ol'
            out.append('<li>' + inline(m.group(2)) + '</li>'); i += 1; continue
        if not ln.strip():
            flush_para(); flush_list(); i += 1; continue
        para.append(ln); i += 1
    flush_para(); flush_list(); flush_table()
    return '\n'.join(out)

STYLE = """
:root { --fg:#1a1a1a; --muted:#666; --accent:#1a4f8b; --border:#ddd; --card:#f7f7f9; }
body { font-family:'Segoe UI',Georgia,serif; color:var(--fg); max-width:760px; margin:40px auto;
       padding:0 24px; line-height:1.6; font-size:15px; }
h1 { font-size:1.9em; border-bottom:3px solid var(--accent); padding-bottom:.3em; }
h2 { font-size:1.4em; border-bottom:1px solid var(--border); padding-bottom:.2em; margin-top:1.8em; }
h3 { font-size:1.15em; margin-top:1.4em; }
table { border-collapse:collapse; margin:1em 0; width:100%; font-size:.92em; }
th,td { border:1px solid var(--border); padding:6px 10px; text-align:left; vertical-align:top; }
th { background:var(--card); }
pre { background:var(--card); border:1px solid var(--border); padding:12px; overflow-x:auto;
      font-size:.85em; border-radius:4px; }
code { font-family:Consolas,monospace; font-size:.92em; background:var(--card); padding:1px 4px; border-radius:3px; }
pre code { background:none; padding:0; }
blockquote { border-left:3px solid var(--accent); margin:1em 0; padding:.2em 1em; color:var(--muted); }
a { color:var(--accent); }
hr { border:none; border-top:1px solid var(--border); margin:2em 0; }
@media print { body { margin:0 auto; } h2 { page-break-after:avoid; } }
"""

def main(md_path, html_path, title):
    with open(md_path, encoding='utf-8') as f:
        body = convert(f.read())
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(f'<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title>'
                f'<style>{STYLE}</style></head><body>\n{body}\n</body></html>')
    print('wrote', html_path)

if __name__ == '__main__':
    main(*sys.argv[1:4])
