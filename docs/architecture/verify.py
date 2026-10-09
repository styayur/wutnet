"""Verify the README architecture source without adding runtime dependencies."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import unquote, urlsplit


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--render', action='store_true')
    parser.add_argument('--chrome', help='Optional installed Chrome/Chromium executable')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    evidence = json.loads((root / 'docs/architecture/evidence.json').read_text(encoding='utf-8'))
    readme = (root / evidence['diagram_source']).read_text(encoding='utf-8')
    match = re.findall(r'<!-- architecture:overview:start -->\s*```mermaid\n(.*?)\n```\s*<!-- architecture:overview:end -->', readme, re.S)
    require(len(match) == 1, 'Expected one authoritative overview Mermaid block')
    for source in evidence['sources']:
        path = root / source['path']
        require(path.is_file(), f'Missing source: {source["path"]}')
        text = path.read_text(encoding='utf-8')
        for anchor in source['anchors']:
            require(anchor in text, f'Missing source anchor: {source["path"]}: {anchor}')
    markdowns = [root / 'README.md', root / 'docs/architecture/README.md']
    if (root / 'docs/README.zh-CN.md').exists():
        markdowns.append(root / 'docs/README.zh-CN.md')
    count = 0
    for md in markdowns:
        text = re.sub(r'```.*?```', '', md.read_text(encoding='utf-8'), flags=re.S)
        # Inline links/images, HTML image sources and reference definitions.
        refs = re.findall(r'!?\[[^\]]*\]\(([^\s)]+)(?:\s+[^)]*)?\)', text)
        refs += re.findall(r'<img\b[^>]*\bsrc=["\']([^"\']+)', text, re.I)
        refs += re.findall(r'^\s*\[[^\]]+\]:\s*(\S+)', text, re.M)
        for ref in refs:
            url = urlsplit(ref.strip('<>'))
            if url.scheme or url.netloc or not url.path:
                continue
            path = (root if url.path.startswith('/') else md.parent) / unquote(url.path.lstrip('/'))
            require(path.exists(), f'Missing local reference in {md.name}: {ref}')
            count += 1
    print(f'PASS: authoritative diagram, {len(evidence["sources"])} source files, {count} local references')
    if not args.render:
        return
    npx = shutil.which('npx.cmd') or shutil.which('npx')
    require(npx, 'Node.js/npx is required for --render')
    out = Path(tempfile.mkdtemp(prefix='architecture-'))
    source = out / 'overview.mmd'
    source.write_text(match[0] + '\n', encoding='utf-8')
    config = out / 'mermaid.json'
    config.write_text(json.dumps({'deterministicIds': True, 'deterministicIDSeed': 'architecture-overview', 'flowchart': {'htmlLabels': False}}), encoding='utf-8')
    chrome = args.chrome or os.environ.get('PUPPETEER_EXECUTABLE_PATH')
    browser_args = []
    if chrome:
        require(Path(chrome).is_file(), 'Chrome executable does not exist')
        browser_config = out / 'puppeteer.json'
        browser_config.write_text(json.dumps({'executablePath': chrome}), encoding='utf-8')
        browser_args = ['-p', str(browser_config)]
    renders = []
    for theme, name in [('default', 'light'), ('default', 'light-repeat'), ('dark', 'dark')]:
        svg = out / f'{name}.svg'
        command = [npx, '--yes', '@mermaid-js/mermaid-cli@11.12.0', '-i', str(source), '-o', str(svg), '-c', str(config), '-t', theme, '-b', 'transparent', '-I', 'architecture-overview']
        subprocess.run(command + browser_args, check=True)
        tree = ET.parse(svg)
        require(tree.getroot().tag == '{http://www.w3.org/2000/svg}svg', 'Invalid SVG root')
        require(tree.getroot().get('viewBox'), 'Missing SVG viewBox')
        require(not any(el.tag.endswith('}script') for el in tree.iter()), 'Unexpected script in SVG')
        require('Syntax error' not in ''.join(tree.getroot().itertext()), 'Mermaid rendered an error')
        renders.append(hashlib.sha256(svg.read_bytes()).hexdigest())
    require(renders[0] == renders[1], 'Repeated rendering differs')
    print(f'PASS: Mermaid syntax, light/dark SVG XML, deterministic repeat: {renders[0]}')
    print(f'Verification artifacts: {out}')


if __name__ == '__main__':
    main()
