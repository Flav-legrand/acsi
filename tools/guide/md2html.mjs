// IAM-Local — Conversion Markdown → HTML, sans dépendance, pour le guide.
// Couvre le sous-ensemble utilisé dans docs/*.md : bloc YAML de tête,
// titres numérotés (comme pandoc --number-sections) + sommaire, paragraphes,
// listes imbriquées, tableaux, blocs de code, citations, images + légende,
// listes de définitions, gras, italique, code, liens, barré.

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function inline(text) {
  const codes = [];
  let s = text.replace(/`([^`]+)`/g, (_, c) => `\u0000${codes.push(c) - 1}\u0000`);
  s = esc(s);
  s = s.replace(/!\[([^\]]*)\]\(([^)\s]+)\)/g, '<img alt="$1" src="$2">')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2">$1</a>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/~~([^~]+)~~/g, '<del>$1</del>')
    .replace(/(^|[^*\w])\*([^*\s][^*]*?)\*(?!\w)/g, '$1<em>$2</em>');
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => `<code>${esc(codes[Number(i)])}</code>`);
}

const indentOf = (l) => l.match(/^ */)[0].length;
const isBlank = (l) => l.trim() === '';
const LIST = /^( *)([-*]|\d+[.)]) +(.*)$/;

function splitRow(line) {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
}

/** Analyse une suite de lignes en blocs HTML. ctx porte la numérotation. */
function blocks(lines, ctx) {
  let out = '';
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (isBlank(line)) { i++; continue; }

    // Bloc de code
    const fence = line.match(/^ *```(\w*)/);
    if (fence) {
      const body = [];
      i++;
      while (i < lines.length && !/^ *```/.test(lines[i])) body.push(lines[i++]);
      i++;
      out += `<pre><code class="lang-${fence[1] || 'text'}">${esc(body.join('\n'))}</code></pre>\n`;
      continue;
    }

    // Titre
    const h = line.match(/^(#{1,6}) +(.*)$/);
    if (h) {
      const level = h[1].length;
      ctx.counters[level - 1]++;
      ctx.counters.fill(0, level);
      const num = ctx.counters.slice(0, level).join('.');
      const id = `sec-${num.replace(/\./g, '-')}`;
      ctx.toc.push({ level, num, id, text: h[2] });
      out += `<h${level} id="${id}"><span class="num">${num}</span> ${inline(h[2])}</h${level}>\n`;
      i++;
      continue;
    }

    // Citation
    if (/^ *>/.test(line)) {
      const body = [];
      while (i < lines.length && /^ *>/.test(lines[i])) body.push(lines[i++].replace(/^ *> ?/, ''));
      out += `<blockquote>${blocks(body, ctx)}</blockquote>\n`;
      continue;
    }

    // Tableau
    if (line.trim().startsWith('|') && i + 1 < lines.length && /^ *\|? *:?-{3,}/.test(lines[i + 1])) {
      const head = splitRow(line);
      i += 2;
      let rows = '';
      while (i < lines.length && lines[i].trim().startsWith('|')) {
        rows += '<tr>' + splitRow(lines[i++]).map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>';
      }
      out += `<table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>\n`;
      continue;
    }

    // Image seule (+ légende en italique sur la ligne suivante)
    const img = line.match(/^ *!\[([^\]]*)\]\(([^)\s]+)\) *$/);
    if (img) {
      i++;
      while (i < lines.length && isBlank(lines[i])) i++;
      let caption = '';
      const cap = i < lines.length && lines[i].match(/^ *\*([^*].*)\* *$/);
      if (cap) { caption = `<figcaption>${inline(cap[1])}</figcaption>`; i++; }
      out += `<figure><img alt="${esc(img[1])}" src="${img[2]}">${caption}</figure>\n`;
      continue;
    }

    // Liste
    const li = line.match(LIST);
    if (li) {
      const base = li[1].length;
      const ordered = /\d/.test(li[2]);
      let items = '';
      while (i < lines.length) {
        const m = lines[i].match(LIST);
        if (!m || m[1].length !== base || /\d/.test(m[2]) !== ordered) break;
        const contentIndent = base + m[2].length + 1;
        const body = [m[3]];
        i++;
        while (i < lines.length) {
          const l = lines[i];
          if (isBlank(l)) {
            const next = lines.slice(i + 1).find((x) => !isBlank(x));
            if (next !== undefined && indentOf(next) >= contentIndent - 1 && indentOf(next) > base) { body.push(''); i++; continue; }
            break;
          }
          if (indentOf(l) > base) { body.push(l.slice(Math.min(indentOf(l), contentIndent))); i++; continue; }
          if (LIST.test(l) || /^ *(#|```|>|\|)/.test(l)) break;
          body.push(l.trim()); i++; // continuation paresseuse
        }
        const simple = body.every((b) => !isBlank(b) && !LIST.test(b) && !/^ *(```|>|\|)/.test(b));
        items += `<li>${simple ? inline(body.join(' ')) : blocks(body, ctx)}</li>`;
      }
      out += ordered ? `<ol>${items}</ol>\n` : `<ul>${items}</ul>\n`;
      continue;
    }

    // Liste de définitions (Terme\n: définition)
    if (i + 1 < lines.length && /^: /.test(lines[i + 1])) {
      let dl = '';
      while (i + 1 < lines.length && !isBlank(lines[i]) && /^: /.test(lines[i + 1])) {
        const term = lines[i];
        const body = [lines[i + 1].slice(2)];
        i += 2;
        while (i < lines.length && (/^ {2,}/.test(lines[i]) || (isBlank(lines[i]) && /^ {2,}\S/.test(lines[i + 1] ?? '')))) {
          body.push(lines[i].replace(/^ {2}/, '')); i++;
        }
        dl += `<dt>${inline(term)}</dt><dd>${blocks(body, ctx)}</dd>`;
        while (i < lines.length && isBlank(lines[i]) && i + 2 < lines.length && /^: /.test(lines[i + 2])) i++;
      }
      out += `<dl>${dl}</dl>\n`;
      continue;
    }

    // Paragraphe
    const para = [];
    while (i < lines.length && !isBlank(lines[i]) && !/^ *(#{1,6} |```|>|\||!\[)/.test(lines[i]) && !LIST.test(lines[i])) {
      para.push(lines[i++].trim());
    }
    if (!para.length) { para.push(lines[i++].trim()); }
    out += `<p>${inline(para.join(' '))}</p>\n`;
  }
  return out;
}

/** @return {{meta: object, body: string, toc: string}} */
export function markdownToHtml(md) {
  const meta = {};
  let text = md.replace(/\r\n/g, '\n');
  const fm = text.match(/^---\n([\s\S]*?)\n---\n/);
  if (fm) {
    for (const l of fm[1].split('\n')) {
      const m = l.match(/^(\w+):\s*"?(.*?)"?\s*$/);
      if (m) meta[m[1]] = m[2];
    }
    text = text.slice(fm[0].length);
  }
  const ctx = { counters: [0, 0, 0, 0, 0, 0], toc: [] };
  const body = blocks(text.split('\n'), ctx);
  const toc = '<ul class="toc">' + ctx.toc.filter((t) => t.level <= 2)
    .map((t) => `<li class="toc-l${t.level}"><a href="#${t.id}"><span class="num">${t.num}</span> ${inline(t.text)}</a></li>`).join('') + '</ul>';
  return { meta, body, toc };
}
