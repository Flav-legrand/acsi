// IAM-Local — Génère docs/<guide>.pdf à partir du Markdown, via Chrome/Edge
// headless (aucune dépendance npm). Utilisé par tools/build-guide-pdf.sh
// quand pandoc + wkhtmltopdf ne sont pas installés.
//
//   node tools/guide/build-pdf.mjs [docs/guide-utilisation-iam.md] [sortie.pdf]

import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Browser } from './cdp.mjs';
import { markdownToHtml } from './md2html.mjs';

const src = resolve(process.argv[2] ?? 'docs/guide-utilisation-iam.md');
const out = resolve(process.argv[3] ?? src.replace(/\.md$/, '.pdf'));
const { meta, body, toc } = markdownToHtml(readFileSync(src, 'utf8'));
const title = meta.title ?? 'Guide';

const css = `
@page { size: A4; margin: 22mm 16mm 20mm 16mm; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.5pt; line-height: 1.5; color: #1f2937; }
h1, h2, h3, h4 { color: #0f172a; line-height: 1.25; break-after: avoid; }
h1 { font-size: 20pt; border-bottom: 2px solid #4338ca; padding-bottom: 6px; margin: 0 0 14px; break-before: page; }
h2 { font-size: 14pt; margin: 22px 0 8px; }
h3 { font-size: 12pt; margin: 16px 0 6px; }
h1 .num, h2 .num, h3 .num { color: #4338ca; margin-right: 6px; }
p { margin: 6px 0 8px; }
a { color: #3730a3; text-decoration: none; }
code { font-family: Consolas, "Courier New", monospace; font-size: 9pt; background: #f1f5f9; padding: 0 3px; border-radius: 3px; }
pre { background: #0f172a; color: #e2e8f0; padding: 10px 12px; border-radius: 6px; font-size: 8.5pt; white-space: pre-wrap; word-break: break-word; break-inside: avoid; }
pre code { background: none; color: inherit; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 8px 0 12px; font-size: 9pt; break-inside: auto; }
th, td { border: 1px solid #cbd5e1; padding: 4px 6px; text-align: left; vertical-align: top; }
th { background: #eef2ff; }
tr { break-inside: avoid; }
blockquote { margin: 10px 0; padding: 8px 12px; background: #fffbeb; border-left: 4px solid #f59e0b; }
blockquote p { margin: 2px 0; }
figure { margin: 12px 0 16px; text-align: center; break-inside: avoid; }
figure img { max-width: 100%; max-height: 110mm; border: 1px solid #cbd5e1; border-radius: 4px; }
figcaption { font-size: 9pt; color: #475569; font-style: italic; margin-top: 4px; }
dl dt { font-weight: 600; margin-top: 8px; }
dl dd { margin-left: 18px; }
ul, ol { margin: 4px 0 8px; padding-left: 22px; }
li { margin: 2px 0; }
.cover { height: 240mm; display: flex; flex-direction: column; justify-content: center; text-align: center; }
.cover .t { font-size: 28pt; font-weight: 700; color: #312e81; }
.cover .s { font-size: 14pt; color: #475569; margin-top: 10px; }
.cover .d { font-size: 11pt; color: #64748b; margin-top: 40px; }
.toc-page { break-before: page; }
.toc-page h1.toc-title { break-before: avoid; }
.toc { list-style: none; padding: 0; }
.toc li { margin: 3px 0; }
.toc-l1 { font-weight: 600; margin-top: 10px !important; }
.toc-l2 { padding-left: 22px; font-size: 10pt; }
.toc .num { display: inline-block; min-width: 34px; color: #4338ca; }
`;

const html = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<base href="${pathToFileURL(dirname(src)).href}/"><title>${title}</title><style>${css}</style></head><body>
<section class="cover"><div class="t">${title}</div><div class="s">${meta.subtitle ?? ''}</div><div class="d">${meta.date ?? ''}</div></section>
<section class="toc-page"><h1 class="toc-title">Table des matières</h1>${toc}</section>
${body}
</body></html>`;

const tmp = out.replace(/\.pdf$/, '.tmp.html');
writeFileSync(tmp, html);
const b = await Browser.launch();
try {
  await b.goto(pathToFileURL(tmp).href);
  const small = 'font-family:Segoe UI,Arial,sans-serif;font-size:8px;color:#64748b;width:100%;padding:0 16mm;';
  await b.pdf(out, {
    printBackground: true,
    preferCSSPageSize: true,
    displayHeaderFooter: true,
    headerTemplate: `<div style="${small}display:flex;justify-content:space-between"><span>IAM ACSI</span><span>${title}</span></div>`,
    footerTemplate: `<div style="${small}text-align:center">Page <span class="pageNumber"></span> / <span class="totalPages"></span></div>`,
  });
  console.log(`PDF écrit : ${out}`);
} finally {
  await b.close();
  try { unlinkSync(tmp); } catch { /* déjà supprimé */ }
}
