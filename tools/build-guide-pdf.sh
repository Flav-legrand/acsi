#!/usr/bin/env bash
# IAM-Local — Génère docs/guide-utilisation-iam.pdf depuis le Markdown.
#
# Ordre de préférence :
#   1. pandoc + wkhtmltopdf (installés) ;
#   2. Node >= 22 + Chrome/Edge : tools/guide/build-pdf.mjs (rien à installer) ;
#   3. sinon, installation de pandoc + wkhtmltopdf (winget, choco, apt ou brew)
#      puis retour au cas 1.
#
# Usage : bash tools/build-guide-pdf.sh [--pandoc]   (--pandoc : impose le cas 1/3)
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=docs/guide-utilisation-iam.md
OUT=docs/guide-utilisation-iam.pdf
FORCE_PANDOC=${1:-}

have() { command -v "$1" >/dev/null 2>&1; }

with_pandoc() {
  echo "→ pandoc + wkhtmltopdf"
  (cd docs && pandoc "$(basename "$SRC")" -o "$(basename "$OUT")" \
    --pdf-engine=wkhtmltopdf --toc --number-sections --resource-path=. \
    --metadata toc-title="Table des matières" \
    --pdf-engine-opt=--enable-local-file-access \
    --pdf-engine-opt=--header-left --pdf-engine-opt="IAM ACSI" \
    --pdf-engine-opt=--header-right --pdf-engine-opt="Guide d'utilisation" \
    --pdf-engine-opt=--header-font-size --pdf-engine-opt=8 \
    --pdf-engine-opt=--footer-center --pdf-engine-opt="Page [page] / [topage]" \
    --pdf-engine-opt=--footer-font-size --pdf-engine-opt=8 \
    -V margin-top=22mm -V margin-bottom=20mm -V margin-left=16mm -V margin-right=16mm)
}

node_ok() {
  have node && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ]
}

install_tools() {
  echo "→ installation de pandoc et wkhtmltopdf"
  if have winget; then
    winget install --silent --accept-package-agreements --accept-source-agreements JohnMacFarlane.Pandoc
    winget install --silent --accept-package-agreements --accept-source-agreements wkhtmltopdf.wkhtmltox
    export PATH="$PATH:/c/Program Files/Pandoc:/c/Program Files/wkhtmltopdf/bin"
  elif have choco; then
    choco install -y pandoc wkhtmltopdf
  elif have apt-get; then
    sudo apt-get update && sudo apt-get install -y pandoc wkhtmltopdf
  elif have brew; then
    brew install pandoc && brew install --cask wkhtmltopdf
  else
    echo "Aucun gestionnaire de paquets reconnu : installez pandoc et wkhtmltopdf manuellement." >&2
    exit 1
  fi
}

if have pandoc && have wkhtmltopdf; then
  with_pandoc
elif [ "$FORCE_PANDOC" != "--pandoc" ] && node_ok && node -e "import('./tools/guide/cdp.mjs').then(m => process.exit(m.findChrome() ? 0 : 1))"; then
  echo "→ Node + Chrome headless (pandoc/wkhtmltopdf absents)"
  node tools/guide/build-pdf.mjs "$SRC" "$OUT"
else
  install_tools
  with_pandoc
fi

echo "PDF : $OUT"
