#!/usr/bin/env bash
# Publica a pasta demo/ (npm run demo) no ramo gh-pages, que o GitHub Pages serve.
# Usa uma cópia de trabalho à parte: não mexe na pasta atual, na main nem no que ainda não foi commitado.
#
#   bash infra/demo/publicar.sh "mensagem do commit"
set -euo pipefail

RAIZ="$(cd "$(dirname "$0")/../.." && pwd)"
MENSAGEM="${1:-docs(demo): atualiza a demonstração estática}"
[ -f "$RAIZ/demo/index.html" ] || { echo "Gere antes: npm --prefix web run demo" >&2; exit 1; }

COPIA="$(mktemp -d)"
trap 'git -C "$RAIZ" worktree remove --force "$COPIA" 2>/dev/null || true; rm -rf "$COPIA"' EXIT

git -C "$RAIZ" fetch -q origin gh-pages 2>/dev/null || true
if git -C "$RAIZ" rev-parse -q --verify origin/gh-pages >/dev/null; then
  git -C "$RAIZ" worktree add -q -B gh-pages "$COPIA" origin/gh-pages
else
  git -C "$RAIZ" worktree add -q --detach "$COPIA"
  git -C "$COPIA" checkout -q --orphan gh-pages
fi
git -C "$COPIA" rm -rfq --ignore-unmatch .
cp -r "$RAIZ/demo/." "$COPIA/"
# Sem o Jekyll do Pages: ele esconderia arquivos que começam com sublinhado.
touch "$COPIA/.nojekyll"
git -C "$COPIA" add -A
if git -C "$COPIA" diff --cached --quiet; then
  echo "Nada mudou na demonstração."
  exit 0
fi
git -C "$COPIA" commit -q -m "$MENSAGEM"
git -C "$COPIA" push -q origin gh-pages
echo "Publicado no ramo gh-pages."
