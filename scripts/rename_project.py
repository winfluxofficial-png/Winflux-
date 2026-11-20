#!/usr/bin/env python3
"""Renomeia o projeto (diretório do pacote + conteúdo dos arquivos).

Uso, a partir da raiz do repositório:

    python scripts/rename_project.py                      # padrão: Winflux / WFLX
    python scripts/rename_project.py --new-name Outro --new-symbol OTR
    python scripts/rename_project.py --dry-run

O nome e o símbolo ATUAIS são detectados sozinhos: o pacote é o diretório que contém `crypto/address.py` e o
símbolo vem do PREFIX de endereço (ex.: "wflx1"). Substitui, nesta ordem: NOME, Nome, nome, <sim>k1 (chave de
recuperação), <sim>1 (prefixo de endereço), SÍMBOLO e <sim> (domínios de assinatura "SIM-…").
Não toca em `docs/naming.md` (histórico de nomes) nem neste script. Rode os testes depois.
ATENÇÃO: mudar o símbolo muda endereços e assinaturas: só é seguro enquanto não há rede pública.
"""
import argparse
import os
import re
import sys

SKIP_FILES = {os.path.join("docs", "naming.md"), os.path.join("scripts", "rename_project.py")}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv"}
EXTS = (".py", ".md", ".ini", ".txt", ".toml", ".json", ".html", ".js", ".kt", ".gradle")


def detect(root: str):
    for d in sorted(os.listdir(root)):
        p = os.path.join(root, d, "crypto", "address.py")
        if os.path.isfile(p):
            m = re.search(r'PREFIX\s*=\s*"([a-z0-9]+)1"', open(p, encoding="utf-8").read())
            if m:
                return d, m.group(1)
    sys.exit("não encontrei o pacote (diretório com crypto/address.py)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--new-name", default="Winflux")
    ap.add_argument("--new-symbol", default="WFLX")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    root = os.getcwd()
    old_pkg, old_sym = detect(root)
    new_pkg, new_sym = a.new_name.lower(), a.new_symbol.lower()
    if (old_pkg, old_sym) == (new_pkg, new_sym):
        sys.exit("nada a fazer: o projeto já usa esse nome e símbolo")
    pairs = [(old_pkg.upper(), a.new_name.upper()), (old_pkg.capitalize(), a.new_name), (old_pkg, new_pkg),
             (old_sym + "k1", new_sym + "k1"), (old_sym + "1", new_sym + "1"),
             (old_sym.upper(), new_sym.upper()), (old_sym, new_sym)]
    changed = 0
    for dp, dn, files in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in files:
            path = os.path.join(dp, f)
            rel = os.path.relpath(path, root)
            if rel in SKIP_FILES or not f.endswith(EXTS):
                continue
            s = open(path, encoding="utf-8").read()
            o = s
            for old, new in pairs:
                s = s.replace(old, new)
            if s != o:
                changed += 1
                if not a.dry_run:
                    open(path, "w", encoding="utf-8").write(s)
    print(f"{old_pkg}/{old_sym.upper()} -> {new_pkg}/{new_sym.upper()}: {changed} arquivo(s) "
          f"{'seriam alterados' if a.dry_run else 'alterados'}")
    if not a.dry_run:
        os.rename(os.path.join(root, old_pkg), os.path.join(root, new_pkg))
        print(f"pacote renomeado: {old_pkg}/ -> {new_pkg}/")


if __name__ == "__main__":
    main()
