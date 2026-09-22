# Binários pré-compilados (Windows)

`port-scanner.exe` (CLI) e `port-scanner-gui.exe` (GUI) — cross-compilados a
partir do código em `windows/` com `mingw-w64`. Baixe o arquivo e rode
diretamente no Windows; não há instalador nem dependências externas.

Para gerar você mesmo: veja `make windows` no `README.md` da raiz do repositório.

Estes binários são commitados manualmente aqui (não há build automatizado/CI
neste repositório); se o código em `windows/` mudar, rode `make windows` e
substitua os arquivos nesta pasta.
