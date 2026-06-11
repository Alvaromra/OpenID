# ctxcap — Context Capsules

Formato portável e verificável para transmitir contexto entre sessões de chat com IA, reduzindo alucinação com integridade criptográfica.

## O problema

Modelos de linguagem inventam quando não sabem (alucinação) e esquecem o contexto ao abrir um chat novo. Colar texto bruto funciona, mas não prova que o conteúdo é o original, nem instrui o modelo a admitir quando algo está fora do que foi fornecido.

## A solução

O ctxcap empacota fatos/documentos numa cápsula onde cada trecho tem um CID (hash SHA-256 do próprio conteúdo, padrão CIDv1/IPFS). Gera um prompt de aterramento que instrui o modelo a responder só com base nos fatos fornecidos, citar a origem, e dizer "fora do contexto" em vez de inventar.

## Funcionalidades

- **Cápsula com integridade** — CIDv1 por afirmação, root CID da cápsula, verificável com `verify`
- **Leitura direta de arquivos** — `ingest` lê texto, código e PDF (com OCR via Tesseract)
- **Pré-tokenização BLT** — chunking por entropia de bytes (Byte Latent Transformer): divide nas fronteiras semânticas
- **Seleção por relevância** — `pack` ranqueia fatos por TF-IDF, economia de 60-85% de tokens
- **Prompt compacto** — IDs curtos, regras em uma linha, combinável com `--terse` (saída enxuta)
- **Enxugador de mensagem** — `shrink` comprime instruções cortando cortesia e redundância
- **Interface no navegador** — `ctxcap-tool.html`, sem instalação, com BLT e estimativa de tokens ao vivo
- **Interoperabilidade** — CIDv1 e CARv1 reais, JSON canônico, Python e HTML geram CIDs idênticos

## Instalação

Só Python 3.10+ com stdlib. Sem dependências externas.

```bash
git clone https://github.com/Alvaromra/OpenID.git
cd OpenID
python3 ctxcap.py --help
```

Para PDF com OCR (opcional):

```bash
sudo apt install poppler-utils tesseract-ocr tesseract-ocr-por
pip install pdfplumber pdf2image pytesseract pillow --break-system-packages
```

Interface no navegador: abra `ctxcap-tool.html` com duplo-clique.

## Uso rápido

```bash
# ingerir arquivos (texto, código, PDF)
python3 ctxcap.py ingest ~/meu-projeto -r -o capsula.json --chunk-mode entropy

# gerar prompt para colar no chat
python3 ctxcap.py prompt capsula.json --compact --terse

# só fatos relevantes à pergunta
python3 ctxcap.py pack capsula.json "qual dataset?" -k 3 --terse

# verificar integridade
python3 ctxcap.py verify capsula.json

# análise BLT de um arquivo
python3 ctxcap.py blt arquivo.py

# enxugar sua mensagem
python3 ctxcap.py shrink "Olá, por favor me ajude com isso?" --show
```

## Como funciona

Cada afirmação vira um bloco JSON canônico cujo hash SHA-256 é o CID. Um manifesto lista os CIDs e tem seu próprio root CID. Alterar qualquer caractere muda o root — adulteração é detectável (Merkle-DAG, mesma estrutura do IPFS/Git).

O prompt de aterramento instrui o modelo a: tratar só aqueles fatos como verdade, citar o ID que usou, e dizer "fora do contexto" se não estiver coberto.

A pré-tokenização BLT calcula entropia local por byte (O(n), janela deslizante). Picos de entropia marcam transições semânticas — o chunking corta nessas fronteiras em vez de linhas fixas.

## Limites

Hash prova integridade, não autoria (para autoria, assine o root CID). Não prova que o fato é verdadeiro no mundo — curadoria continua sendo sua. O modelo no chat não calcula SHA-256 — a verificação é por código (`verify`).

## Licença

MIT
