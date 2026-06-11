#!/usr/bin/env python3
"""
ctxcap - Context Capsule
========================

Um formato portátil e verificável para transmitir contexto/conhecimento
entre sessões de chat com uma IA, usando endereçamento por conteúdo
(content addressing) no mesmo espírito dos CIDs do IPFS e dos arquivos .car.

Ideia central:
- Cada "afirmação" (statement) é um bloco. O identificador do bloco É o
  hash do seu conteúdo (CIDv1, multihash sha2-256, multibase base32).
- Um manifesto (capsule) referencia os CIDs de todas as afirmações,
  formando um Merkle-DAG. O hash do manifesto é o "root CID" e identifica
  a cápsula inteira.
- Mude qualquer caractere de qualquer afirmação -> o CID dela muda ->
  o manifesto muda -> o root CID muda. Adulteração é detectável.

Interoperabilidade:
- CIDv1 (version=1, codec=raw 0x55, multihash sha2-256) -> alinhado ao
  padrão IPFS/IPLD. Qualquer ferramenta que entenda CIDv1 consegue ler.
- Exporta um arquivo CARv1 (Content Addressable aRchive) com header CBOR
  dag-cbor, igual ao formato usado pelo IPFS.
- O conteúdo de cada bloco é JSON canônico (chaves ordenadas, sem espaços),
  então qualquer linguagem que faça SHA-256 consegue reproduzir os CIDs.

Sem dependências externas. Apenas a stdlib.
"""

from __future__ import annotations
import hashlib
import json
import base64
import argparse
import os
import sys
import datetime
from typing import Any

SPEC = "ctxcap/1"

# ---------------------------------------------------------------------------
# Primitivas de baixo nível: varint, multihash, CIDv1, multibase base32
# ---------------------------------------------------------------------------

def varint_encode(n: int) -> bytes:
    """Unsigned LEB128 varint, como usado em CIDs e no formato CAR."""
    if n < 0:
        raise ValueError("varint nao suporta negativos")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def varint_decode(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Retorna (valor, novo_offset)."""
    result = 0
    shift = 0
    pos = offset
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def multihash_sha256(data: bytes) -> bytes:
    """multihash = <codigo-do-hash><tamanho><digest>. sha2-256 = 0x12, 32 bytes."""
    digest = hashlib.sha256(data).digest()
    return bytes([0x12, 0x20]) + digest


# Codecs IPLD (multicodec). 0x55 = raw (bytes opacos).
CODEC_RAW = 0x55
# 0x71 = dag-cbor (usado no header do CAR).
CODEC_DAG_CBOR = 0x71


def cid_v1(data: bytes, codec: int = CODEC_RAW) -> bytes:
    """CIDv1 = <versao=1><codec><multihash>."""
    return varint_encode(1) + varint_encode(codec) + multihash_sha256(data)


def cid_to_string(cid: bytes) -> str:
    """Codifica em multibase base32 minusculo sem padding, prefixo 'b'."""
    b32 = base64.b32encode(cid).decode("ascii").lower().rstrip("=")
    return "b" + b32


def cid_from_string(s: str) -> bytes:
    if not s.startswith("b"):
        raise ValueError("esperado multibase base32 (prefixo 'b')")
    body = s[1:].upper()
    pad = (-len(body)) % 8
    return base64.b32decode(body + ("=" * pad))


# ---------------------------------------------------------------------------
# JSON canonico -> bytes deterministicos para hashing
# ---------------------------------------------------------------------------

def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def block_cid(obj: Any) -> str:
    return cid_to_string(cid_v1(canonical_bytes(obj), CODEC_RAW))


# ---------------------------------------------------------------------------
# CBOR minimo (somente o necessario para o header do CARv1)
# ---------------------------------------------------------------------------

def _cbor_head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    elif value < 0x100:
        return bytes([(major << 5) | 24, value])
    elif value < 0x10000:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    elif value < 0x100000000:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    else:
        return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_encode(obj: Any) -> bytes:
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        return _cbor_head(0, obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return _cbor_head(3, len(b)) + b
    if isinstance(obj, list):
        out = _cbor_head(4, len(obj))
        for item in obj:
            out += cbor_encode(item)
        return out
    if isinstance(obj, dict):
        out = _cbor_head(5, len(obj))
        for k, v in obj.items():
            out += cbor_encode(k) + cbor_encode(v)
        return out
    if isinstance(obj, _CborCid):
        # dag-cbor: CID = tag 42, byte string com prefixo multibase 0x00
        body = b"\x00" + obj.cid_bytes
        return b"\xd8\x2a" + _cbor_head(2, len(body)) + body
    raise TypeError(f"cbor: tipo nao suportado {type(obj)}")


class _CborCid:
    def __init__(self, cid_bytes: bytes):
        self.cid_bytes = cid_bytes


# ---------------------------------------------------------------------------
# Construcao e verificacao da capsula
# ---------------------------------------------------------------------------

def make_statement(
    claim: str,
    sources: list[str] | None = None,
    confidence: float | None = None,
    tags: list[str] | None = None,
    ts: str | None = None,
) -> dict:
    st: dict[str, Any] = {"type": "statement", "claim": claim}
    if sources:
        st["sources"] = sources
    if confidence is not None:
        # coerca numeros inteiros para int (1.0 -> 1) para que a serializacao
        # canonica seja identica entre Python e JavaScript (interop dos CIDs).
        c = float(confidence)
        st["confidence"] = int(c) if c.is_integer() else c
    if tags:
        st["tags"] = tags
    st["ts"] = ts or datetime.datetime.now(datetime.timezone.utc).isoformat()
    return st


def build_capsule(
    title: str,
    statements: list[dict],
    links: list[dict] | None = None,
    created: str | None = None,
) -> dict:
    """Monta a capsula completa: blocos + manifesto + root CID.

    Passe `created` explicitamente para obter um root CID reproduzivel
    (mesmo conteudo -> mesmo root). Se omitido, usa a hora atual.
    """
    blocks: dict[str, dict] = {}
    statement_cids: list[str] = []
    for st in statements:
        cid = block_cid(st)
        blocks[cid] = st
        statement_cids.append(cid)

    manifest = {
        "type": "capsule",
        "spec": SPEC,
        "title": title,
        "created": created or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "statements": statement_cids,
    }
    if links:
        manifest["links"] = links

    root = block_cid(manifest)
    blocks[root] = manifest
    return {"root": root, "manifest": manifest, "blocks": blocks}


def verify_capsule(capsule: dict) -> dict:
    """Re-hasheia tudo e confere. Retorna relatorio com problemas encontrados."""
    problems: list[str] = []
    blocks = capsule["blocks"]
    root = capsule["root"]

    # 1) cada bloco bate com seu CID declarado?
    for cid, obj in blocks.items():
        recomputed = block_cid(obj)
        if recomputed != cid:
            problems.append(f"bloco corrompido: declarado {cid}, recalculado {recomputed}")

    # 2) o root existe e e do tipo capsula?
    if root not in blocks:
        problems.append(f"root {root} ausente nos blocos")
        return {"ok": False, "problems": problems}
    manifest = blocks[root]
    if manifest.get("type") != "capsule":
        problems.append("root nao e um manifesto de capsula")

    # 3) todas as afirmacoes referenciadas existem?
    for cid in manifest.get("statements", []):
        if cid not in blocks:
            problems.append(f"afirmacao referenciada ausente: {cid}")

    # 4) o root e realmente o hash do manifesto?
    if block_cid(manifest) != root:
        problems.append("root nao corresponde ao hash do manifesto")

    return {"ok": len(problems) == 0, "problems": problems, "root": root}


# ---------------------------------------------------------------------------
# Export / Import: JSON e CARv1
# ---------------------------------------------------------------------------

def to_json(capsule: dict) -> str:
    return json.dumps(capsule, ensure_ascii=False, indent=2)


def from_json(text: str) -> dict:
    return json.loads(text)


def write_car(capsule: dict, path: str) -> None:
    """Escreve um arquivo CARv1 real (header CBOR dag-cbor + blocos)."""
    root_str = capsule["root"]
    root_bytes = cid_from_string(root_str)

    header = {"roots": [_CborCid(root_bytes)], "version": 1}
    header_bytes = cbor_encode(header)

    with open(path, "wb") as f:
        # header: varint(len) + header
        f.write(varint_encode(len(header_bytes)))
        f.write(header_bytes)
        # blocos: varint(len(cid+data)) + cid + data
        for cid_str, obj in capsule["blocks"].items():
            cid_bytes = cid_from_string(cid_str)
            data = canonical_bytes(obj)
            block = cid_bytes + data
            f.write(varint_encode(len(block)))
            f.write(block)


def read_car(path: str) -> dict:
    """Le um CARv1 escrito por write_car e reconstroi a capsula, verificando CIDs."""
    with open(path, "rb") as f:
        buf = f.read()

    pos = 0
    hlen, pos = varint_decode(buf, pos)
    pos += hlen  # pula o header CBOR (so precisamos dos blocos para reconstruir)

    blocks: dict[str, dict] = {}
    root = None
    while pos < len(buf):
        blen, pos = varint_decode(buf, pos)
        block = buf[pos:pos + blen]
        pos += blen
        # CIDv1 raw sha2-256 tem tamanho fixo: 1(ver)+1(codec)+2(mh head)+32 = 36 bytes
        cid_bytes = block[:36]
        data = block[36:]
        cid_str = cid_to_string(cid_bytes)
        # verifica integridade do bloco
        if cid_v1(data, CODEC_RAW) != cid_bytes:
            raise ValueError(f"bloco com hash invalido no CAR: {cid_str}")
        obj = json.loads(data.decode("utf-8"))
        blocks[cid_str] = obj
        if obj.get("type") == "capsule":
            root = cid_str

    if root is None:
        raise ValueError("nenhum manifesto de capsula encontrado no CAR")
    return {"root": root, "manifest": blocks[root], "blocks": blocks}


# ---------------------------------------------------------------------------
# Geracao do "prompt de aterramento" para colar no chat
# ---------------------------------------------------------------------------

PROMPT_TEMPLATE = """\
[CONTEXTO VERIFICADO — Context Capsule {spec}]
Root CID: {root}

Protocolo:
- Trate APENAS as afirmacoes abaixo como verdade fornecida. Cada uma tem um CID
  (hash do proprio conteudo) e, quando disponivel, fonte e confianca.
- Ao responder, cite os CIDs das afirmacoes que voce usou.
- Se a pergunta exigir algo que NAO esteja coberto por estas afirmacoes, diga
  explicitamente "fora do contexto verificado" em vez de inventar.
- Nao contradiga uma afirmacao verificada sem sinalizar o conflito.

Afirmacoes:
{statements}
"""


# Regras de saida enxuta (cortam tokens da RESPOSTA da IA). Inspirado em CLAUDE.md.
TERSE_RULES = (
    "Saida enxuta: responda direto, sem preambulo, saudacao ou fecho; "
    "sem repetir a pergunta; so o que foi pedido, no minimo de palavras; "
    'se nao souber, diga "nao sei" em vez de inventar.'
)


def make_prompt(capsule: dict, terse: bool = False) -> str:
    manifest = capsule["manifest"]
    lines = []
    for cid in manifest["statements"]:
        st = capsule["blocks"][cid]
        extra = []
        if "confidence" in st:
            extra.append(f"conf={st['confidence']}")
        if "sources" in st:
            extra.append("fontes=" + "; ".join(st["sources"]))
        meta = (" [" + ", ".join(extra) + "]") if extra else ""
        lines.append(f"- ({cid}) {st['claim']}{meta}")
    out = PROMPT_TEMPLATE.format(
        spec=manifest["spec"], root=capsule["root"], statements="\n".join(lines)
    )
    if terse:
        out += "\n" + TERSE_RULES
    return out


# ---------------------------------------------------------------------------
# Modo compacto + selecao por relevancia (economia de tokens)
# ---------------------------------------------------------------------------

def short_ids(cids: list[str]) -> dict:
    """IDs curtos e estaveis (#xxxx) derivados do fim do CID, garantindo unicidade."""
    n = 4
    while True:
        mapping = {c: "#" + c[-n:] for c in cids}
        if len(set(mapping.values())) == len(mapping):
            return mapping
        n += 1


def make_compact_prompt(capsule: dict, only: list[str] | None = None, terse: bool = False) -> str:
    """Prompt minimo: regra em 1 linha, IDs curtos no lugar dos CIDs longos."""
    manifest = capsule["manifest"]
    all_cids = manifest["statements"]
    sid = short_ids(all_cids)
    cids = [c for c in all_cids if (only is None or c in only)]
    head = (f'CTX[{capsule["root"][-6:]}] So estes fatos sao verdade; '
            f'cite o # usado; se algo nao estiver coberto, diga "fora do contexto".')
    lines = []
    for c in cids:
        st = capsule["blocks"][c]
        meta = []
        if "sources" in st:
            meta.append(st["sources"][0])
        if "confidence" in st:
            meta.append(str(st["confidence"]))
        mm = " <" + ";".join(meta) + ">" if meta else ""
        claim = st["claim"].strip()
        lines.append(f'{sid[c]} {claim}{mm}')
    out = head + "\n" + "\n".join(lines)
    if terse:
        out += "\n" + TERSE_RULES
    return out


def _normalize_terms(text: str) -> list[str]:
    """Minusculas + sem acento + so alfanumerico (para casar pt-BR)."""
    import unicodedata
    import re
    stripped = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.findall(r"[a-z0-9]+", stripped.lower())


_STOPWORDS = set("""a o e de da do das dos em no na nos nas um uma uns umas que com por para
se ao aos as os e ou mas como qual quais quando onde sao e esta estao foi ser usa usado usada
the of and to in is are was for on with as at by an be this that it from or
""".split())


def rank_by_relevance(capsule: dict, query: str, k: int = 0) -> list[str]:
    """Ordena os fatos por similaridade lexical (TF-IDF) com a pergunta.

    Faz, offline, o que a 'vetorizacao' faria: escolher os fatos relevantes
    para mandar so eles ao chat. Sem API, sem embeddings.
    """
    import math
    cids = capsule["manifest"]["statements"]
    docs = {c: _normalize_terms(capsule["blocks"][c]["claim"]) for c in cids}
    df: dict[str, int] = {}
    for toks in docs.values():
        for w in set(toks):
            df[w] = df.get(w, 0) + 1
    n = max(len(docs), 1)
    qterms = {w for w in _normalize_terms(query) if w not in _STOPWORDS and len(w) > 1}
    scores: dict[str, float] = {}
    for c, toks in docs.items():
        tf: dict[str, int] = {}
        for w in toks:
            tf[w] = tf.get(w, 0) + 1
        score = 0.0
        for w in qterms:
            if w in tf:
                idf = math.log(1 + n / df.get(w, 1))
                score += idf * (1 + math.log(tf[w]))
        scores[c] = score
    ranked = sorted(cids, key=lambda c: scores[c], reverse=True)
    relevant = [c for c in ranked if scores[c] > 0]
    chosen = relevant if relevant else ranked  # se nada casar, mantem tudo
    return chosen[:k] if k and k > 0 else chosen


def estimate_tokens(text: str) -> int:
    """Estimativa de tokens via analise byte-level (BLT). Mais precisa que chars/4."""
    return blt_estimate_tokens(text)


# ---------------------------------------------------------------------------
# Pre-tokenizacao BLT (Byte Latent Transformer)
# Patching por entropia: divide texto em fronteiras semanticas em vez de linhas
# fixas. Cada patch e um trecho onde a entropia de bytes e estavel (mesmo
# "assunto"); picos de entropia marcam transicoes (fim de funcao, troca de
# paragrafo, mudanca de lingua). Isso produz chunks mais coerentes para a
# capsula e uma estimativa de tokens mais precisa.
# ---------------------------------------------------------------------------

import math as _math
from collections import deque as _deque


def blt_bytes_view(text: str) -> list[int]:
    """Converte texto para sequencia de bytes UTF-8."""
    return list(text.encode("utf-8"))


def blt_local_entropy(byte_seq: list[int], window: int = 256) -> list[float]:
    """Entropia local por byte com janela deslizante. O(n)."""
    n = len(byte_seq)
    if n == 0:
        return []
    entropies = [0.0] * n
    freq: dict[int, int] = {}
    q: _deque[int] = _deque()
    for i in range(n):
        b = byte_seq[i]
        freq[b] = freq.get(b, 0) + 1
        q.append(b)
        if len(q) > window:
            old = q.popleft()
            freq[old] -= 1
            if freq[old] == 0:
                del freq[old]
        total = len(q)
        ent = 0.0
        for c in freq.values():
            p = c / total
            ent -= p * _math.log2(p)
        entropies[i] = ent
    return entropies


def blt_entropy_patches(text: str, threshold: float = 4.0,
                        min_patch_bytes: int = 64) -> list[str]:
    """Divide texto em patches nas fronteiras de entropia.

    Picos de entropia marcam transicoes semanticas (mudanca de funcao,
    paragrafo, assunto). O split encaixa na newline/espaco mais proximo
    para cortes limpos.

    threshold: limiar de entropia para considerar um pico (padrao 4.0 bits).
               Mais alto = menos splits (chunks maiores).
    min_patch_bytes: tamanho minimo de cada patch em bytes (evita lascas).
    """
    byte_seq = blt_bytes_view(text)
    if not byte_seq:
        return [text] if text.strip() else []

    entropies = blt_local_entropy(byte_seq)

    splits: list[int] = []
    last_split = 0
    for i in range(1, len(byte_seq)):
        if entropies[i] >= threshold and (i - last_split) >= min_patch_bytes:
            # procura newline/espaco proximo para corte limpo
            snap = i
            for j in range(i, max(last_split, i - 30), -1):
                if byte_seq[j] == 10:  # \n preferido
                    snap = j + 1
                    break
                elif byte_seq[j] in (13, 32, 9):
                    snap = j + 1
            # so aceita o split se o chunk resultante nao ficar menor que o minimo
            if snap > last_split and (snap - last_split) >= min_patch_bytes:
                splits.append(snap)
                last_split = snap

    boundaries = [0] + splits + [len(byte_seq)]
    patches = []
    for i in range(len(boundaries) - 1):
        chunk = bytes(byte_seq[boundaries[i]:boundaries[i + 1]])
        t = chunk.decode("utf-8", errors="replace").strip()
        if t:
            patches.append(t)
    return patches if patches else ([text.strip()] if text.strip() else [])


def blt_estimate_tokens(text: str) -> int:
    """Estimativa de tokens baseada em analise byte-level.

    Hibrido: conta patches de entropia e pondera pelo tamanho de cada um.
    Mais preciso que chars/4 porque respeita a estrutura real do texto
    (codigo puro tem mais tokens/char que prosa, e o BLT captura isso).
    """
    if not text or not text.strip():
        return 0
    byte_seq = blt_bytes_view(text)
    n = len(byte_seq)
    if n < 8:
        return max(1, n // 3)
    patches = blt_entropy_patches(text, threshold=3.5, min_patch_bytes=4)
    total = 0
    for p in patches:
        b = len(p.encode("utf-8"))
        # cada patch >= 1 token; patches grandes = multiplos tokens (~4 bytes/token)
        total += max(1, round(b / 3.7))
    return max(1, total)


def blt_analyze(text: str, window: int = 256) -> dict:
    """Analise BLT completa de um texto: bytes, entropia media/max, patches,
    estimativa de tokens. Util para diagnostico."""
    byte_seq = blt_bytes_view(text)
    entropies = blt_local_entropy(byte_seq, window)
    patches = blt_entropy_patches(text)
    tokens_blt = blt_estimate_tokens(text)
    tokens_naive = max(1, round(len(text) / 4))
    return {
        "bytes": len(byte_seq),
        "chars": len(text),
        "entropy_media": round(sum(entropies) / max(len(entropies), 1), 3),
        "entropy_max": round(max(entropies) if entropies else 0, 3),
        "patches": len(patches),
        "tokens_blt": tokens_blt,
        "tokens_naive": tokens_naive,
        "delta": f"{'+' if tokens_blt > tokens_naive else ''}"
                 f"{tokens_blt - tokens_naive} ({round((tokens_blt/max(tokens_naive,1)-1)*100)}%)",
    }


# ---------------------------------------------------------------------------
# Enxugador da MENSAGEM do usuario (compressao semantica offline, sem API)
# Reduz redundancia/cortesia mantendo portugues legivel. E lossy: revise a saida.
# ---------------------------------------------------------------------------

import re as _re

_GREETINGS = [r"\bol[áa]\b", r"\boi\b", r"\be a[íi]\b", r"\bbom dia\b", r"\bboa tarde\b",
              r"\bboa noite\b", r"\btudo bem\s*\??", r"\btudo bom\s*\??", r"\bcomo vai\s*\??"]
_THANKS = [r"(desde j[áa],?\s*)?(muit[oa]s?\s+|muit[íi]ssimo\s+)?obrigad[oa]s?(\s*[!.]*)?",
           r"\bagrade[çc]o( desde j[áa])?\b", r"\bvaleu\b", r"\bgrat[oa]\b"]
_FILLERS = [r"\bpor favor\b", r"\bvoc[eê] poderia\b", r"\bser[áa] que voc[eê] (poderia|consegue|pode)\b",
            r"\bgostaria de (saber|pedir|que)\b", r"\beu queria\b", r"\beu gostaria\b",
            r"\bse poss[íi]vel\b", r"\bquando puder\b", r"\bvoc[eê] consegue\b",
            r"\bestou tentando\b", r"\beu estou\b", r"\bna verdade\b", r"\bbasicamente\b",
            r"\bsimplesmente\b", r"\bs[óo] pra (deixar claro|confirmar)\b",
            r"\btipo assim\b", r"\bsabe\s*\??", r"\bn[ée]\s*\??", r"\benfim\b"]
_SUBST = [(r"\ba fim de que\b", "para"), (r"\ba fim de\b", "para"), (r"\bde modo que\b", "para"),
          (r"\bde forma que\b", "para"), (r"\bcom o objetivo de\b", "para"), (r"\bno sentido de\b", "sobre"),
          (r"\bem rela[çc][ãa]o a\b", "sobre"), (r"\bfazer com que\b", "fazer"), (r"\buma vez que\b", "pois"),
          (r"\bdevido ao fato de que\b", "porque"), (r"\bbem como\b", "e"), (r"\bque eu possa\b", "pra eu"),
          (r"\bme ajud[ae] a\b", "")]


def shrink_message(t: str) -> str:
    s = t
    s = _re.sub(r"^\s*(?:(?:ol[áa]|oi|e a[íi]|bom dia|boa tarde|boa noite|tudo bem|tudo bom|como vai)[\s,!.?]*)+",
                "", s, flags=_re.IGNORECASE)
    for p in _GREETINGS + _THANKS + _FILLERS:
        s = _re.sub(p, "", s, flags=_re.IGNORECASE)
    for p, r in _SUBST:
        s = _re.sub(p, r, s, flags=_re.IGNORECASE)
    s = _re.sub(r"\s+([,.;:?!])", r"\1", s)
    s = _re.sub(r"([,;:])(\s*[,;:])+", r"\1", s)
    s = _re.sub(r"([?.!])[\s,;:]*([?.!])", r"\2", s)
    s = _re.sub(r",(\s*[.?!])", r"\1", s)
    s = _re.sub(r"(^|[.?!]\s*)[,;:]\s*", r"\1", s)
    s = _re.sub(r"\s{2,}", " ", s)
    s = _re.sub(r"\s+,", ",", s)
    s = _re.sub(r",\s*,", ",", s)
    s = s.strip(" ,;:\n\t")
    s = _re.sub(r"(^|[.?!]\s+)([a-zà-ú])", lambda m: m.group(1) + m.group(2).upper(), s)
    return s.strip()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_SKIP_DIRS = {"venv", ".venv", "env", ".git", "__pycache__", "node_modules",
              ".mypy_cache", ".pytest_cache", "dist", "build", ".idea", ".vscode",
              "target", ".cache", "site-packages"}
_SKIP_EXT = {"pyc", "pyo", "so", "o", "a", "dll", "exe", "bin", "zip", "gz", "tar",
             "whl", "jpg", "jpeg", "png", "gif", "webp", "mp4", "mp3", "wav", "lock"}


def _expand_paths(paths: list[str], recursive: bool) -> list[str]:
    files: list[str] = []

    def keep_file(name: str) -> bool:
        ext = os.path.splitext(name)[1].lstrip(".").lower()
        return ext not in _SKIP_EXT

    def in_skipped_dir(path: str) -> bool:
        parts = set(path.replace("\\", "/").split("/"))
        return bool(parts & _SKIP_DIRS) or any(
            p.startswith(".") and p not in (".", "..") for p in parts)

    for path in paths:
        if os.path.isdir(path):
            if recursive:
                for root, dirs, names in os.walk(path):
                    # poda no proprio os.walk (impede descer em lixo)
                    dirs[:] = [d for d in dirs
                               if d not in _SKIP_DIRS and not d.startswith(".")]
                    for n in sorted(names):
                        full = os.path.join(root, n)
                        if keep_file(n) and not in_skipped_dir(full):
                            files.append(full)
            else:
                for n in sorted(os.listdir(path)):
                    full = os.path.join(path, n)
                    if os.path.isfile(full) and keep_file(n):
                        files.append(full)
        elif os.path.isfile(path):
            files.append(path)  # arquivo dado explicitamente: nao filtra
        else:
            print(f"aviso: caminho ignorado (nao existe): {path}", file=sys.stderr)
    return files


def _ocr_langs_available(requested: str) -> str:
    """Filtra os idiomas pedidos pelos que estao instalados no tesseract."""
    try:
        import pytesseract
        have = set(pytesseract.get_languages(config=""))
    except Exception:
        have = set()
    want = [l for l in requested.split("+") if l]
    ok = [l for l in want if l in have]
    if ok:
        return "+".join(ok)
    if "eng" in have:
        return "eng"
    return ok[0] if ok else (want[0] if want else "eng")


def extract_pdf_text(path: str, ocr_lang: str = "por+eng", ocr: bool = True,
                     min_chars: int = 25) -> tuple[str, list[int]]:
    """Extrai texto de um PDF. Paginas sem camada de texto (escaneadas) usam OCR.

    Retorna (texto, lista_de_paginas_ocr). Levanta ImportError com instrucao
    clara se as bibliotecas de PDF nao estiverem instaladas.
    """
    try:
        import pdfplumber
    except ImportError:
        raise ImportError(
            "Para ler PDF instale as dependencias:\n"
            "  pip install pdfplumber pdf2image pytesseract pillow\n"
            "  e os binarios: sudo apt install poppler-utils tesseract-ocr tesseract-ocr-por")

    pages: list[str] = []
    need_ocr: list[int] = []
    with pdfplumber.open(path) as pdf:
        for i, page in enumerate(pdf.pages):
            t = (page.extract_text() or "").strip()
            if len(t) < min_chars:
                need_ocr.append(i)
                t = ""
            pages.append(t)

    if need_ocr and ocr:
        try:
            import pytesseract
            from pdf2image import convert_from_path
        except ImportError:
            print("aviso: paginas escaneadas detectadas mas OCR indisponivel "
                  "(instale pdf2image/pytesseract); elas ficarao vazias", file=sys.stderr)
        else:
            lang = _ocr_langs_available(ocr_lang)
            for i in need_ocr:
                try:
                    imgs = convert_from_path(path, first_page=i + 1, last_page=i + 1, dpi=200)
                    if imgs:
                        pages[i] = pytesseract.image_to_string(imgs[0], lang=lang).strip()
                except Exception as e:
                    print(f"aviso: OCR falhou na pagina {i + 1}: {e}", file=sys.stderr)

    text = "\n\n".join(p for p in pages if p)
    return text, need_ocr


def _chunk_content(content: str, source: str, tags: list[str],
                   chunk_lines: int, chunk_mode: str, entropy_threshold: float) -> list[dict]:
    """Fatia conteudo em afirmacoes. Dois modos:
    - 'lines': corta a cada N linhas (simples, mecanico).
    - 'entropy': corta nas fronteiras de entropia BLT (respeita limites
       semanticos — funcoes, paragrafos, mudancas de assunto).
    """
    if chunk_mode == "entropy":
        # Para capsulas, patches maiores (~200-500 chars) sao mais uteis que os
        # micro-patches da analise BLT. min_patch_bytes escala com o tamanho do texto.
        content_bytes = len(content.encode("utf-8"))
        min_patch = max(200, content_bytes // 15)
        patches = blt_entropy_patches(content, threshold=entropy_threshold,
                                      min_patch_bytes=min_patch)
        if len(patches) <= 1:
            return [make_statement(content, sources=[source], tags=tags)]
        sts = []
        for i, patch in enumerate(patches, 1):
            sts.append(make_statement(patch, sources=[f"{source} (patch {i}/{len(patches)})"], tags=tags))
        return sts
    elif chunk_lines and chunk_lines > 0:
        lines = content.splitlines()
        sts = []
        for i in range(0, len(lines), chunk_lines):
            piece = "\n".join(lines[i:i + chunk_lines])
            rng = f"linhas {i + 1}-{min(i + chunk_lines, len(lines))}"
            sts.append(make_statement(piece, sources=[f"{source} ({rng})"], tags=tags))
        return sts
    else:
        return [make_statement(content, sources=[source], tags=tags)]


def statements_from_files(paths: list[str], recursive: bool, chunk_lines: int,
                          ocr_lang: str = "por+eng", ocr: bool = True,
                          chunk_mode: str = "lines", entropy_threshold: float = 4.0) -> list[dict]:
    """Le arquivos de texto direto e transforma cada um (ou cada bloco) numa afirmacao.

    Voce nao precisa escrever JSON: aponte para os arquivos e pronto.
    Modo 'entropy' usa pre-tokenizacao BLT para dividir em fronteiras semanticas.
    """
    statements: list[dict] = []
    for fp in _expand_paths(paths, recursive):
        ext = os.path.splitext(fp)[1].lstrip(".").lower() or "txt"
        name = os.path.basename(fp)

        if ext == "pdf":
            try:
                content, ocr_pages = extract_pdf_text(fp, ocr_lang=ocr_lang, ocr=ocr)
            except ImportError as e:
                print(str(e), file=sys.stderr)
                continue
            except Exception as e:
                print(f"aviso: falha ao ler PDF {fp}: {e}", file=sys.stderr)
                continue
            if not content.strip():
                print(f"aviso: PDF sem texto extraivel: {fp}", file=sys.stderr)
                continue
            note = f" (OCR em {len(ocr_pages)} pag.)" if ocr_pages else ""
            print(f"  pdf lido: {name}{note}")
            src = fp + (f" [OCR: paginas {','.join(str(p+1) for p in ocr_pages)}]" if ocr_pages else "")
            statements.extend(_chunk_content(content, src, ["pdf"],
                                             chunk_lines, chunk_mode, entropy_threshold))
            continue

        try:
            with open(fp, encoding="utf-8") as f:
                content = f.read()
        except (UnicodeDecodeError, OSError):
            print(f"aviso: pulado (nao e texto utf-8): {fp}", file=sys.stderr)
            continue

        statements.extend(_chunk_content(content, fp, [ext],
                                         chunk_lines, chunk_mode, entropy_threshold))
    return statements


def _cli():
    p = argparse.ArgumentParser(description="ctxcap - capsulas de contexto verificaveis")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create", help="cria capsula a partir de um JSON de afirmacoes")
    c.add_argument("input", help="JSON: {title, statements:[{claim, sources?, confidence?, tags?}]}")
    c.add_argument("-o", "--out", default="capsule.json")
    c.add_argument("--car", help="tambem exporta um arquivo .car")

    v = sub.add_parser("verify", help="verifica integridade (JSON ou .car)")
    v.add_argument("path")

    pr = sub.add_parser("prompt", help="gera o prompt de aterramento para colar no chat")
    pr.add_argument("path")
    pr.add_argument("--compact", action="store_true",
                    help="formato minimo (IDs curtos, regra em 1 linha) p/ economizar tokens")
    pr.add_argument("--terse", action="store_true",
                    help="anexa regras de SAIDA enxuta (corta tokens da resposta da IA)")

    pk = sub.add_parser("pack", help="prompt compacto SO com os fatos relevantes a uma pergunta")
    pk.add_argument("path")
    pk.add_argument("query", help="a pergunta/assunto; seleciona os fatos por relevancia")
    pk.add_argument("-k", type=int, default=5, help="quantos fatos no maximo (padrao 5; 0 = todos relevantes)")
    pk.add_argument("--full", action="store_true", help="usa o formato completo em vez do compacto")
    pk.add_argument("--terse", action="store_true",
                    help="anexa regras de SAIDA enxuta (corta tokens da resposta da IA)")

    sh = sub.add_parser("shrink", help="enxuga SUA mensagem (corta cortesia/redundancia, offline)")
    sh.add_argument("text", nargs="?", help="o texto; se omitido, le do stdin")
    sh.add_argument("--show", action="store_true", help="mostra original e enxuto lado a lado")

    cv = sub.add_parser("car", help="converte JSON -> .car")
    cv.add_argument("json_path")
    cv.add_argument("car_path")

    uncar = sub.add_parser("uncar", help="converte .car -> JSON")
    uncar.add_argument("car_path")
    uncar.add_argument("json_path")

    ing = sub.add_parser("ingest", help="cria capsula direto de arquivos (sem escrever JSON na mao)")
    ing.add_argument("paths", nargs="+", help="um ou mais arquivos/pastas")
    ing.add_argument("-o", "--out", default="capsule.json")
    ing.add_argument("--car", help="tambem exporta um arquivo .car")
    ing.add_argument("--title", help="titulo da capsula (padrao: nome do 1o arquivo)")
    ing.add_argument("--chunk-lines", type=int, default=0,
                     help="divide arquivos grandes em blocos de N linhas (0 = arquivo inteiro)")
    ing.add_argument("--chunk-mode", choices=["lines", "entropy"], default="lines",
                     help="metodo de fatiamento: 'lines' (por linhas) ou 'entropy' (BLT, por fronteiras semanticas)")
    ing.add_argument("--entropy-threshold", type=float, default=4.0,
                     help="limiar de entropia para o modo entropy (padrao 4.0; mais alto = chunks maiores)")
    ing.add_argument("-r", "--recursive", action="store_true", help="entra em subpastas")
    ing.add_argument("--ocr-lang", default="por+eng",
                     help="idioma(s) do OCR p/ PDF escaneado (padrao: por+eng)")
    ing.add_argument("--no-ocr", action="store_true",
                     help="nao tenta OCR em PDFs escaneados")

    blt = sub.add_parser("blt", help="analise BLT de um texto/arquivo (bytes, entropia, patches, tokens)")
    blt.add_argument("path", help="arquivo para analisar")
    blt.add_argument("--window", type=int, default=256, help="janela de entropia (padrao 256)")

    args = p.parse_args()

    if args.cmd == "create":
        spec = json.load(open(args.input, encoding="utf-8"))
        statements = [make_statement(**s) if isinstance(s, dict) else make_statement(s)
                      for s in spec["statements"]]
        cap = build_capsule(spec.get("title", "Sem titulo"), statements, spec.get("links"))
        open(args.out, "w", encoding="utf-8").write(to_json(cap))
        print(f"root: {cap['root']}")
        print(f"escrito: {args.out}")
        if args.car:
            write_car(cap, args.car)
            print(f"escrito: {args.car}")

    elif args.cmd == "verify":
        cap = read_car(args.path) if args.path.endswith(".car") else from_json(open(args.path, encoding="utf-8").read())
        rep = verify_capsule(cap)
        print("OK" if rep["ok"] else "FALHOU")
        for prob in rep["problems"]:
            print("  -", prob)
        sys.exit(0 if rep["ok"] else 1)

    elif args.cmd == "prompt":
        cap = read_car(args.path) if args.path.endswith(".car") else from_json(open(args.path, encoding="utf-8").read())
        full = make_prompt(cap)
        if args.compact:
            out = make_compact_prompt(cap, terse=args.terse)
            print(out)
            print(f"~{estimate_tokens(out)} tokens (compacto) vs ~{estimate_tokens(full)} (completo)",
                  file=sys.stderr)
        else:
            out = make_prompt(cap, terse=args.terse)
            print(out)
            print(f"~{estimate_tokens(out)} tokens", file=sys.stderr)

    elif args.cmd == "pack":
        cap = read_car(args.path) if args.path.endswith(".car") else from_json(open(args.path, encoding="utf-8").read())
        chosen = rank_by_relevance(cap, args.query, args.k)
        if args.full:
            # prompt completo, mas so com os fatos escolhidos
            sub_manifest = dict(cap["manifest"]); sub_manifest["statements"] = chosen
            sub_cap = {"root": cap["root"], "manifest": sub_manifest, "blocks": cap["blocks"]}
            out = make_prompt(sub_cap, terse=args.terse)
        else:
            out = make_compact_prompt(cap, only=chosen, terse=args.terse)
        print(out)
        total = len(cap["manifest"]["statements"])
        full_all = make_prompt(cap)
        print(f"selecionados {len(chosen)}/{total} fatos · ~{estimate_tokens(out)} tokens "
              f"(vs ~{estimate_tokens(full_all)} mandando tudo)", file=sys.stderr)

    elif args.cmd == "shrink":
        text = args.text if args.text is not None else sys.stdin.read()
        out = shrink_message(text)
        if args.show:
            eco = round((1 - estimate_tokens(out) / estimate_tokens(text)) * 100)
            print(f"--- original (~{estimate_tokens(text)} tokens) ---")
            print(text.strip())
            print(f"\n--- enxuto (~{estimate_tokens(out)} tokens, -{eco}%) ---")
            print(out)
            print("\n(revise: metodo por regras, pode deixar pequenas asperezas)", file=sys.stderr)
        else:
            print(out)
            print(f"~{estimate_tokens(text)} -> ~{estimate_tokens(out)} tokens", file=sys.stderr)

    elif args.cmd == "car":
        cap = from_json(open(args.json_path, encoding="utf-8").read())
        write_car(cap, args.car_path)
        print(f"escrito: {args.car_path}")

    elif args.cmd == "uncar":
        cap = read_car(args.car_path)
        open(args.json_path, "w", encoding="utf-8").write(to_json(cap))
        print(f"root: {cap['root']}")
        print(f"escrito: {args.json_path}")

    elif args.cmd == "ingest":
        statements = statements_from_files(
            args.paths, args.recursive, args.chunk_lines,
            ocr_lang=args.ocr_lang, ocr=not args.no_ocr,
            chunk_mode=args.chunk_mode, entropy_threshold=args.entropy_threshold)
        if not statements:
            print("nenhum arquivo legivel encontrado", file=sys.stderr)
            sys.exit(1)
        title = args.title or os.path.basename(args.paths[0].rstrip("/")) or "Capsula"
        cap = build_capsule(title, statements)
        open(args.out, "w", encoding="utf-8").write(to_json(cap))
        mode_label = "entropia BLT" if args.chunk_mode == "entropy" else "linhas"
        print(f"root: {cap['root']}")
        print(f"afirmacoes: {len(statements)} (chunking: {mode_label})")
        print(f"escrito: {args.out}")
        if args.car:
            write_car(cap, args.car)
            print(f"escrito: {args.car}")

    elif args.cmd == "blt":
        try:
            with open(args.path, encoding="utf-8") as f:
                text = f.read()
        except (UnicodeDecodeError, OSError) as e:
            print(f"erro ao ler {args.path}: {e}", file=sys.stderr)
            sys.exit(1)
        info = blt_analyze(text, window=args.window)
        patches = blt_entropy_patches(text)
        print(f"=== Analise BLT: {os.path.basename(args.path)} ===")
        print(f"  chars:          {info['chars']}")
        print(f"  bytes UTF-8:    {info['bytes']}")
        print(f"  entropia media: {info['entropy_media']} bits")
        print(f"  entropia max:   {info['entropy_max']} bits")
        print(f"  patches BLT:    {info['patches']}")
        print(f"  tokens (BLT):   {info['tokens_blt']}")
        print(f"  tokens (naive): {info['tokens_naive']}")
        print(f"  diferenca:      {info['delta']}")
        print(f"\n--- Patches (primeiros 5) ---")
        for i, p in enumerate(patches[:5], 1):
            preview = p[:120].replace("\n", "\\n")
            print(f"  [{i}] ({len(p)} chars) {preview}{'...' if len(p) > 120 else ''}")


if __name__ == "__main__":
    try:
        _cli()
    except BrokenPipeError:
        # acontece quando a saida e cortada por 'head'/'less'; nao e erro
        try:
            sys.stdout.close()
        except Exception:
            pass
    except RuntimeError as e:
        print(f"erro: {e}", file=sys.stderr)
        sys.exit(1)