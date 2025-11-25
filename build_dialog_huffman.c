/* build_dialog_huffman.c
 *
 * Builder de diccionario + morfología + Huffman + macros de n-gramas (3–4)
 * + paquete Deflate para los diálogos de Skyrim limpios en CSV:
 *
 *   skyrim_dialogue_clean.csv
 *   (cabecera: id,formId,origin,expansion,part,text)
 *
 * Salidas:
 *   - dict_full.txt        (id;token o id;id1,id2,... para macros)
 *   - dict_full.bin        (binario compacto: longitud + texto)
 *   - dialog_huffman.bin   (HUF1 + tabla de longitudes + bitstream)
 *   - dialogue_pack.deflate (paquete final Deflate)
 *
 * Compilar (TDM-GCC + zlib):
 *   gcc -std=c99 -O2 -Wall build_dialog_huffman.c -o Build_Dialog_Huffman.exe -I. -L. -lz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>

#include <zlib.h>
#include "zopfli-master/src/zopfli/zopfli.h"


/* ============================
 * Utilidades de memoria
 * ============================ */

static void die(const char *msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(1);
}

static void *xmalloc(size_t sz) {
    void *p = malloc(sz);
    if (!p) die("memoria agotada (malloc)");
    return p;
}

static void *xcalloc(size_t n, size_t sz) {
    void *p = calloc(n, sz);
    if (!p) die("memoria agotada (calloc)");
    return p;
}

static void *xrealloc(void *ptr, size_t sz) {
    void *p = realloc(ptr, sz);
    if (!p) die("memoria agotada (realloc)");
    return p;
}

/* ============================
 * Lectura de líneas
 * ============================ */

static char *read_line(FILE *f) {
    size_t cap = 1024;
    size_t len = 0;
    char *buf = (char *)xmalloc(cap);
    int c;
    int got_any = 0;

    while ((c = fgetc(f)) != EOF) {
        got_any = 1;
        if (c == '\r') {
            int c2 = fgetc(f);
            if (c2 != '\n' && c2 != EOF) {
                ungetc(c2, f);
            }
            break;
        }
        if (c == '\n') {
            break;
        }
        if (len + 1 >= cap) {
            cap *= 2;
            buf = (char *)xrealloc(buf, cap);
        }
        buf[len++] = (char)c;
    }

    if (!got_any && c == EOF) {
        free(buf);
        return NULL;
    }
    buf[len] = '\0';
    return buf;
}

/* ============================
 * Parser CSV simple (con comillas)
 * ============================ */

typedef struct {
    char **cols;
    int count;
} CsvRow;

static CsvRow parse_csv_line(const char *line) {
    CsvRow row;
    int capCols = 8;
    row.cols = (char **)xmalloc((size_t)capCols * sizeof(char *));
    row.count = 0;

    size_t fieldCap = 64;
    size_t fieldLen = 0;
    char *field = (char *)xmalloc(fieldCap);

    int in_quotes = 0;
    const char *p = line;

    while (*p) {
        char c = *p++;
        if (c == '"') {
            if (in_quotes && *p == '"') {
                if (fieldLen + 1 >= fieldCap) {
                    fieldCap *= 2;
                    field = (char *)xrealloc(field, fieldCap);
                }
                field[fieldLen++] = '"';
                p++;
            } else {
                in_quotes = !in_quotes;
            }
        } else if (c == ',' && !in_quotes) {
            if (fieldLen + 1 >= fieldCap) {
                fieldCap *= 2;
                field = (char *)xrealloc(field, fieldCap);
            }
            field[fieldLen] = '\0';

            if (row.count >= capCols) {
                capCols *= 2;
                row.cols = (char **)xrealloc(row.cols,
                                             (size_t)capCols * sizeof(char *));
            }
            row.cols[row.count++] = strdup(field);
            fieldLen = 0;
        } else {
            if (fieldLen + 1 >= fieldCap) {
                fieldCap *= 2;
                field = (char *)xrealloc(field, fieldCap);
            }
            field[fieldLen++] = c;
        }
    }

    if (fieldLen + 1 >= fieldCap) {
        fieldCap *= 2;
        field = (char *)xrealloc(field, fieldCap);
    }
    field[fieldLen] = '\0';
    if (row.count >= capCols) {
        capCols *= 2;
        row.cols = (char **)xrealloc(row.cols,
                                     (size_t)capCols * sizeof(char *));
    }
    row.cols[row.count++] = strdup(field);

    free(field);
    return row;
}

static void free_csv_row(CsvRow *row) {
    if (!row || !row->cols) return;
    for (int i = 0; i < row->count; ++i) {
        free(row->cols[i]);
    }
    free(row->cols);
    row->cols = NULL;
    row->count = 0;
}

/* ============================
 * Diccionario token -> id
 * ============================ */

#define DICT_HASH_SIZE 65536

typedef struct TokenNode {
    char *token;
    int id;
    struct TokenNode *next;
} TokenNode;

typedef struct {
    TokenNode **buckets;
    int hashSize;
    int nextId;
    char **idToToken;
    int idCap;
} Dict;

static unsigned hash_str(const char *s) {
    unsigned h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

static void dict_init(Dict *d, int hashSize) {
    d->hashSize = hashSize;
    d->buckets = (TokenNode **)xcalloc((size_t)hashSize,
                                       sizeof(TokenNode *));
    d->nextId = 1;
    d->idCap = 1024;
    d->idToToken = (char **)xcalloc((size_t)d->idCap,
                                    sizeof(char *));
}

static void dict_ensure_id_cap(Dict *d, int id) {
    if (id >= d->idCap) {
        int newCap = d->idCap;
        if (newCap <= 0) newCap = 1024;
        while (id >= newCap) newCap *= 2;
        d->idToToken = (char **)xrealloc(d->idToToken,
                                         (size_t)newCap * sizeof(char *));
        memset(d->idToToken + d->idCap, 0,
               (size_t)(newCap - d->idCap) * sizeof(char *));
        d->idCap = newCap;
    }
}

static int dict_get_or_add(Dict *d, const char *token) {
    unsigned h = hash_str(token);
    int idx = (int)(h % (unsigned)d->hashSize);

    TokenNode *n = d->buckets[idx];
    while (n) {
        if (strcmp(n->token, token) == 0) {
            return n->id;
        }
        n = n->next;
    }

    int id = d->nextId++;
    TokenNode *nn = (TokenNode *)xmalloc(sizeof(TokenNode));
    nn->token = strdup(token);
    nn->id = id;
    nn->next = d->buckets[idx];
    d->buckets[idx] = nn;

    dict_ensure_id_cap(d, id + 1);
    d->idToToken[id] = nn->token;

    return id;
}

static int dict_find(const Dict *d, const char *token) {
    unsigned h = hash_str(token);
    int idx = (int)(h % (unsigned)d->hashSize);

    TokenNode *n = d->buckets[idx];
    while (n) {
        if (strcmp(n->token, token) == 0) {
            return n->id;
        }
        n = n->next;
    }
    return 0;
}

static void dict_free(Dict *d) {
    if (!d) return;
    if (d->buckets) {
        for (int i = 0; i < d->hashSize; ++i) {
            TokenNode *n = d->buckets[i];
            while (n) {
                TokenNode *next = n->next;
                free(n->token);
                free(n);
                n = next;
            }
        }
        free(d->buckets);
    }
    if (d->idToToken) {
        free(d->idToToken);
    }
}

/* ============================
 * Vector dinámico de IDs
 * ============================ */

typedef struct {
    int *data;
    int size;
    int cap;
} IntVec;

static void ivec_init(IntVec *v) {
    v->data = NULL;
    v->size = 0;
    v->cap = 0;
}

static void ivec_push(IntVec *v, int value) {
    if (v->size >= v->cap) {
        int newCap = (v->cap > 0) ? v->cap * 2 : 1024;
        v->data = (int *)xrealloc(v->data,
                                  (size_t)newCap * sizeof(int));
        v->cap = newCap;
    }
    v->data[v->size++] = value;
}

static void ivec_free(IntVec *v) {
    if (!v) return;
    free(v->data);
    v->data = NULL;
    v->size = v->cap = 0;
}

/* ============================
 * Normalización de texto
 * ============================ */

static char *strip_trailing_stage_dir(const char *text) {
    size_t n = strlen(text);
    for (size_t i = 0; i < n; ++i) {
        char c = text[i];
        if (c == '.' || c == '!' || c == '?') {
            size_t j = i + 1;
            int spaceCount = 0;
            while (j < n && text[j] == ' ') {
                spaceCount++;
                j++;
            }
            if (spaceCount >= 2 && j < n) {
                unsigned char next = (unsigned char)text[j];
                if ((next >= 'A' && next <= 'Z') || next == '(') {
                    size_t outLen = i + 1;
                    char *out = (char *)xmalloc(outLen + 1);
                    memcpy(out, text, outLen);
                    out[outLen] = '\0';
                    return out;
                }
            }
        }
    }
    size_t outLen = n;
    char *out = (char *)xmalloc(outLen + 1);
    memcpy(out, text, outLen + 1);
    return out;
}

static char *normalize_case_and_brackets(const char *text) {
    size_t n = strlen(text);
    char *out = (char *)xmalloc(n + 1);
    size_t o = 0;
    int depth = 0;

    for (size_t i = 0; i < n; ++i) {
        char c = text[i];
        if (c == '[') {
            depth++;
            continue;
        }
        if (c == ']') {
            if (depth > 0) depth--;
            continue;
        }
        if (depth > 0) continue;
        out[o++] = (char)tolower((unsigned char)c);
    }

    out[o] = '\0';
    return out;
}

static char *normalize_text(const char *text) {
    char *cut = strip_trailing_stage_dir(text);
    char *norm = normalize_case_and_brackets(cut);
    free(cut);
    return norm;
}

/* ============================
 * Emisión de tokens
 * ============================ */

static void emit_token_str(Dict *dict, IntVec *stream, const char *s, int len) {
    if (len <= 0) return;
    char buf[256];
    if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
    memcpy(buf, s, (size_t)len);
    buf[len] = '\0';
    int id = dict_get_or_add(dict, buf);
    ivec_push(stream, id);
}

/* ============================
 * PASS 1: tokenización básica
 * ============================ */

static void tokenize_text_pass1(const char *text, Dict *dict, IntVec *stream) {
    char *norm = normalize_text(text);
    size_t len = strlen(norm);
    size_t i = 0;
    char wordBuf[512];
    int wlen = 0;

    while (i < len) {
        unsigned char c = (unsigned char)norm[i];

        if (isspace(c)) {
            if (wlen > 0) {
                emit_token_str(dict, stream, wordBuf, wlen);
                wlen = 0;
            }
            i++;
            continue;
        }

        if (c == '.' || c == ',' || c == '!' || c == '?' ||
            c == ';' || c == ':' || c == '(' || c == ')') {

            if (wlen > 0) {
                emit_token_str(dict, stream, wordBuf, wlen);
                wlen = 0;
            }

            if (c == '.') {
                size_t start = i;
                size_t j = i;
                while (j < len && norm[j] == '.') {
                    j++;
                }
                size_t runLen = j - start;
                emit_token_str(dict, stream, &norm[start], (int)runLen);
                i = j;
            } else {
                emit_token_str(dict, stream, &norm[i], 1);
                i++;
            }
            continue;
        }

        if (isalnum(c) || c == '\'' || c == '_') {
            if (wlen < (int)sizeof(wordBuf) - 1) {
                wordBuf[wlen++] = (char)c;
            }
            i++;
        } else {
            if (wlen > 0) {
                emit_token_str(dict, stream, wordBuf, wlen);
                wlen = 0;
            }
            i++;
        }
    }

    if (wlen > 0) {
        emit_token_str(dict, stream, wordBuf, wlen);
    }

    free(norm);
}

/* ============================
 * PASS 2: morfología global
 * ============================ */

static const char * const CONTR_SUFFIXES[] = {
    "'s","'re","'ve","'ll","'d","'m","'em"
};
static const int CONTR_SUFFIX_COUNT = 7;

/* sufijos planos: se pegan directamente tras la base */
static const char * const PLAIN_SUFFIXES[] = {
    "ed","es","er","ly"
};
static const int PLAIN_SUFFIX_COUNT = 4;

static void morph_split_token(const char *word,
                              const Dict *baseDict,
                              Dict *outDict,
                              IntVec *outStream)
{
    int len = (int)strlen(word);
    if (len <= 0) return;

    char baseBuf[256];

    /* 1) Caso especial: "n't" */
    int ntPos = -1;
    for (int i = 1; i + 2 < len; ++i) {
        if (word[i] == 'n' && word[i+1] == '\'' && word[i+2] == 't') {
            ntPos = i;
            break;
        }
    }

    if (ntPos > 0) {
        int baseLen = ntPos;

        if (baseLen > 0 && baseLen < (int)sizeof(baseBuf)) {
            memcpy(baseBuf, word, (size_t)baseLen);
            baseBuf[baseLen] = '\0';
            int baseId = dict_find(baseDict, baseBuf);
            if (baseId != 0) {
                emit_token_str(outDict, outStream, baseBuf, baseLen);
                emit_token_str(outDict, outStream, "n't", 3);
                return;
            }
        }

        if (baseLen > 0 && baseLen + 1 < (int)sizeof(baseBuf)) {
            memcpy(baseBuf, word, (size_t)baseLen);
            baseBuf[baseLen] = 'n';
            baseBuf[baseLen + 1] = '\0';

            int baseNId = dict_find(baseDict, baseBuf);
            if (baseNId != 0) {
                emit_token_str(outDict, outStream, baseBuf, baseLen + 1);
                emit_token_str(outDict, outStream, "'t", 2);
                return;
            }
        }
    }

    /* 2) Sufijos con apóstrofe */
    int aposIndex = -1;
    for (int i = 1; i < len - 1; ++i) {
        if (word[i] == '\'') {
            aposIndex = i;
            break;
        }
    }

    if (aposIndex > 0 && aposIndex < len - 1) {
        const char *suffix = word + aposIndex;
        int sLen = len - aposIndex;

        int suffixMatched = 0;
        for (int si = 0; si < CONTR_SUFFIX_COUNT; ++si) {
            const char *suff = CONTR_SUFFIXES[si];
            int suffLen = (int)strlen(suff);
            if (sLen == suffLen && memcmp(suffix, suff, (size_t)sLen) == 0) {
                suffixMatched = 1;
                break;
            }
        }

        if (suffixMatched) {
            int baseLen = aposIndex;
            int baseOk = 1;

            if (baseLen <= 0) baseOk = 0;
            for (int j = 0; j < baseLen && baseOk; ++j) {
                unsigned char c = (unsigned char)word[j];
                if (!isalnum(c)) {
                    baseOk = 0;
                }
            }

            if (baseOk) {
                if (baseLen >= (int)sizeof(baseBuf)) baseLen = (int)sizeof(baseBuf) - 1;
                memcpy(baseBuf, word, (size_t)baseLen);
                baseBuf[baseLen] = '\0';

                int baseId = dict_find(baseDict, baseBuf);
                if (baseId != 0) {
                    emit_token_str(outDict, outStream, baseBuf, baseLen);
                    emit_token_str(outDict, outStream, suffix, sLen);
                    return;
                }
            }
        }
    }

   /* 3) Sufijo "ing" con regla de puente tipo "run + ning" (Modo 1, opción A) */
    if (len > 3 &&
        word[len-3] == 'i' &&
        word[len-2] == 'n' &&
        word[len-1] == 'g') {

        int baseLen = len - 3;

        /* 3.a) Intento directo: <base> + "ing" si la base ya existe */
        if (baseLen > 0 && baseLen < (int)sizeof(baseBuf)) {
            memcpy(baseBuf, word, (size_t)baseLen);
            baseBuf[baseLen] = '\0';

            int baseId = dict_find(baseDict, baseBuf);
            if (baseId != 0) {
                /* ejemplo: "ringing" -> "ring" + "ing" */
                emit_token_str(outDict, outStream, baseBuf, baseLen);
                emit_token_str(outDict, outStream, "ing", 3);
                return;
            }
        }

        /* 3.b) Regla de puente: letra duplicada antes de "ing"
           running  -> run + ning
           sitting  -> sit + ting
           jogging  -> jog + ging
         */
        if (baseLen >= 2 &&
            baseLen < (int)sizeof(baseBuf) &&
            word[baseLen - 1] == word[baseLen - 2]) {

            int prefixLen = baseLen - 1; /* quitamos una de las letras duplicadas */
            memcpy(baseBuf, word, (size_t)prefixLen);
            baseBuf[prefixLen] = '\0';

            int baseId2 = dict_find(baseDict, baseBuf);
            if (baseId2 != 0) {
                int suf2Len = len - prefixLen; /* p.ej. "ning", "ting", "ging" */
                if (suf2Len > 0) {
                    emit_token_str(outDict, outStream, baseBuf, prefixLen);
                    emit_token_str(outDict, outStream, word + prefixLen, suf2Len);
                    return;
                }
            }
        }
        /* Si no se cumple nada, seguimos con el siguiente bloque de sufijos. */
    }

    /* 5) Regla extra: prefijo + texto intermedio + sufijo ("ing" o planos),
           modo 1 / opción A para casos como "running" -> "run" + "ning" */
    {
        const char * const SUF_LIST[] = { "ing", "ed", "es", "er", "ly" };
        const int SUF_COUNT = (int)(sizeof(SUF_LIST) / sizeof(SUF_LIST[0]));
        char sufBuf[256];

        for (int si = 0; si < SUF_COUNT; ++si) {
            const char *suf = SUF_LIST[si];
            int sLen = (int)strlen(suf);

            /* base >= 3 y al menos 1 letra entre base y sufijo */
            if (len <= sLen + 3) continue;

            /* ¿termina la palabra con este sufijo? */
            if (memcmp(word + (len - sLen), suf, (size_t)sLen) != 0) continue;

            int maxBridge = 2;      /* como mucho 2 letras de "puente" */
            int minBaseLen = 3;

            for (int bridgeLen = 1; bridgeLen <= maxBridge; ++bridgeLen) {
                int baseLen = len - sLen - bridgeLen;
                if (baseLen < minBaseLen) break;

                if (baseLen >= (int)sizeof(baseBuf)) continue;
                memcpy(baseBuf, word, (size_t)baseLen);
                baseBuf[baseLen] = '\0';

                int baseId = dict_find(baseDict, baseBuf);
                if (baseId == 0) continue;

                /* Nuevo sufijo = texto intermedio + sufijo normal. p.ej. "n" + "ing" -> "ning" */
                int newSufLen = bridgeLen + sLen;
                if (newSufLen >= (int)sizeof(sufBuf)) continue;
                memcpy(sufBuf, word + baseLen, (size_t)newSufLen);
                sufBuf[newSufLen] = '\0';

                emit_token_str(outDict, outStream, baseBuf, baseLen);
                emit_token_str(outDict, outStream, sufBuf, newSufLen);
                return;
            }
        }
    }

    /* 6) Sin split útil → palabra tal cual */
    emit_token_str(outDict, outStream, word, len);
}

static void apply_morphology(const IntVec *inStream,
                             const Dict *baseDict,
                             Dict *outDict,
                             IntVec *outStream)
{
    dict_init(outDict, DICT_HASH_SIZE);
    ivec_init(outStream);

    for (int i = 0; i < inStream->size; ++i) {
        int id = inStream->data[i];
        if (id < 1 || id >= baseDict->idCap) continue;
        const char *tok = baseDict->idToToken[id];
        if (!tok) tok = "";
        morph_split_token(tok, baseDict, outDict, outStream);
    }
}


/* ============================
 * Reindexar tokens por longitud
 * ============================ */

typedef struct {
    int   oldId;
    char *token;
    int   len;
} TokenLenInfo;

static int cmp_token_len(const void *a, const void *b) {
    const TokenLenInfo *ta = (const TokenLenInfo *)a;
    const TokenLenInfo *tb = (const TokenLenInfo *)b;
    if (ta->len < tb->len) return -1;
    if (ta->len > tb->len) return 1;
    if (ta->oldId < tb->oldId) return -1;
    if (ta->oldId > tb->oldId) return 1;
    return 0;
}

static int reindex_tokens_by_length(Dict *dict, IntVec *stream) {
    int count = dict->nextId - 1;
    if (count <= 0) return 0;

    TokenLenInfo *arr = (TokenLenInfo *)xmalloc((size_t)count * sizeof(TokenLenInfo));
    for (int id = 1; id <= count; ++id) {
        char *tok = dict->idToToken[id];
        if (!tok) tok = "";
        arr[id - 1].oldId = id;
        arr[id - 1].token = tok;
        arr[id - 1].len   = (int)strlen(tok);
    }

    qsort(arr, (size_t)count, sizeof(TokenLenInfo), cmp_token_len);

    int   *oldToNew     = (int *)xcalloc((size_t)(count + 1), sizeof(int));
    char **newIdToToken = (char **)xcalloc((size_t)(count + 1), sizeof(char *));

    for (int i = 0; i < count; ++i) {
        int newId = i + 1;
        int oldId = arr[i].oldId;
        oldToNew[oldId]      = newId;
        newIdToToken[newId]  = arr[i].token;
    }

    for (int i = 0; i < stream->size; ++i) {
        int oldId = stream->data[i];
        if (oldId >= 1 && oldId <= count) {
            stream->data[i] = oldToNew[oldId];
        }
    }

    char **oldArr = dict->idToToken;
    dict->idToToken = newIdToToken;
    free(oldArr);

    free(oldToNew);
    free(arr);

    return count;
}

/* ============================
 * Huffman
 * ============================ */

typedef struct HuffNode {
    int sym;
    uint32_t freq;
    struct HuffNode *left;
    struct HuffNode *right;
} HuffNode;

typedef struct {
    HuffNode **data;
    int size;
    int cap;
} HuffHeap;

static void heap_init(HuffHeap *h) {
    h->data = NULL;
    h->size = 0;
    h->cap = 0;
}

static void heap_reserve(HuffHeap *h) {
    if (h->size >= h->cap) {
        int newCap = (h->cap > 0) ? h->cap * 2 : 64;
        h->data = (HuffNode **)xrealloc(h->data,
                                        (size_t)newCap * sizeof(HuffNode *));
        h->cap = newCap;
    }
}

static void heap_sift_up(HuffHeap *h, int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (h->data[parent]->freq <= h->data[idx]->freq) break;
        HuffNode *tmp = h->data[parent];
        h->data[parent] = h->data[idx];
        h->data[idx] = tmp;
        idx = parent;
    }
}

static void heap_sift_down(HuffHeap *h, int idx) {
    for (;;) {
        int left = idx * 2 + 1;
        int right = left + 1;
        int smallest = idx;

        if (left < h->size &&
            h->data[left]->freq < h->data[smallest]->freq) {
            smallest = left;
        }
        if (right < h->size &&
            h->data[right]->freq < h->data[smallest]->freq) {
            smallest = right;
        }
        if (smallest == idx) break;

        HuffNode *tmp = h->data[smallest];
        h->data[smallest] = h->data[idx];
        h->data[idx] = tmp;
        idx = smallest;
    }
}

static void heap_push(HuffHeap *h, HuffNode *node) {
    heap_reserve(h);
    h->data[h->size] = node;
    heap_sift_up(h, h->size);
    h->size++;
}

static HuffNode *heap_pop(HuffHeap *h) {
    if (h->size == 0) return NULL;
    HuffNode *res = h->data[0];
    h->size--;
    if (h->size > 0) {
        h->data[0] = h->data[h->size];
        heap_sift_down(h, 0);
    }
    return res;
}

static HuffNode *build_huffman_tree(const uint32_t *freq, int symbolCount) {
    HuffHeap heap;
    heap_init(&heap);

    int nonzero = 0;
    for (int i = 1; i <= symbolCount; ++i) {
        if (freq[i] == 0) continue;
        HuffNode *node = (HuffNode *)xmalloc(sizeof(HuffNode));
        node->sym = i;
        node->freq = freq[i];
        node->left = node->right = NULL;
        heap_push(&heap, node);
        nonzero++;
    }

    if (nonzero == 0) {
        return NULL;
    }

    if (nonzero == 1) {
        HuffNode *only = heap_pop(&heap);
        free(heap.data);
        return only;
    }

    while (heap.size > 1) {
        HuffNode *a = heap_pop(&heap);
        HuffNode *b = heap_pop(&heap);
        HuffNode *parent = (HuffNode *)xmalloc(sizeof(HuffNode));
        parent->sym = -1;
        parent->freq = a->freq + b->freq;
        parent->left = a;
        parent->right = b;
        heap_push(&heap, parent);
    }

    HuffNode *root = heap_pop(&heap);
    free(heap.data);
    return root;
}

static void free_huffman_tree(HuffNode *node) {
    if (!node) return;
    free_huffman_tree(node->left);
    free_huffman_tree(node->right);
    free(node);
}

static void build_codes_rec(HuffNode *node,
                            char *buffer,
                            int depth,
                            char **codes,
                            uint8_t *codeLen) {
    if (!node) return;

    if (!node->left && !node->right) {
        int len = depth;
        if (len == 0) {
            buffer[0] = '0';
            len = 1;
        }
        char *c = (char *)xmalloc((size_t)len + 1);
        memcpy(c, buffer, (size_t)len);
        c[len] = '\0';
        codes[node->sym] = c;
        codeLen[node->sym] = (uint8_t)len;
        return;
    }

    buffer[depth] = '0';
    build_codes_rec(node->left, buffer, depth + 1, codes, codeLen);

    buffer[depth] = '1';
    build_codes_rec(node->right, buffer, depth + 1, codes, codeLen);
}

/* ============================
 * BitWriter
 * ============================ */

typedef struct {
    uint8_t *data;
    size_t size;
    size_t cap;
    int bitPos;
} BitWriter;

static void bw_init(BitWriter *bw) {
    bw->data = NULL;
    bw->size = 0;
    bw->cap = 0;
    bw->bitPos = 0;
}

static void bw_ensure(BitWriter *bw) {
    if (bw->size >= bw->cap) {
        size_t newCap = (bw->cap > 0) ? bw->cap * 2 : 1024;
        bw->data = (uint8_t *)xrealloc(bw->data, newCap);
        bw->cap = newCap;
    }
}

static void bw_put_bit(BitWriter *bw, int bit) {
    if (bw->bitPos == 0) {
        bw_ensure(bw);
        bw->data[bw->size] = 0;
    }
    if (bit) {
        bw->data[bw->size] |= (uint8_t)(1u << (7 - bw->bitPos));
    }
    bw->bitPos++;
    if (bw->bitPos == 8) {
        bw->bitPos = 0;
        bw->size++;
    }
}

static void bw_put_code(BitWriter *bw, const char *code) {
    for (const char *p = code; *p; ++p) {
        bw_put_bit(bw, (*p == '1') ? 1 : 0);
    }
}

static void bw_flush(BitWriter *bw) {
    if (bw->bitPos > 0) {
        bw->bitPos = 0;
        bw->size++;
    }
}

/* ============================
 * Utilidades de ficheros
 * ============================ */

static long file_size(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    fclose(f);
    return sz;
}

/* ============================
 * Macros de n-gramas (3–4)
 * ============================ */

#define NGRAM_MIN_LEN          3
#define NGRAM_MAX_LEN          4
#define MAX_MACROS             4096
#define MIN_NGRAM_FREQ         12
#define MIN_MACRO_GAIN_TOKENS  64

typedef struct {
    uint64_t key;
    uint32_t freq;
} NGramFreq;

typedef struct {
    uint64_t key;
    int      macroId;
} MacroMapEntry64;

static int cmp_u64_asc(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

static int cmp_ngfreq_desc(const void *a, const void *b) {
    const NGramFreq *pa = (const NGramFreq *)a;
    const NGramFreq *pb = (const NGramFreq *)b;
    if (pa->freq < pb->freq) return 1;
    if (pa->freq > pb->freq) return -1;
    return 0;
}

static int cmp_macromap64_key_asc(const void *a, const void *b) {
    const MacroMapEntry64 *ma = (const MacroMapEntry64 *)a;
    const MacroMapEntry64 *mb = (const MacroMapEntry64 *)b;
    if (ma->key < mb->key) return -1;
    if (ma->key > mb->key) return 1;
    return 0;
}

static int macromap64_find(const MacroMapEntry64 *map, int count, uint64_t key) {
    int lo = 0;
    int hi = count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        uint64_t mk = map[mid].key;
        if (mk == key) return map[mid].macroId;
        if (mk < key) lo = mid + 1;
        else hi = mid - 1;
    }
    return 0;
}

/* Construye macros de n-gramas (3 y 4) y reescribe el stream */
static void build_ngram_macros(const IntVec *inStream,
                               int baseSymbolCount,
                               int **outMacroLen,
                               int **outMacroA,
                               int **outMacroB,
                               int **outMacroC,
                               int **outMacroD,
                               int *outMacroCount,
                               IntVec *outStream)
{
    *outMacroLen = NULL;
    *outMacroA   = NULL;
    *outMacroB   = NULL;
    *outMacroC   = NULL;
    *outMacroD   = NULL;
    *outMacroCount = 0;
    ivec_init(outStream);

    if (inStream->size < NGRAM_MIN_LEN || baseSymbolCount <= 0) {
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    if (baseSymbolCount > 65535) {
        fprintf(stderr,
                "Aviso: demasiados tokens únicos (%d) para macros de n-gramas; se desactivan.\n",
                baseSymbolCount);
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    int maxNgrams = inStream->size * (NGRAM_MAX_LEN - NGRAM_MIN_LEN + 1);
    if (maxNgrams <= 0) {
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    uint64_t *keys = (uint64_t *)xmalloc((size_t)maxNgrams * sizeof(uint64_t));
    int usedKeys = 0;

    for (int i = 0; i < inStream->size; ++i) {
        if (i + 2 < inStream->size) {
            int a = inStream->data[i];
            int b = inStream->data[i + 1];
            int c = inStream->data[i + 2];
            if (a >= 1 && a <= baseSymbolCount &&
                b >= 1 && b <= baseSymbolCount &&
                c >= 1 && c <= baseSymbolCount) {
                uint64_t key = ((uint64_t)a << 48) |
                               ((uint64_t)b << 32) |
                               ((uint64_t)c << 16) |
                               0u;
                keys[usedKeys++] = key;
            }
        }
        if (i + 3 < inStream->size) {
            int a = inStream->data[i];
            int b = inStream->data[i + 1];
            int c = inStream->data[i + 2];
            int d = inStream->data[i + 3];
            if (a >= 1 && a <= baseSymbolCount &&
                b >= 1 && b <= baseSymbolCount &&
                c >= 1 && c <= baseSymbolCount &&
                d >= 1 && d <= baseSymbolCount) {
                uint64_t key = ((uint64_t)a << 48) |
                               ((uint64_t)b << 32) |
                               ((uint64_t)c << 16) |
                               (uint64_t)d;
                keys[usedKeys++] = key;
            }
        }
    }

    if (usedKeys == 0) {
        free(keys);
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    qsort(keys, (size_t)usedKeys, sizeof(uint64_t), cmp_u64_asc);

    NGramFreq *pf = (NGramFreq *)xmalloc((size_t)usedKeys * sizeof(NGramFreq));
    int pfCount = 0;

    int idx = 0;
    while (idx < usedKeys) {
        uint64_t key = keys[idx];
        uint32_t freq = 1;
        idx++;
        while (idx < usedKeys && keys[idx] == key) {
            freq++;
            idx++;
        }
        pf[pfCount].key = key;
        pf[pfCount].freq = freq;
        pfCount++;
    }

    free(keys);

    qsort(pf, (size_t)pfCount, sizeof(NGramFreq), cmp_ngfreq_desc);

    int macroCap = MAX_MACROS;
    int macroCount = 0;
    int *macroLen = NULL;
    int *macroA   = NULL;
    int *macroB   = NULL;
    int *macroC   = NULL;
    int *macroD   = NULL;

    if (macroCap > 0) {
        macroLen = (int *)xmalloc((size_t)macroCap * sizeof(int));
        macroA   = (int *)xmalloc((size_t)macroCap * sizeof(int));
        macroB   = (int *)xmalloc((size_t)macroCap * sizeof(int));
        macroC   = (int *)xmalloc((size_t)macroCap * sizeof(int));
        macroD   = (int *)xmalloc((size_t)macroCap * sizeof(int));

        for (int i = 0; i < pfCount && macroCount < macroCap; ++i) {
            uint32_t f = pf[i].freq;
            if (f < MIN_NGRAM_FREQ) break;

            uint64_t key = pf[i].key;
            int dId = (int)(key & 0xFFFFu);
            int len = (dId == 0) ? 3 : 4;

            uint32_t gainTokens = (uint32_t)((len - 1) * (uint64_t)f);
            if (gainTokens < MIN_MACRO_GAIN_TOKENS) {
                continue;
            }

            int a = (int)((key >> 48) & 0xFFFFu);
            int b = (int)((key >> 32) & 0xFFFFu);
            int c = (int)((key >> 16) & 0xFFFFu);
            int d = dId;

            macroLen[macroCount] = len;
            macroA[macroCount]   = a;
            macroB[macroCount]   = b;
            macroC[macroCount]   = c;
            macroD[macroCount]   = (len == 4) ? d : 0;
            macroCount++;
        }

        if (macroCount == 0) {
            free(macroLen);
            free(macroA);
            free(macroB);
            free(macroC);
            free(macroD);
            macroLen = macroA = macroB = macroC = macroD = NULL;
        } else {
            macroLen = (int *)xrealloc(macroLen, (size_t)macroCount * sizeof(int));
            macroA   = (int *)xrealloc(macroA,   (size_t)macroCount * sizeof(int));
            macroB   = (int *)xrealloc(macroB,   (size_t)macroCount * sizeof(int));
            macroC   = (int *)xrealloc(macroC,   (size_t)macroCount * sizeof(int));
            macroD   = (int *)xrealloc(macroD,   (size_t)macroCount * sizeof(int));
        }
    }

    free(pf);

    *outMacroLen   = macroLen;
    *outMacroA     = macroA;
    *outMacroB     = macroB;
    *outMacroC     = macroC;
    *outMacroD     = macroD;
    *outMacroCount = macroCount;

    if (macroCount == 0) {
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    MacroMapEntry64 *map = (MacroMapEntry64 *)xmalloc((size_t)macroCount * sizeof(MacroMapEntry64));
    for (int i = 0; i < macroCount; ++i) {
        uint64_t key = ((uint64_t)macroA[i] << 48) |
                       ((uint64_t)macroB[i] << 32) |
                       ((uint64_t)macroC[i] << 16) |
                       (uint64_t)((macroLen[i] == 4) ? macroD[i] : 0);
        map[i].key = key;
        map[i].macroId = baseSymbolCount + i + 1;
    }
    qsort(map, (size_t)macroCount, sizeof(MacroMapEntry64), cmp_macromap64_key_asc);

    int i = 0;
    while (i < inStream->size) {
        int matched = 0;

        if (i + 3 < inStream->size) {
            int a = inStream->data[i];
            int b = inStream->data[i + 1];
            int c = inStream->data[i + 2];
            int d = inStream->data[i + 3];
            if (a >= 1 && a <= baseSymbolCount &&
                b >= 1 && b <= baseSymbolCount &&
                c >= 1 && c <= baseSymbolCount &&
                d >= 1 && d <= baseSymbolCount) {
                uint64_t key4 = ((uint64_t)a << 48) |
                                ((uint64_t)b << 32) |
                                ((uint64_t)c << 16) |
                                (uint64_t)d;
                int mid = macromap64_find(map, macroCount, key4);
                if (mid != 0) {
                    ivec_push(outStream, mid);
                    i += 4;
                    matched = 1;
                }
            }
        }

        if (!matched && i + 2 < inStream->size) {
            int a = inStream->data[i];
            int b = inStream->data[i + 1];
            int c = inStream->data[i + 2];
            if (a >= 1 && a <= baseSymbolCount &&
                b >= 1 && b <= baseSymbolCount &&
                c >= 1 && c <= baseSymbolCount) {
                uint64_t key3 = ((uint64_t)a << 48) |
                                ((uint64_t)b << 32) |
                                ((uint64_t)c << 16) |
                                0u;
                int mid = macromap64_find(map, macroCount, key3);
                if (mid != 0) {
                    ivec_push(outStream, mid);
                    i += 3;
                    matched = 1;
                }
            }
        }

        if (!matched) {
            ivec_push(outStream, inStream->data[i]);
            i++;
        }
    }

    free(map);
}

/* ============================
 * MAIN
 * ============================ */

int main(void) {
    const char *csvPath     = "skyrim_dialogue_clean.csv";
    const char *dictTxtPath = "dict_full.txt";
    const char *dictBinPath = "dict_full.bin";
    const char *huffBinPath = "dialog_huffman.bin";
    const char *packPath    = "dialogue_pack.deflate";

    FILE *csv = fopen(csvPath, "rb");
    if (!csv) {
        die("No se encuentra skyrim_dialogue_clean.csv en la carpeta actual.");
    }

    printf("Leyendo CSV limpio: %s\n", csvPath);

    char *line = read_line(csv);
    if (!line) {
        fclose(csv);
        die("CSV vacío o sin cabecera.");
    }
    free(line);

    Dict dictPass1;
    dict_init(&dictPass1, DICT_HASH_SIZE);
    IntVec streamPass1;
    ivec_init(&streamPass1);

    size_t totalLines = 0;

    while ((line = read_line(csv)) != NULL) {
        if (line[0] == '\0') {
            free(line);
            continue;
        }

        CsvRow row = parse_csv_line(line);
        free(line);

        if (row.count >= 6) {
            const char *text = row.cols[5];
            tokenize_text_pass1(text, &dictPass1, &streamPass1);
        }

        totalLines++;
        if (totalLines % 10000 == 0) {
            printf("Líneas procesadas: %zu\n", totalLines);
        }

        free_csv_row(&row);
    }
    fclose(csv);

    size_t totalTokensPass1 = (size_t)streamPass1.size;
    int baseTokensPass1 = dictPass1.nextId - 1;

    printf("PASS1 - líneas totales          : %zu\n", totalLines);
    printf("PASS1 - tokens totales          : %zu\n", totalTokensPass1);
    printf("PASS1 - tokens únicos (base)    : %d\n", baseTokensPass1);

    Dict dict;
    IntVec stream;
    apply_morphology(&streamPass1, &dictPass1, &dict, &stream);

    ivec_free(&streamPass1);
    dict_free(&dictPass1);

    size_t totalTokensMorph = (size_t)stream.size;
    int tokensAfterMorph = dict.nextId - 1;

    printf("PASS2 (morfología) - tokens totales: %zu\n", totalTokensMorph);
    printf("PASS2 (morfología) - tokens únicos : %d\n", tokensAfterMorph);

    int baseSymbolCount = reindex_tokens_by_length(&dict, &stream);

    printf("Tras reindexado por longitud - tokens únicos: %d\n", baseSymbolCount);

    int *macroLen = NULL;
    int *macroA   = NULL;
    int *macroB   = NULL;
    int *macroC   = NULL;
    int *macroD   = NULL;
    int macroCount = 0;
    IntVec stream2;

    build_ngram_macros(&stream, baseSymbolCount,
                       &macroLen, &macroA, &macroB, &macroC, &macroD,
                       &macroCount, &stream2);

    ivec_free(&stream);
    stream = stream2;

    int symbolCountTotal = baseSymbolCount + macroCount;
    size_t totalTokensFinal = (size_t)stream.size;

    printf("PASS3 (n-gramas) - macros usados   : %d\n", macroCount);
    printf("PASS3 (n-gramas) - tokens finales  : %zu\n", totalTokensFinal);
    printf("PASS3 (n-gramas) - símbolos totales: %d\n", symbolCountTotal);

    FILE *dictTxt = fopen(dictTxtPath, "wb");
    if (!dictTxt) {
        die("No se puede crear dict_full.txt");
    }

    for (int id = 1; id <= baseSymbolCount; ++id) {
        const char *token = dict.idToToken[id];
        if (!token) token = "";
        fprintf(dictTxt, "%d;%s\n", id, token);
    }

    for (int m = 0; m < macroCount; ++m) {
        int macroId = baseSymbolCount + m + 1;
        fprintf(dictTxt, "%d;%d,%d,%d", macroId, macroA[m], macroB[m], macroC[m]);
        if (macroLen[m] == 4) {
            fprintf(dictTxt, ",%d", macroD[m]);
        }
        fprintf(dictTxt, "\n");
    }

    fclose(dictTxt);
    printf("Escrito %s\n", dictTxtPath);

    FILE *dictBin = fopen(dictBinPath, "wb");
    if (!dictBin) {
        die("No se puede crear dict_full.bin");
    }

    fputc('D', dictBin);
    fputc('L', dictBin);
    fputc('G', dictBin);
    fputc('1', dictBin);

    uint32_t entryCount = (uint32_t)symbolCountTotal;
    fwrite(&entryCount, sizeof(uint32_t), 1, dictBin);

    for (int id = 1; id <= baseSymbolCount; ++id) {
        const char *token = dict.idToToken[id];
        if (!token) token = "";
        size_t tlen = strlen(token);
        if (tlen > 65535) die("Token demasiado largo (>65535 bytes)");
        uint16_t len16 = (uint16_t)tlen;
        fwrite(&len16, sizeof(uint16_t), 1, dictBin);
        fwrite(token, 1, tlen, dictBin);
    }

    for (int m = 0; m < macroCount; ++m) {
        char buf[128];
        if (macroLen[m] == 3) {
            snprintf(buf, sizeof(buf), "%d,%d,%d",
                     macroA[m], macroB[m], macroC[m]);
        } else {
            snprintf(buf, sizeof(buf), "%d,%d,%d,%d",
                     macroA[m], macroB[m], macroC[m], macroD[m]);
        }
        size_t tlen = strlen(buf);
        if (tlen > 65535) die("Token de macro demasiado largo (>65535 bytes)");
        uint16_t len16 = (uint16_t)tlen;
        fwrite(&len16, sizeof(uint16_t), 1, dictBin);
        fwrite(buf, 1, tlen, dictBin);
    }

    fclose(dictBin);
    printf("Escrito %s\n", dictBinPath);

    uint32_t *freq = (uint32_t *)xcalloc((size_t)(symbolCountTotal + 1),
                                         sizeof(uint32_t));
    for (int i2 = 0; i2 < stream.size; ++i2) {
        int id = stream.data[i2];
        if (id >= 1 && id <= symbolCountTotal) {
            freq[id]++;
        }
    }

    HuffNode *root = build_huffman_tree(freq, symbolCountTotal);
    if (!root) {
        die("No se pudo construir el árbol de Huffman.");
    }

    char **codes = (char **)xcalloc((size_t)(symbolCountTotal + 1),
                                    sizeof(char *));
    uint8_t *codeLen = (uint8_t *)xcalloc((size_t)(symbolCountTotal + 1),
                                          sizeof(uint8_t));

    char tmpBuf[512];
    build_codes_rec(root, tmpBuf, 0, codes, codeLen);

    BitWriter bw;
    bw_init(&bw);

    for (int i2 = 0; i2 < stream.size; ++i2) {
        int id = stream.data[i2];
        const char *code = codes[id];
        if (!code) die("Código Huffman nulo para un ID.");
        bw_put_code(&bw, code);
    }
    bw_flush(&bw);

    FILE *huffBin = fopen(huffBinPath, "wb");
    if (!huffBin) {
        die("No se puede crear dialog_huffman.bin");
    }

    fputc('H', huffBin);
    fputc('U', huffBin);
    fputc('F', huffBin);
    fputc('1', huffBin);

    uint32_t sc32 = (uint32_t)symbolCountTotal;
    fwrite(&sc32, sizeof(uint32_t), 1, huffBin);

    for (int id = 1; id <= symbolCountTotal; ++id) {
        uint8_t len = codeLen[id];
        fwrite(&len, 1, 1, huffBin);
    }

    uint32_t dataLen32 = (uint32_t)bw.size;
    fwrite(&dataLen32, sizeof(uint32_t), 1, huffBin);
    fwrite(bw.data, 1, bw.size, huffBin);

    fclose(huffBin);
    printf("Escrito %s\n", huffBinPath);

    long origSize = file_size(csvPath);
    long dictSize = file_size(dictBinPath);
    long huffSize = file_size(huffBinPath);

    if (dictSize < 0 || huffSize < 0) {
        die("No se pudo medir tamaño de dict_full.bin o dialog_huffman.bin");
    }

    size_t rawPackSize = sizeof(uint32_t) + (size_t)dictSize + (size_t)huffSize;
    uint8_t *rawPack = (uint8_t *)xmalloc(rawPackSize);

    uint32_t dictLen32 = (uint32_t)dictSize;
    memcpy(rawPack, &dictLen32, sizeof(uint32_t));

    FILE *fDict = fopen(dictBinPath, "rb");
    if (!fDict) die("No se puede reabrir dict_full.bin");
    if (fread(rawPack + sizeof(uint32_t), 1, (size_t)dictSize, fDict)
        != (size_t)dictSize) {
        fclose(fDict);
        die("Error leyendo dict_full.bin");
    }
    fclose(fDict);

    FILE *fHuff = fopen(huffBinPath, "rb");
    if (!fHuff) die("No se puede reabrir dialog_huffman.bin");
    if (fread(rawPack + sizeof(uint32_t) + (size_t)dictSize,
              1, (size_t)huffSize, fHuff) != (size_t)huffSize) {
        fclose(fHuff);
        die("Error leyendo dialog_huffman.bin");
    }
    fclose(fHuff);

        /* --- Compresión final con Zopfli (formato zlib) --- */
    unsigned char *comp = NULL;
    size_t destLen = 0;

    ZopfliOptions zopts;
    ZopfliInitOptions(&zopts);
    /* Puedes subir numiterations si quieres aún más compresión a costa de tiempo */
    zopts.numiterations = 15;

    ZopfliCompress(&zopts,
                   ZOPFLI_FORMAT_ZLIB,
                   (const unsigned char *)rawPack,
                   rawPackSize,
                   &comp,
                   &destLen);

    FILE *fPack = fopen(packPath, "wb");
    if (!fPack) {
        die("No se puede crear dialogue_pack.deflate");
    }
    if (fwrite(comp, 1, destLen, fPack) != destLen) {
        fclose(fPack);
        die("Error escribiendo dialogue_pack.deflate");
    }
    fclose(fPack);

    printf("\n--- Estadísticas ---\n");
    printf("Tamaño CSV original      : %ld bytes\n", origSize);
    printf("Tamaño dict_full.bin     : %ld bytes\n", dictSize);
    printf("Tamaño dialog_huffman    : %ld bytes\n", huffSize);
    printf("Tamaño paquete sin compr.: %zu bytes\n", rawPackSize);
    printf("Tamaño Deflate final     : %lu bytes\n", (unsigned long)destLen);

    if (origSize > 0) {
        long diffDict = origSize - dictSize;
        long diffHuff = origSize - huffSize;
        long diffPack = origSize - (long)destLen;

        double pctDict = 100.0 * (double)diffDict / (double)origSize;
        double pctHuff = 100.0 * (double)diffHuff / (double)origSize;
        double pctPack = 100.0 * (double)diffPack / (double)origSize;

        printf("\nAhorro respecto a CSV original:\n");
        printf(" dict_full.bin     : %+ld bytes (%.2f %%)\n", diffDict, pctDict);
        printf(" dialog_huffman    : %+ld bytes (%.2f %%)\n", diffHuff, pctHuff);
        printf(" dialogue_pack.defl: %+ld bytes (%.2f %%)\n", diffPack, pctPack);

        double ratioDictHuff = (double)origSize /
                               (double)(dictSize + huffSize);
        double ratioPack = (double)origSize / (double)destLen;
        printf("\nCompresión dict+Huffman : x%.2f\n", ratioDictHuff);
        printf("Compresión total (pack) : x%.2f\n", ratioPack);
    }

    free(rawPack);
    free(comp);
    free(freq);
    for (int id = 1; id <= symbolCountTotal; ++id) {
        free(codes[id]);
    }
    free(codes);
    free(codeLen);
    free_huffman_tree(root);
    ivec_free(&stream);
    dict_free(&dict);
    free(bw.data);
    free(macroLen);
    free(macroA);
    free(macroB);
    free(macroC);
    free(macroD);

    printf("\nPulsa ENTER para salir...");
    getchar();

    return 0;
}
