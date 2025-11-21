/* build_dialog_huffman.c
 *
 * Builder de diccionario + Huffman + macros de trigramas + paquete Deflate
 * para los diálogos de Skyrim limpios en CSV:
 *
 *   skyrim_dialogue_clean.csv
 *   (cabecera: id,formId,origin,expansion,part,text)
 *
 * Salidas:
 *   - dict_full.txt       (id;token o id;id1,id2,id3 para macros)
 *   - dict_full.bin       (binario compacto: solo longitud + texto)
 *   - dialog_huffman.bin  (HUF1 + tabla de longitudes + bitstream)
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
                /* comilla escapada "" -> " */
                if (fieldLen + 1 >= fieldCap) {
                    fieldCap *= 2;
                    field = (char *)xrealloc(field, fieldCap);
                }
                field[fieldLen++] = '"';
                p++; /* saltar segunda comilla */
            } else {
                in_quotes = !in_quotes;
            }
        } else if (c == ',' && !in_quotes) {
            /* fin de campo */
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
    /* FNV-1a 32-bit */
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

    /* nuevo token */
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
        /* Los tokens ya se liberan en los buckets; aquí solo el array. */
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
 * Normalización de texto + tokenización
 * ============================ */

/* Sufijos de contracción tratadas como tokens propios */
static const char * const CONTR_SUFFIXES[] = {
    "'re","'ve","'ll","'d","'s","'m","'t","'em"
};
static const int CONTR_SUFFIX_COUNT = 8;

/* Emite un token (string) al diccionario + stream */
static void emit_token_str(Dict *dict, IntVec *stream, const char *s, int len) {
    if (len <= 0) return;
    char buf[256];
    if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
    memcpy(buf, s, (size_t)len);
    buf[len] = '\0';
    int id = dict_get_or_add(dict, buf);
    ivec_push(stream, id);
}

/* Procesa una “palabra” con posibles contracciones tipo you're, it's, can't... */
static void process_word_token(const char *word, int len, Dict *dict, IntVec *stream) {
    if (len <= 0) return;

    int aposIndex = -1;
    for (int i = 1; i < len; ++i) {
        if (word[i] == '\'') {
            aposIndex = i;
            break;
        }
    }

    if (aposIndex > 0 && aposIndex < len - 1) {
        const char *suffix = word + aposIndex;
        int sLen = len - aposIndex;

        for (int si = 0; si < CONTR_SUFFIX_COUNT; ++si) {
            const char *suff = CONTR_SUFFIXES[si];
            int suffLen = (int)strlen(suff);
            if (sLen == suffLen && memcmp(suffix, suff, (size_t)sLen) == 0) {
                int baseLen = aposIndex;
                int baseOk = 1;
                if (baseLen <= 0) baseOk = 0;
                for (int j = 0; j < baseLen; ++j) {
                    unsigned char c = (unsigned char)word[j];
                    if (!isalnum(c)) {
                        baseOk = 0;
                        break;
                    }
                }
                if (baseOk) {
                    /* ej: "you're" -> "you" + "'re" */
                    emit_token_str(dict, stream, word, baseLen);
                    emit_token_str(dict, stream, suffix, sLen);
                    return;
                }
            }
        }
    }

    /* Si no hay contracción relevante, emitimos la palabra entera */
    emit_token_str(dict, stream, word, len);
}

/* Corta colas tipo: "papa.  Disappointed" o "papa.   (inner monologue)" */
static char *strip_trailing_stage_dir(const char *text) {
    size_t n = strlen(text);
    for (size_t i = 0; i < n; ++i) {
        char c = text[i];
        if (c == '.' || c == '!' || c == '?' ) {
            size_t j = i + 1;
            int spaceCount = 0;
            while (j < n && text[j] == ' ') {
                spaceCount++;
                j++;
            }
            if (spaceCount >= 2 && j < n) {
                unsigned char next = (unsigned char)text[j];
                if ((next >= 'A' && next <= 'Z') || next == '(') {
                    /* Nos quedamos hasta el punto (o !, ?) inclusive */
                    size_t outLen = i + 1;
                    char *out = (char *)xmalloc(outLen + 1);
                    memcpy(out, text, outLen);
                    out[outLen] = '\0';
                    return out;
                }
            }
        }
    }
    /* Sin cola tipo "Disappointed": devolvemos copia completa */
    size_t outLen = n;
    char *out = (char *)xmalloc(outLen + 1);
    memcpy(out, text, outLen + 1);
    return out;
}

/* Pasa a lowercase y elimina [texto] entre corchetes */
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
        if (depth > 0) {
            continue; /* estamos dentro de [ ... ], se ignora */
        }
        out[o++] = (char)tolower((unsigned char)c);
    }

    out[o] = '\0';
    return out;
}

/* Normalización completa: cortar cola + corchetes + lowercase */
static char *normalize_text(const char *text) {
    char *cut = strip_trailing_stage_dir(text);
    char *norm = normalize_case_and_brackets(cut);
    free(cut);
    return norm;
}

/* Nueva tokenización: palabras + puntuación como tokens separados */
static void tokenize_text(const char *text, Dict *dict, IntVec *stream) {
    char *norm = normalize_text(text);
    size_t len = strlen(norm);
    size_t i = 0;
    char wordBuf[512];
    int wlen = 0;

    while (i < len) {
        unsigned char c = (unsigned char)norm[i];

        if (isspace(c)) {
            if (wlen > 0) {
                process_word_token(wordBuf, wlen, dict, stream);
                wlen = 0;
            }
            i++;
            continue;
        }

        /* Puntuación como token propio */
        if (c == '.' || c == ',' || c == '!' || c == '?' ||
            c == ';' || c == ':' || c == '(' || c == ')') {

            if (wlen > 0) {
                process_word_token(wordBuf, wlen, dict, stream);
                wlen = 0;
            }

            if (c == '.') {
                /* Rachas de puntos: "." ".." "..." => un solo token */
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

        /* Caracter de palabra: letras, dígitos, guión bajo, apóstrofe */
        if (isalnum(c) || c == '\'' || c == '_') {
            if (wlen < (int)sizeof(wordBuf) - 1) {
                wordBuf[wlen++] = (char)c;
            }
            i++;
        } else {
            if (wlen > 0) {
                process_word_token(wordBuf, wlen, dict, stream);
                wlen = 0;
            }
            i++;
        }
    }

    if (wlen > 0) {
        process_word_token(wordBuf, wlen, dict, stream);
    }

    free(norm);
}

/* ============================
 * Huffman
 * ============================ */

typedef struct HuffNode {
    int sym;            /* >0 simbolo, -1 interno */
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
 * BitWriter para el stream Huffman
 * ============================ */

typedef struct {
    uint8_t *data;
    size_t size;   /* bytes llenos */
    size_t cap;
    int bitPos;    /* 0..7 bit actual dentro del byte */
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
 * Macros de trigramas (3 tokens)
 * ============================ */

#define MACRO_LEN              3
#define MAX_MACROS             4096
#define MIN_TRIGRAM_FREQ       8
#define MIN_MACRO_GAIN_TOKENS  32   /* ganancia mínima en nº de IDs del stream */

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

/* Construye macros de trigramas y re-encode el stream */
static void build_trigram_macros(const IntVec *inStream,
                                 int baseSymbolCount,
                                 int **outMacroA,
                                 int **outMacroB,
                                 int **outMacroC,
                                 int *outMacroCount,
                                 IntVec *outStream)
{
    *outMacroA = NULL;
    *outMacroB = NULL;
    *outMacroC = NULL;
    *outMacroCount = 0;
    ivec_init(outStream);

    if (inStream->size < MACRO_LEN || baseSymbolCount <= 0) {
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    if (baseSymbolCount > 65535) {
        fprintf(stderr,
                "Aviso: demasiados tokens únicos (%d) para macros de 16 bits; "
                "se desactivan macros de trigramas.\n",
                baseSymbolCount);
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    int ngramTotal = inStream->size - (MACRO_LEN - 1);
    uint64_t *keys = (uint64_t *)xmalloc((size_t)ngramTotal * sizeof(uint64_t));
    int usedKeys = 0;

    for (int i = 0; i < ngramTotal; ++i) {
        int a = inStream->data[i];
        int b = inStream->data[i + 1];
        int c = inStream->data[i + 2];

        if (a < 1 || a > baseSymbolCount ||
            b < 1 || b > baseSymbolCount ||
            c < 1 || c > baseSymbolCount) {
            continue;
        }

        uint64_t key = ((uint64_t)a << 32) | ((uint64_t)b << 16) | (uint64_t)c;
        keys[usedKeys++] = key;
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
    int *macroA = NULL;
    int *macroB = NULL;
    int *macroC = NULL;

    if (macroCap > 0) {
        macroA = (int *)xmalloc((size_t)macroCap * sizeof(int));
        macroB = (int *)xmalloc((size_t)macroCap * sizeof(int));
        macroC = (int *)xmalloc((size_t)macroCap * sizeof(int));

        for (int i = 0; i < pfCount && macroCount < macroCap; ++i) {
            uint32_t f = pf[i].freq;

            if (f < MIN_TRIGRAM_FREQ) break;

            /* Ganancia aproximada: (MACRO_LEN - 1) * f, para trigramas: 2*f */
            uint32_t gainTokens = (MACRO_LEN - 1) * f;
            if (gainTokens < MIN_MACRO_GAIN_TOKENS) {
                continue;
            }

            uint64_t key = pf[i].key;
            int a = (int)((key >> 32) & 0xFFFFu);
            int b = (int)((key >> 16) & 0xFFFFu);
            int c = (int)(key & 0xFFFFu);

            macroA[macroCount] = a;
            macroB[macroCount] = b;
            macroC[macroCount] = c;
            macroCount++;
        }

        if (macroCount == 0) {
            free(macroA);
            free(macroB);
            free(macroC);
            macroA = macroB = macroC = NULL;
        } else {
            macroA = (int *)xrealloc(macroA, (size_t)macroCount * sizeof(int));
            macroB = (int *)xrealloc(macroB, (size_t)macroCount * sizeof(int));
            macroC = (int *)xrealloc(macroC, (size_t)macroCount * sizeof(int));
        }
    }

    free(pf);

    *outMacroA = macroA;
    *outMacroB = macroB;
    *outMacroC = macroC;
    *outMacroCount = macroCount;

    if (macroCount == 0) {
        for (int i = 0; i < inStream->size; ++i) {
            ivec_push(outStream, inStream->data[i]);
        }
        return;
    }

    /* Mapa key -> macroId para reescritura rápida */
    MacroMapEntry64 *map = (MacroMapEntry64 *)xmalloc((size_t)macroCount * sizeof(MacroMapEntry64));
    for (int i = 0; i < macroCount; ++i) {
        uint64_t key = ((uint64_t)macroA[i] << 32) |
                       ((uint64_t)macroB[i] << 16) |
                       (uint64_t)macroC[i];
        map[i].key = key;
        map[i].macroId = baseSymbolCount + i + 1;
    }
    qsort(map, (size_t)macroCount, sizeof(MacroMapEntry64), cmp_macromap64_key_asc);

    /* Reescritura greedy del stream: si hay trigram-macro, sustituye (a,b,c) por macroId */
    int i = 0;
    while (i < inStream->size) {
        if (i + (MACRO_LEN - 1) < inStream->size) {
            int a = inStream->data[i];
            int b = inStream->data[i + 1];
            int c = inStream->data[i + 2];
            if (a >= 1 && a <= baseSymbolCount &&
                b >= 1 && b <= baseSymbolCount &&
                c >= 1 && c <= baseSymbolCount) {
                uint64_t key = ((uint64_t)a << 32) |
                               ((uint64_t)b << 16) |
                               (uint64_t)c;
                int mid = macromap64_find(map, macroCount, key);
                if (mid != 0) {
                    ivec_push(outStream, mid);
                    i += MACRO_LEN;
                    continue;
                }
            }
        }
        ivec_push(outStream, inStream->data[i]);
        i++;
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

    /* Saltar cabecera */
    char *line = read_line(csv);
    if (!line) {
        fclose(csv);
        die("CSV vacío o sin cabecera.");
    }
    free(line);

    Dict dict;
    dict_init(&dict, DICT_HASH_SIZE);

    IntVec stream;
    ivec_init(&stream);

    size_t totalLines = 0;

    while ((line = read_line(csv)) != NULL) {
        if (line[0] == '\0') {
            free(line);
            continue;
        }

        CsvRow row = parse_csv_line(line);
        free(line);

        /* Esperamos al menos 6 columnas: id,formId,origin,expansion,part,text */
        if (row.count >= 6) {
            const char *text = row.cols[5];
            tokenize_text(text, &dict, &stream);
        }

        totalLines++;
        if (totalLines % 10000 == 0) {
            printf("Líneas procesadas: %zu\n", totalLines);
        }

        free_csv_row(&row);
    }

    fclose(csv);

    size_t totalTokensInitial = (size_t)stream.size;
    int baseSymbolCount = dict.nextId - 1;
    if (baseSymbolCount <= 0) {
        die("No se generaron tokens; ¿CSV vacío?");
    }

    printf("Líneas totales          : %zu\n", totalLines);
    printf("Tokens totales iniciales: %zu\n", totalTokensInitial);
    printf("Tokens únicos (base)    : %d\n", baseSymbolCount);

    /* ==============================
     * Macros de trigramas
     * ============================== */

    int *macroA = NULL;
    int *macroB = NULL;
    int *macroC = NULL;
    int macroCount = 0;
    IntVec stream2;
    build_trigram_macros(&stream, baseSymbolCount,
                         &macroA, &macroB, &macroC, &macroCount, &stream2);

    ivec_free(&stream);
    stream = stream2;

    int symbolCountTotal = baseSymbolCount + macroCount;
    size_t totalTokensFinal = (size_t)stream.size;

    printf("Macros de trigramas usadas: %d\n", macroCount);
    printf("Tokens tras macros         : %zu\n", totalTokensFinal);
    printf("Símbolos totales           : %d\n", symbolCountTotal);

    /* ==============================
     * Escribir dict_full.txt (mínimo)
     * ============================== */

    FILE *dictTxt = fopen(dictTxtPath, "wb");
    if (!dictTxt) {
        die("No se puede crear dict_full.txt");
    }

    /* Tokens base */
    for (int id = 1; id <= baseSymbolCount; ++id) {
        const char *token = dict.idToToken[id];
        if (!token) token = "";
        fprintf(dictTxt, "%d;%s\n", id, token);
    }

    /* Macros como texto "id1,id2,id3" */
    for (int m = 0; m < macroCount; ++m) {
        int macroId = baseSymbolCount + m + 1;
        int a = macroA[m];
        int b = macroB[m];
        int c = macroC[m];
        fprintf(dictTxt, "%d;%d,%d,%d\n", macroId, a, b, c);
    }

    fclose(dictTxt);
    printf("Escrito %s\n", dictTxtPath);

    /* ==============================
     * Diccionario binario dict_full.bin (compacto)
     *
     * Formato:
     *   - 'D','L','G','1'
     *   - uint32_t entryCount
     *   - para id=1..entryCount:
     *       uint16_t lenBytes
     *       bytes UTF-8 del token
     * ============================== */

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

    /* Tokens base */
    for (int id = 1; id <= baseSymbolCount; ++id) {
        const char *token = dict.idToToken[id];
        if (!token) token = "";
        size_t tlen = strlen(token);
        if (tlen > 65535) {
            die("Token demasiado largo (>65535 bytes)");
        }
        uint16_t len16 = (uint16_t)tlen;
        fwrite(&len16, sizeof(uint16_t), 1, dictBin);
        fwrite(token, 1, tlen, dictBin);
    }

    /* Macros: texto "id1,id2,id3" */
    for (int m = 0; m < macroCount; ++m) {
        char buf[96];
        int a = macroA[m];
        int b = macroB[m];
        int c = macroC[m];
        snprintf(buf, sizeof(buf), "%d,%d,%d", a, b, c);
        size_t tlen = strlen(buf);
        if (tlen > 65535) {
            die("Token de macro demasiado largo (>65535 bytes)");
        }
        uint16_t len16 = (uint16_t)tlen;
        fwrite(&len16, sizeof(uint16_t), 1, dictBin);
        fwrite(buf, 1, tlen, dictBin);
    }

    fclose(dictBin);
    printf("Escrito %s\n", dictBinPath);

    /* ==============================
     * Huffman sobre IDs (tokens + macros)
     * ============================== */

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
        if (!code) {
            die("Código Huffman nulo para un ID.");
        }
        bw_put_code(&bw, code);
    }
    bw_flush(&bw);

    /* ==============================
     * Escribir dialog_huffman.bin
     * ============================== */

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

    /* ==============================
     * Paquete final Deflate
     * ============================== */

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

    uLong srcLen = (uLong)rawPackSize;
    uLongf destLen = compressBound(srcLen);
    uint8_t *comp = (uint8_t *)xmalloc(destLen);

    int zres = compress2(comp, &destLen, rawPack, srcLen, Z_BEST_COMPRESSION);
    if (zres != Z_OK) {
        die("compress2() falló al generar el paquete Deflate");
    }

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
    printf("Tamaño CSV original     : %ld bytes\n", origSize);
    printf("Tamaño dict_full.bin    : %ld bytes\n", dictSize);
    printf("Tamaño dialog_huffman   : %ld bytes\n", huffSize);
    printf("Tamaño paquete raw      : %zu bytes\n", rawPackSize);
    printf("Tamaño Deflate final    : %lu bytes\n", (unsigned long)destLen);

    if (origSize > 0) {
        double ratioDictHuff = (double)origSize /
                               (double)(dictSize + huffSize);
        double ratioPack = (double)origSize / (double)destLen;
        printf("Compresión dict+Huffman : x%.2f\n", ratioDictHuff);
        printf("Compresión total        : x%.2f\n", ratioPack);
    }

    /* Limpieza básica */
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
    free(macroA);
    free(macroB);
    free(macroC);

    return 0;
}
