// convert_skyrim_dialogue.c
// Convierte SkyrimGOTY_Dialogue.txt -> skyrim_dialogue_clean.csv
// con eliminación de duplicados (formId,origin,expansion,part,text).
// Requiere uthash.h en el mismo directorio.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "uthash.h"

#define MAX_LINE 8192

#ifndef _MSC_VER
#define _strdup strdup
#endif

typedef struct SeenEntry {
    char *key;          // clave "formId|origin|expansion|part|text"
    UT_hash_handle hh;
} SeenEntry;

static void chomp(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\r' || s[n-1] == '\n')) {
        s[--n] = '\0';
    }
}

static char *trim_left(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static void trim_right(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n-1])) {
        s[--n] = '\0';
    }
}

// Escapa comillas para CSV
static char *escape_csv(const char *s) {
    if (!s) {
        char *r = (char*)malloc(3);
        strcpy(r, "\"\"");
        return r;
    }
    size_t len = strlen(s);
    // peor caso: todas comillas → se duplican
    char *r = (char*)malloc(len*2 + 3);
    char *dst = r;
    *dst++ = '"';
    for (const char *p = s; *p; ++p) {
        if (*p == '"') {
            *dst++ = '"';
        }
        *dst++ = *p;
    }
    *dst++ = '"';
    *dst = '\0';
    return r;
}

// Devuelve 1 si token es solo dígitos
static int is_number_token(const char *t) {
    if (!t || !*t) return 0;
    for (const char *p = t; *p; ++p) {
        if (!isdigit((unsigned char)*p)) return 0;
    }
    return 1;
}

int main(void) {
    const char *inputName  = "SkyrimGOTY_Dialogue.txt";
    const char *outputName = "skyrim_dialogue_clean.csv";

    FILE *fin = fopen(inputName, "rb");
    if (!fin) {
        fprintf(stderr, "No se pudo abrir %s\n", inputName);
        return 1;
    }
    FILE *fout = fopen(outputName, "wb");
    if (!fout) {
        fprintf(stderr, "No se pudo crear %s\n", outputName);
        fclose(fin);
        return 1;
    }

    printf("Carpeta actual       : .\\\n");
    printf("Archivo de entrada   : %s\n", inputName);
    printf("Archivo de salida    : %s\n", outputName);
    printf("Convirtiendo SkyrimGOTY_Dialogue.txt a skyrim_dialogue_clean.csv...\n");

    // Cabecera CSV
    fprintf(fout, "id,formId,origin,expansion,part,text\n");

    char buf[MAX_LINE];
    SeenEntry *seen = NULL;
    unsigned long long id = 1;
    unsigned long long totalLines = 0;
    unsigned long long keptLines  = 0;

    while (fgets(buf, sizeof(buf), fin)) {
        totalLines++;
        chomp(buf);
        trim_right(buf);
        char *line = trim_left(buf);
        if (*line == '\0') continue;

        // Solo líneas que comienzan por "FormID:"
        if (strncmp(line, "FormID:", 7) != 0) {
            continue;
        }

        // Hacemos una copia temporal para separar en tokens por espacios
        char *tmp = _strdup(line);
        if (!tmp) {
            fprintf(stderr, "Memoria insuficiente.\n");
            fclose(fin);
            fclose(fout);
            return 1;
        }

        // tokenizar por espacios
        char *tokens[128];
        int   tcount = 0;
        char *p = tmp;
        char *tok;
        while ((tok = strtok(p, " \t")) != NULL) {
            p = NULL;
            if (tcount < 128) {
                tokens[tcount++] = tok;
            } else {
                break;
            }
        }
        if (tcount < 2) {
            free(tmp);
            continue;
        }

        // tokens[0] debería ser "FormID:"
        // tokens[1] -> formId, tokens[2] -> origin, tokens[3] -> expansion (si existen)
        const char *formId    = (tcount > 1) ? tokens[1] : "";
        const char *origin    = (tcount > 2) ? tokens[2] : "";
        const char *expansion = (tcount > 3) ? tokens[3] : "";

        // Segunda pasada: buscar último número en la línea original (palabras separadas por espacios)
        // Recorremos tokens para encontrar el último que sea número
        const char *lastNumStr = NULL;
        int lastNumIndexInLine = -1;
        {
            // Para saber dónde empieza cada token en la línea original, hacemos un escaneo manual
            const char *l = line;
            int lenLine = (int)strlen(line);
            int tokenIndex = 0;
            int i = 0;

            while (i < lenLine && tokenIndex < tcount) {
                // saltar espacios
                while (i < lenLine && isspace((unsigned char)l[i])) i++;
                if (i >= lenLine) break;
                int start = i;
                while (i < lenLine && !isspace((unsigned char)l[i])) i++;
                int end = i; // [start,end)

                // extraemos esa "palabra"
                int wlen = end - start;
                if (wlen > 0 && tokenIndex < tcount) {
                    char tempWord[256];
                    if (wlen >= (int)sizeof(tempWord)) wlen = sizeof(tempWord)-1;
                    memcpy(tempWord, l+start, wlen);
                    tempWord[wlen] = '\0';

                    if (is_number_token(tempWord)) {
                        lastNumStr = tokens[tokenIndex];
                        lastNumIndexInLine = start;
                    }
                }
                tokenIndex++;
            }
        }

        if (!lastNumStr || lastNumIndexInLine < 0) {
            free(tmp);
            continue;
        }

        // Buscamos de nuevo la posición final del último número
        const char *l2 = line;
        int lenLine2 = (int)strlen(line);
        int startNum = lastNumIndexInLine;
        int endNum = startNum;
        while (endNum < lenLine2 && !isspace((unsigned char)l2[endNum])) endNum++;

        // Texto = todo lo que viene después de endNum
        if (endNum >= lenLine2) {
            free(tmp);
            continue;
        }
        char *text = _strdup(line + endNum);
        trim_right(text);
        char *textTrim = trim_left(text);
        if (*textTrim == '\0') {
            free(text);
            free(tmp);
            continue;
        }

        // clave para deduplicar
        size_t keyLen = strlen(formId) + strlen(origin) + strlen(expansion)
                      + strlen(lastNumStr) + strlen(textTrim) + 16;
        char *key = (char*)malloc(keyLen);
        if (!key) {
            fprintf(stderr, "Memoria insuficiente.\n");
            free(text);
            free(tmp);
            fclose(fin);
            fclose(fout);
            return 1;
        }
        snprintf(key, keyLen, "%s|%s|%s|%s|%s",
                 formId, origin, expansion, lastNumStr, textTrim);

        SeenEntry *entry;
        HASH_FIND_STR(seen, key, entry);
        if (!entry) {
            entry = (SeenEntry*)malloc(sizeof(SeenEntry));
            entry->key = key;
            HASH_ADD_KEYPTR(hh, seen, entry->key, strlen(entry->key), entry);

            // Escapar campos para CSV
            char *eFormId    = escape_csv(formId);
            char *eOrigin    = escape_csv(origin);
            char *eExpansion = escape_csv(expansion);
            char *ePart      = escape_csv(lastNumStr);
            char *eText      = escape_csv(textTrim);

            fprintf(fout, "%llu,%s,%s,%s,%s,%s\n",
                    id, eFormId, eOrigin, eExpansion, ePart, eText);

            free(eFormId);
            free(eOrigin);
            free(eExpansion);
            free(ePart);
            free(eText);

            id++;
            keptLines++;
            if (keptLines % 10000ULL == 0ULL) {
                printf("Líneas únicas de diálogo procesadas: %llu\n", keptLines);
            }
        } else {
            free(key);
        }

        free(text);
        free(tmp);
    }

    printf("Conversión terminada.\n");
    printf("Total líneas leídas     : %llu\n", totalLines);
    printf("Líneas únicas de diálogo: %llu\n", keptLines);

    fclose(fin);
    fclose(fout);

    // liberar hash
    SeenEntry *e, *tmpE;
    HASH_ITER(hh, seen, e, tmpE) {
        HASH_DEL(seen, e);
        free(e->key);
        free(e);
    }

    return 0;
}
