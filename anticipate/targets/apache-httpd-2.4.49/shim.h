/* Minimal stand-ins so the extracted functions compile without APR. */
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef size_t apr_size_t;
#define AP_DECLARE(t) t
#define APR_CHARSET_EBCDIC 0
#define apr_isxdigit(c) isxdigit((unsigned char)(c))
#define apr_isalnum(c) isalnum((unsigned char)(c))
#define apr_isalpha(c) isalpha((unsigned char)(c))
#define apr_isdigit(c) isdigit((unsigned char)(c))
#define apr_isspace(c) isspace((unsigned char)(c))
#define apr_isupper(c) isupper((unsigned char)(c))
#define apr_islower(c) islower((unsigned char)(c))
#define apr_tolower(c) tolower((unsigned char)(c))
#define apr_toupper(c) toupper((unsigned char)(c))
#define IS_SLASH(s) ((s) == '/')
#define IS_SLASH_OR_NUL(s) ((s) == '\0' || IS_SLASH(s))
#define AP_NORMALIZE_ALLOW_RELATIVE     (1u <<  0)
#define AP_NORMALIZE_NOT_ABOVE_ROOT     (1u <<  1)
#define AP_NORMALIZE_DECODE_UNRESERVED  (1u <<  2)
#define AP_NORMALIZE_MERGE_SLASHES      (1u <<  3)
#define AP_NORMALIZE_DROP_PARAMETERS    (1u <<  4)
static char x2c(const char *what);
