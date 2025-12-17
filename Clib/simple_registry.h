/*
 * simple_registry.h - Cross-platform Registry/Config helper functions for Eiffel
 *
 * Windows: Uses native Registry API (RegOpenKeyExA, etc.)
 * Linux/macOS: Uses file-based config store (~/.config/simple_eiffel/registry/)
 *
 * On non-Windows platforms, registry "keys" map to directories and
 * "values" map to files within those directories.
 *
 * Following Eric Bezault's recommended pattern: struct definitions
 * and helper functions in .h file, called from Eiffel inline C.
 *
 * Copyright (c) 2025 Larry Rix - MIT License
 */

#ifndef SIMPLE_REGISTRY_H
#define SIMPLE_REGISTRY_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32) || defined(EIF_WINDOWS)
/* ============ WINDOWS IMPLEMENTATION ============ */

#include <windows.h>

/* Result structure for registry operations */
typedef struct {
    int success;           /* Non-zero if operation succeeded */
    char* string_value;    /* String result (caller must free via sr_free_result) */
    DWORD dword_value;     /* DWORD result */
    char* error_message;   /* Error message if failed (caller must free) */
} sr_result;

/* Allocate and initialize a result structure */
static sr_result* sr_create_result(void) {
    sr_result* r = (sr_result*)malloc(sizeof(sr_result));
    if (r) {
        r->success = 0;
        r->string_value = NULL;
        r->dword_value = 0;
        r->error_message = NULL;
    }
    return r;
}

/* Set error message in result */
static void sr_set_error(sr_result* r, LONG error_code) {
    char buf[256];
    FormatMessageA(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error_code, 0, buf, sizeof(buf), NULL
    );
    r->error_message = _strdup(buf);
}

/* Free a result structure and its contents */
static void sr_free_result(sr_result* r) {
    if (r) {
        if (r->string_value) free(r->string_value);
        if (r->error_message) free(r->error_message);
        free(r);
    }
}

/* Read a string value from registry */
static sr_result* sr_read_string(HKEY root, const char* subkey, const char* name) {
    sr_result* r = sr_create_result();
    if (!r) return NULL;

    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        sr_set_error(r, result);
        return r;
    }

    DWORD type, size = 0;
    result = RegQueryValueExA(hKey, name, NULL, &type, NULL, &size);
    if (result != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        sr_set_error(r, result);
        return r;
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        RegCloseKey(hKey);
        r->error_message = _strdup("Value is not a string type");
        return r;
    }

    r->string_value = (char*)malloc(size + 1);
    if (!r->string_value) {
        RegCloseKey(hKey);
        r->error_message = _strdup("Memory allocation failed");
        return r;
    }

    result = RegQueryValueExA(hKey, name, NULL, NULL, (LPBYTE)r->string_value, &size);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        r->string_value[size] = '\0';
        r->success = 1;
    } else {
        free(r->string_value);
        r->string_value = NULL;
        sr_set_error(r, result);
    }

    return r;
}

/* Read a DWORD value from registry */
static sr_result* sr_read_dword(HKEY root, const char* subkey, const char* name) {
    sr_result* r = sr_create_result();
    if (!r) return NULL;

    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        sr_set_error(r, result);
        return r;
    }

    DWORD type, size = sizeof(DWORD);
    result = RegQueryValueExA(hKey, name, NULL, &type, (LPBYTE)&r->dword_value, &size);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS && type == REG_DWORD) {
        r->success = 1;
    } else if (result == ERROR_SUCCESS) {
        r->error_message = _strdup("Value is not a DWORD type");
    } else {
        sr_set_error(r, result);
    }

    return r;
}

/* Write a string value to registry */
static int sr_write_string(HKEY root, const char* subkey, const char* name, const char* value) {
    HKEY hKey;
    LONG result = RegCreateKeyExA(root, subkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) return 0;

    result = RegSetValueExA(hKey, name, 0, REG_SZ, (const BYTE*)value, (DWORD)strlen(value) + 1);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS) ? 1 : 0;
}

/* Write a DWORD value to registry */
static int sr_write_dword(HKEY root, const char* subkey, const char* name, DWORD value) {
    HKEY hKey;
    LONG result = RegCreateKeyExA(root, subkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) return 0;

    result = RegSetValueExA(hKey, name, 0, REG_DWORD, (const BYTE*)&value, sizeof(DWORD));
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS) ? 1 : 0;
}

/* Delete a registry value */
static int sr_delete_value(HKEY root, const char* subkey, const char* name) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) return 0;

    result = RegDeleteValueA(hKey, name);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS) ? 1 : 0;
}

/* Delete a registry key (must be empty) */
static int sr_delete_key(HKEY root, const char* subkey) {
    return (RegDeleteKeyA(root, subkey) == ERROR_SUCCESS) ? 1 : 0;
}

/* Check if a registry key exists */
static int sr_key_exists(HKEY root, const char* subkey) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}

/* Check if a registry value exists */
static int sr_value_exists(HKEY root, const char* subkey, const char* name) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) return 0;

    result = RegQueryValueExA(hKey, name, NULL, NULL, NULL, NULL);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS) ? 1 : 0;
}

/* Create a registry key */
static int sr_create_key(HKEY root, const char* subkey) {
    HKEY hKey;
    LONG result = RegCreateKeyExA(root, subkey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}

#else
/* ============ POSIX IMPLEMENTATION (Linux/macOS) ============ */
/* Uses file-based config store in ~/.config/simple_eiffel/registry/ */

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

/* Define HKEY as void* for API compatibility */
typedef void* HKEY;
typedef unsigned long DWORD;

/* Root key constants - map to different base directories */
#define HKEY_CLASSES_ROOT    ((HKEY)(unsigned long)0x80000000)
#define HKEY_CURRENT_USER    ((HKEY)(unsigned long)0x80000001)
#define HKEY_LOCAL_MACHINE   ((HKEY)(unsigned long)0x80000002)
#define HKEY_USERS           ((HKEY)(unsigned long)0x80000003)

/* Result structure for registry operations */
typedef struct {
    int success;           /* Non-zero if operation succeeded */
    char* string_value;    /* String result (caller must free via sr_free_result) */
    DWORD dword_value;     /* DWORD result */
    char* error_message;   /* Error message if failed (caller must free) */
} sr_result;

/* Get the base config directory */
static const char* sr_get_config_base(void) {
    static char base_path[PATH_MAX] = {0};
    const char* config_home;
    const char* home;

    if (base_path[0]) return base_path;

    config_home = getenv("XDG_CONFIG_HOME");
    if (config_home && config_home[0]) {
        snprintf(base_path, sizeof(base_path), "%s/simple_eiffel/registry", config_home);
    } else {
        home = getenv("HOME");
        if (home && home[0]) {
            snprintf(base_path, sizeof(base_path), "%s/.config/simple_eiffel/registry", home);
        } else {
            snprintf(base_path, sizeof(base_path), "/tmp/simple_eiffel/registry");
        }
    }

    return base_path;
}

/* Build full path for a registry key */
static void sr_build_path(char* buffer, size_t size, HKEY root, const char* subkey) {
    const char* base = sr_get_config_base();
    const char* root_name;

    /* Map root key to directory name */
    if (root == HKEY_CURRENT_USER) {
        root_name = "HKCU";
    } else if (root == HKEY_LOCAL_MACHINE) {
        root_name = "HKLM";
    } else if (root == HKEY_CLASSES_ROOT) {
        root_name = "HKCR";
    } else {
        root_name = "OTHER";
    }

    if (subkey && subkey[0]) {
        snprintf(buffer, size, "%s/%s/%s", base, root_name, subkey);
    } else {
        snprintf(buffer, size, "%s/%s", base, root_name);
    }

    /* Convert backslashes to forward slashes */
    for (char* p = buffer; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

/* Sanitize subkey to prevent path traversal attacks */
static int sr_is_safe_path(const char* path) {
    if (!path) return 1;
    /* Reject paths containing ".." */
    if (strstr(path, "..") != NULL) return 0;
    /* Reject absolute paths */
    if (path[0] == '/') return 0;
    return 1;
}

/* Create directories recursively with secure permissions (owner-only) */
static int sr_mkdir_recursive(const char* path) {
    char tmp[PATH_MAX];
    char* p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/') tmp[len - 1] = 0;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0700);  /* Owner-only: rwx------ */
            *p = '/';
        }
    }
    return mkdir(tmp, 0700) == 0 || errno == EEXIST;
}

/* Allocate and initialize a result structure */
static sr_result* sr_create_result(void) {
    sr_result* r = (sr_result*)malloc(sizeof(sr_result));
    if (r) {
        r->success = 0;
        r->string_value = NULL;
        r->dword_value = 0;
        r->error_message = NULL;
    }
    return r;
}

/* Free a result structure and its contents */
static void sr_free_result(sr_result* r) {
    if (r) {
        if (r->string_value) free(r->string_value);
        if (r->error_message) free(r->error_message);
        free(r);
    }
}

/* Read a string value from file-based registry */
static sr_result* sr_read_string(HKEY root, const char* subkey, const char* name) {
    sr_result* r = sr_create_result();
    if (!r) return NULL;

    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    FILE* f;
    char buffer[4096];
    size_t len;

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);
    snprintf(file_path, sizeof(file_path), "%s/%s.str", dir_path, name);

    f = fopen(file_path, "r");
    if (!f) {
        r->error_message = strdup("Value not found");
        return r;
    }

    len = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);

    if (len > 0) {
        buffer[len] = '\0';
        r->string_value = strdup(buffer);
        r->success = 1;
    } else {
        r->error_message = strdup("Failed to read value");
    }

    return r;
}

/* Read a DWORD value from file-based registry */
static sr_result* sr_read_dword(HKEY root, const char* subkey, const char* name) {
    sr_result* r = sr_create_result();
    if (!r) return NULL;

    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    FILE* f;

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);
    snprintf(file_path, sizeof(file_path), "%s/%s.dword", dir_path, name);

    f = fopen(file_path, "r");
    if (!f) {
        r->error_message = strdup("Value not found");
        return r;
    }

    if (fscanf(f, "%lu", &r->dword_value) == 1) {
        r->success = 1;
    } else {
        r->error_message = strdup("Failed to read DWORD value");
    }

    fclose(f);
    return r;
}

/* Write a string value to file-based registry */
static int sr_write_string(HKEY root, const char* subkey, const char* name, const char* value) {
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    FILE* f;
    int fd;

    /* Security: validate path components */
    if (!sr_is_safe_path(subkey) || !sr_is_safe_path(name)) {
        return 0;
    }

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);

    if (!sr_mkdir_recursive(dir_path)) {
        return 0;
    }

    snprintf(file_path, sizeof(file_path), "%s/%s.str", dir_path, name);

    /* Create file with owner-only permissions (rw-------) */
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;

    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return 0;
    }

    fprintf(f, "%s", value);
    fclose(f);
    return 1;
}

/* Write a DWORD value to file-based registry */
static int sr_write_dword(HKEY root, const char* subkey, const char* name, DWORD value) {
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    FILE* f;
    int fd;

    /* Security: validate path components */
    if (!sr_is_safe_path(subkey) || !sr_is_safe_path(name)) {
        return 0;
    }

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);

    if (!sr_mkdir_recursive(dir_path)) {
        return 0;
    }

    snprintf(file_path, sizeof(file_path), "%s/%s.dword", dir_path, name);

    /* Create file with owner-only permissions (rw-------) */
    fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;

    f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return 0;
    }

    fprintf(f, "%lu", value);
    fclose(f);
    return 1;
}

/* Delete a registry value */
static int sr_delete_value(HKEY root, const char* subkey, const char* name) {
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);

    /* Try both string and dword files */
    snprintf(file_path, sizeof(file_path), "%s/%s.str", dir_path, name);
    if (unlink(file_path) == 0) return 1;

    snprintf(file_path, sizeof(file_path), "%s/%s.dword", dir_path, name);
    if (unlink(file_path) == 0) return 1;

    return 0;
}

/* Delete a registry key (directory) */
static int sr_delete_key(HKEY root, const char* subkey) {
    char dir_path[PATH_MAX];
    sr_build_path(dir_path, sizeof(dir_path), root, subkey);
    return rmdir(dir_path) == 0 ? 1 : 0;
}

/* Check if a registry key exists */
static int sr_key_exists(HKEY root, const char* subkey) {
    char dir_path[PATH_MAX];
    struct stat st;

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);
    return (stat(dir_path, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
}

/* Check if a registry value exists */
static int sr_value_exists(HKEY root, const char* subkey, const char* name) {
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    struct stat st;

    sr_build_path(dir_path, sizeof(dir_path), root, subkey);

    /* Check string file */
    snprintf(file_path, sizeof(file_path), "%s/%s.str", dir_path, name);
    if (stat(file_path, &st) == 0 && S_ISREG(st.st_mode)) return 1;

    /* Check dword file */
    snprintf(file_path, sizeof(file_path), "%s/%s.dword", dir_path, name);
    if (stat(file_path, &st) == 0 && S_ISREG(st.st_mode)) return 1;

    return 0;
}

/* Create a registry key */
static int sr_create_key(HKEY root, const char* subkey) {
    char dir_path[PATH_MAX];
    sr_build_path(dir_path, sizeof(dir_path), root, subkey);
    return sr_mkdir_recursive(dir_path);
}

#endif /* _WIN32 */

#endif /* SIMPLE_REGISTRY_H */
