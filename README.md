<p align="center">
  <img src="https://raw.githubusercontent.com/simple-eiffel/claude_eiffel_op_docs/main/artwork/LOGO.png" alt="simple_ library logo" width="400">
</p>

# SIMPLE_REGISTRY

**[Documentation](https://simple-eiffel.github.io/simple_registry/)**

### Windows Registry Access Library for Eiffel

[![Language](https://img.shields.io/badge/language-Eiffel-blue.svg)](https://www.eiffel.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue.svg)]()
[![SCOOP](https://img.shields.io/badge/SCOOP-compatible-orange.svg)]()
[![Design by Contract](https://img.shields.io/badge/DbC-enforced-orange.svg)]()
[![Tests](https://img.shields.io/badge/tests-9%20passing-brightgreen.svg)]()

---

## Overview

SIMPLE_REGISTRY provides safe, SCOOP-compatible access to the Windows Registry from Eiffel applications. It wraps the Win32 Registry API functions (RegOpenKeyEx, RegQueryValueEx, RegSetValueEx, RegDeleteValue, etc.) through a clean C interface, enabling registry operations without threading complications.

The library supports reading and writing string, integer, and binary values across all major registry hives (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, etc.), with proper error handling and resource cleanup.

**Developed using AI-assisted methodology:** Built interactively with Claude Opus 4.5 following rigorous Design by Contract principles.

---

## Features

### Registry Operations

- **Read Values** - Query string, integer (DWORD), and binary registry values
- **Write Values** - Create or update string and integer values
- **Delete Values** - Remove specific values from registry keys
- **Key Management** - Open, create, and delete registry keys
- **Value Enumeration** - List all values under a registry key

### Registry Hives

| Constant | Hive |
|----------|------|
| `HKCU` | HKEY_CURRENT_USER |
| `HKLM` | HKEY_LOCAL_MACHINE |
| `HKCR` | HKEY_CLASSES_ROOT |
| `HKU` | HKEY_USERS |
| `HKCC` | HKEY_CURRENT_CONFIG |

### Value Types

| Type | Eiffel Method |
|------|---------------|
| REG_SZ | `read_string`, `write_string` |
| REG_DWORD | `read_integer`, `write_integer` |
| REG_BINARY | `read_binary` |

---

## Quick Start

### Installation

1. Clone the repository:
```bash
git clone https://github.com/simple-eiffel/simple_registry.git
```

2. Compile the C library:
```bash
cd simple_registry/Clib
compile.bat
```

3. Set the environment variable:
```bash
set SIMPLE_REGISTRY=D:\path\to\simple_registry
```

4. Add to your ECF file:
```xml
<library name="simple_registry" location="$SIMPLE_REGISTRY\simple_registry.ecf"/>
```

### Basic Usage

```eiffel
class
    MY_APPLICATION

feature

    read_example
        local
            reg: SIMPLE_REGISTRY
            value: detachable STRING_8
        do
            create reg.make

            -- Read a string value from HKEY_CURRENT_USER
            value := reg.read_string (reg.HKCU, "Software\MyApp", "Username")

            if attached value as v then
                print ("Username: " + v)
            end

            reg.close
        end

    write_example
        local
            reg: SIMPLE_REGISTRY
        do
            create reg.make

            -- Write a string value
            reg.write_string (reg.HKCU, "Software\MyApp", "Username", "JohnDoe")

            -- Write an integer value
            reg.write_integer (reg.HKCU, "Software\MyApp", "LaunchCount", 42)

            if reg.last_write_succeeded then
                print ("Value written successfully")
            end

            reg.close
        end

end
```

---

## API Reference

### SIMPLE_REGISTRY Class

#### Creation

```eiffel
make
    -- Initialize registry access.
```

#### Reading Values

```eiffel
read_string (a_hive: INTEGER; a_subkey, a_value_name: STRING_8): detachable STRING_8
    -- Read REG_SZ value from registry.

read_integer (a_hive: INTEGER; a_subkey, a_value_name: STRING_8): INTEGER
    -- Read REG_DWORD value from registry.

read_binary (a_hive: INTEGER; a_subkey, a_value_name: STRING_8): detachable ARRAY [NATURAL_8]
    -- Read REG_BINARY value from registry.
```

#### Writing Values

```eiffel
write_string (a_hive: INTEGER; a_subkey, a_value_name, a_value: STRING_8)
    -- Write REG_SZ value to registry.

write_integer (a_hive: INTEGER; a_subkey, a_value_name: STRING_8; a_value: INTEGER)
    -- Write REG_DWORD value to registry.
```

#### Deleting Values

```eiffel
delete_value (a_hive: INTEGER; a_subkey, a_value_name: STRING_8): BOOLEAN
    -- Delete a value from the registry.
```

#### Status Queries

```eiffel
last_read_succeeded: BOOLEAN
    -- Did the last read operation succeed?

last_write_succeeded: BOOLEAN
    -- Did the last write operation succeed?

last_error_code: INTEGER
    -- Windows error code from last failed operation.
```

---

## Building & Testing

### Build Library

```bash
cd simple_registry
ec -config simple_registry.ecf -target simple_registry -c_compile
```

### Run Tests

```bash
ec -config simple_registry.ecf -target simple_registry_tests -c_compile
./EIFGENs/simple_registry_tests/W_code/simple_registry.exe
```

**Test Results:** 9 tests passing

---

## Project Structure

```
simple_registry/
├── Clib/                       # C wrapper library
│   ├── simple_registry.h       # C header file
│   ├── simple_registry.c       # C implementation
│   └── compile.bat             # Build script
├── src/                        # Eiffel source
│   └── simple_registry.e       # Main wrapper class
├── testing/                    # Test suite
│   ├── application.e           # Test runner
│   └── test_simple_registry.e  # Test cases
├── simple_registry.ecf         # Library configuration
├── README.md                   # This file
└── LICENSE                     # MIT License
```

---

## Dependencies

- **Windows OS** - Registry API is Windows-specific
- **EiffelStudio 23.09+** - Development environment
- **Visual Studio C++ Build Tools** - For compiling C wrapper

---

## SCOOP Compatibility

SIMPLE_REGISTRY is fully SCOOP-compatible. The C wrapper handles all Win32 API calls synchronously without threading dependencies, making it safe for use in concurrent Eiffel applications.

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Contact

- **Author:** Larry Rix
- **Repository:** https://github.com/simple-eiffel/simple_registry
- **Issues:** https://github.com/simple-eiffel/simple_registry/issues

---

## Acknowledgments

- Built with Claude Opus 4.5 (Anthropic)
- Uses Win32 Registry API (Microsoft)
- Part of the simple_ library collection for Eiffel
