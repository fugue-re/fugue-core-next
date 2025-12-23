# ghidra2specs

Convert Ghidra's patterns to a format compatible with fugue-specs.

## Examples

```sh
uv run main.py x86_generic_patterns.xml x86-generic.yml --language 'x86:LE:32:default:*'
uv run main.py x86gcc_patterns.xml x86-gcc.yml --language 'x86:LE:32:default:gcc'
```
