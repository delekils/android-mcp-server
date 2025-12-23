# BadLog Rules

Rules are YAML or JSON lists of objects. Each rule includes:

- `name`: unique identifier
- `severity`: INFO, MEDIUM, HIGH, CRITICAL
- `category`: WATCHDOG, KERNEL, MEMORY, POWER, ANR, TOMBSTONE, THERMAL, STORAGE, SECURITY, FRAMEWORK
- `pattern`: case-insensitive regex
- `context_boost`: extra pre/post lines to capture

Example:

```yaml
- name: thermal_shutdown
  severity: HIGH
  category: THERMAL
  pattern: "thermal.*shutdown|overheat"
  context_boost: 10
```
