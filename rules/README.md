# BadLog Rules

Rules are YAML or JSON lists with metadata. The default format is versioned:

```yaml
version: 2
rules:
  - name: thermal_shutdown
    severity: HIGH
    category: THERMAL
    pattern: "thermal.*shutdown|overheat"
    context_boost: 10
    rationale: "Thermal shutdown indicates overtemperature protection."
    domains: [thermal, pmic]
    evidence:
      - failure_class: THERMAL_SHUTDOWN
        weight: 0.8
        label: "thermal shutdown"
```

Fields:

- `name`: unique identifier
- `severity`: INFO, MEDIUM, HIGH, CRITICAL
- `category`: WATCHDOG, KERNEL, MEMORY, POWER, ANR, TOMBSTONE, THERMAL, STORAGE, SECURITY, FRAMEWORK
- `pattern`: case-insensitive regex
- `context_boost`: extra pre/post lines to capture
- `rationale`: human explanation for why the rule exists
- `domains`: typical root-cause domains (clock, ddr, pmic, storage, framework, scheduler)
- `evidence`: weighted mapping to failure classes

Evidence weights are combined deterministically to classify incidents.
