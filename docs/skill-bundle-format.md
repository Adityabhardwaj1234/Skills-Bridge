# Whole-Directory Skill Bundle Format (`docs/skill-bundle-format.md`)

## 1. Directory Structure

A skill in SkillBridge v2 is a complete, versioned directory bundle (`src/skillbridge/bundles/manager.py`), preserving all supporting subdirectories expected by its instructions and scripts:

```text
my-skill/
  SKILL.md
  references/
  scripts/
  assets/
  examples/
  tests/
  config/
  templates/
  requirements.txt / pyproject.toml / package.json
```

## 2. Tier 0 Bundle Manifest (`BundleManifest`)

During Tier 0 intake (`BundleStager.stage_into_quarantine`), SkillBridge generates `.skillbridge_bundle_manifest.json` recording:
- `skill_id`, `name`, `version`, `source_provider`, `source_uri`, `source_subpath`, `resolved_revision`
- `bundle_digest`: Deterministic SHA-256 tree digest computed over sorted `(relative_path, file_sha256)` pairs across every regular file in the bundle.
- `files[]` (`BundleFileEntry`): `relative_path`, `sha256`, `size_bytes`, `classification` (`markdown`, `python`, `shell`, `javascript`, `typescript`, `config`, `manifest`, `asset`, `binary`, `archive`, `other`), `is_executable`, `is_hidden`, `is_referenced`, `line_count`, `encoding_valid`.
- `scripts[]` (`ScriptEntryPoint`): `relative_path`, `language`, `sha256`, `is_referenced_in_skill_md`, `declared_dependencies`, `local_imports`, `observed_capabilities`, `syntax_valid`, `syntax_error`.

## 3. Containment & Resource Bounds

- **Maximum Files (`bundle_max_files`)**: `500` files
- **Maximum Total Bundle Size (`bundle_max_total_bytes`)**: `15 MiB`
- **Maximum Single File Size (`bundle_max_single_file_bytes`)**: `2 MiB`
- **Maximum Directory Depth (`bundle_max_depth`)**: `8` levels
- **Symlink & Traversal Policy**: Any `..` path segment, symlink inside the bundle, non-regular file (FIFO/device), hidden executable script, hidden binary payload, or nested archive exceeding decompression bounds triggers a Tier 0 integrity violation (`tier0_passed = False`).
