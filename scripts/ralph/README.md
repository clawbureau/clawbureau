# Ralph Integration

To use Ralph loops per domain:

1. Copy ralph.sh + prompt into this repo:

```bash
mkdir -p scripts/ralph
cp /path/to/ralph/ralph.sh scripts/ralph/
cp /path/to/ralph/CLAUDE.md scripts/ralph/
```

2. For each domain:
- Generate `prd.json` from the PRD in `docs/prds/<domain>.md`
- Store as `services/<domain>/prd.json`

3. Run Ralph:

```bash
cd services/<domain>
../../scripts/ralph/ralph.sh --tool claude 50
```

Parallelize by running multiple domains in different terminals.
