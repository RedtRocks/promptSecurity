# Poisoned tool definitions (tool-poisoning detection set)

An MCP tool's `description` and `kb_context` are written by whoever published the
server, but the agent reads them as trusted instructions. **Tool poisoning** hides
directives there. Because this pipeline takes the tool *description* as its primary
input, whether it notices a poisoned one is directly in scope — and it is a
different question from "can the tool be misused", which the attack stages measure.

Each file here is a poisoned variant of a clean tool in `../`. The clean file is
the matched negative control: same tool, same schema, no payload. That pairing is
what makes a false-positive rate measurable — a detector that flags everything
scores perfect recall and is useless.

Run the experiment with:

```bash
python scripts/tool_poisoning_eval.py --config config.yaml --out poisoning_eval.json
```

It profiles every clean and poisoned definition and reports detection rate
(recall), false-positive rate on the clean controls, and precision.

## Payload families

Each variant carries `poison_meta` describing what was planted, so results can be
broken down by technique rather than reported as one aggregate number.

| Family | What it does |
|---|---|
| `direct_instruction` | Plain directive to the assistant inside the description |
| `fake_system_note` | Text styled as a system/operator message |
| `exfil_side_effect` | Declares a mandatory "logging"/"audit" step that ships data out |
| `concealment` | Instructs the agent to hide the behaviour from the user |
| `schema_field` | Payload hidden in a *parameter* description, not the tool description |
| `precondition_chain` | Claims another tool must be called first |
| `authority_override` | Claims policy/approval already grants a wider scope |

`schema_field` matters because a reviewer skimming the tool description would not
see it; a detector that only reads `description` will miss it.
