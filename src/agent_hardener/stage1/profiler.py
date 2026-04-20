"""Stage 1.1 — Tool Profiling.

Parses the MCPToolDefinition and extracts:
- Data sources and destinations (classified as public/private)
- External capabilities the tool uses
- Semantic domain
- Potential description ambiguities

Uses the LLM to perform the semantic analysis.
"""

from __future__ import annotations

import json
import textwrap

from agent_hardener.shared.llm_provider import LLMProvider
from agent_hardener.shared.schemas import (
    CapabilityProfile,
    DataClassification,
    DataEndpoint,
    MCPToolDefinition,
    ToolProfile,
)

_PROFILE_SYSTEM = textwrap.dedent("""\
You are a security analyst specializing in AI agent tool deployments.
Your task is to analyze a tool definition and produce a structured security profile.
Respond ONLY with a valid JSON object matching the schema specified. No prose, no markdown fences.
""")

_PROFILE_USER_TMPL = textwrap.dedent("""\
Analyze the following tool definition and extract a security profile.

TOOL DEFINITION:
Name: {name}
Description: {description}
Parameters:
{params}
Knowledge Base Context:
{kb_context}

Produce a JSON object with this exact structure:
{{
  "data_sources": [
    {{"name": "<source name>", "classification": "public" | "private", "description": "<brief>"}}
  ],
  "data_destinations": [
    {{"name": "<dest name>", "classification": "public" | "private", "description": "<brief>"}}
  ],
  "capabilities": {{
    "network": true | false,
    "filesystem": true | false,
    "environment": true | false,
    "execution": true | false,
    "software_libraries": ["<lib1>", "<lib2>"]
  }},
  "semantic_domain": "<e.g., file management | communication | financial | code execution | web browsing | identity management>",
  "description_ambiguities": [
    "<exact phrase from tool description that is vague enough to be exploited>"
  ]
}}

Rules:
- Classify a data source as "private" if it involves user-specific data, authentication,
  session state, personal information, internal APIs, or any data not freely public.
- Classify a data destination as "private" if writing to it could expose data externally,
  post publicly, or affect state outside the current session.
- List ONLY ambiguities that could realistically be exploited by an adversarial user.
- software_libraries: list actual library names implied by the tool (e.g., subprocess, requests).
""")


def profile_tool(tool: MCPToolDefinition, llm: LLMProvider) -> ToolProfile:
    """Parse the tool definition and produce a ToolProfile.

    Args:
        tool: The validated MCPToolDefinition.
        llm: Initialized LLMProvider.

    Returns:
        A populated ToolProfile ready for Stage 1.2.
    """
    # Get model-optimized parameters
    profile_temp, profile_tokens = llm.get_profile_params()
    enhanced_system = llm.enhance_system_prompt(_PROFILE_SYSTEM)
    
    params_text = _format_parameters(tool)
    user_msg = _PROFILE_USER_TMPL.format(
        name=tool.name,
        description=tool.description,
        params=params_text,
        kb_context=tool.kb_context or "(none)",
    )

    raw = llm.chat_json(
        messages=[
            {"role": "system", "content": enhanced_system},
            {"role": "user", "content": user_msg},
        ],
        temperature=profile_temp,
        max_tokens=profile_tokens,
    )

    data = _try_parse_json_object(raw)
    if data is None:
        retry_user_msg = (
            user_msg
            + "\n\nIMPORTANT: Return STRICT JSON only. No markdown fences. "
            + "Populate every top-level key exactly as requested."
        )
        retry_raw = llm.chat(
            messages=[
                {"role": "system", "content": enhanced_system},
                {"role": "user", "content": retry_user_msg},
            ],
            temperature=0.05,  # Even more deterministic for retry
            max_tokens=int(profile_tokens * 0.9),
        )
        data = _try_parse_json_object(retry_raw)

    if data is None:
        return _fallback_profile(tool)

    return _build_profile(tool.name, data)


def _format_parameters(tool: MCPToolDefinition) -> str:
    if not tool.parameters:
        return "  (no parameters)"
    lines = []
    for p in tool.parameters:
        req = " [required]" if p.required else " [optional]"
        enum_hint = f" enum={p.enum}" if p.enum else ""
        lines.append(f"  - {p.name} ({p.type}{enum_hint}){req}: {p.description}")
    return "\n".join(lines)


def _try_parse_json_object(raw: str) -> dict | None:
    text = (raw or "").strip()
    if not text:
        return None

    if text.startswith("```"):
        lines = text.splitlines()
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    snippet = text[start : end + 1]
    try:
        obj = json.loads(snippet)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _fallback_profile(tool: MCPToolDefinition) -> ToolProfile:
    """Deterministic fallback when profiler LLM output is malformed."""
    desc = (tool.description or "").lower()
    names = [p.name.lower() for p in tool.parameters]

    filesystem = any(
        k in desc for k in ["file", "filesystem", "path", "directory"]
    ) or any("path" in n or "file" in n or "dir" in n for n in names)
    network = any(k in desc for k in ["http", "url", "web", "network", "api"])
    environment = any(k in desc for k in ["env", "environment variable"])
    execution = any(k in desc for k in ["execute", "command", "shell", "subprocess"])

    semantic_domain = "file management" if filesystem else "general tooling"
    ambiguities = [tool.description] if tool.description else []

    data_sources: list[DataEndpoint] = []
    data_destinations: list[DataEndpoint] = []
    if filesystem:
        data_sources.append(
            DataEndpoint(
                name="filesystem",
                classification=DataClassification.PRIVATE,
                description="Local file access inferred from tool description/parameters.",
            )
        )

    return ToolProfile(
        tool_name=tool.name,
        data_sources=data_sources,
        data_destinations=data_destinations,
        capabilities=CapabilityProfile(
            network=network,
            filesystem=filesystem,
            environment=environment,
            execution=execution,
            software_libraries=[],
        ),
        semantic_domain=semantic_domain,
        description_ambiguities=ambiguities,
    )


def _build_profile(tool_name: str, data: dict) -> ToolProfile:
    sources = [
        DataEndpoint(
            name=s["name"],
            classification=DataClassification(s.get("classification", "public")),
            description=s.get("description", ""),
        )
        for s in data.get("data_sources", [])
    ]
    destinations = [
        DataEndpoint(
            name=d["name"],
            classification=DataClassification(d.get("classification", "public")),
            description=d.get("description", ""),
        )
        for d in data.get("data_destinations", [])
    ]
    cap_raw = data.get("capabilities", {})
    capabilities = CapabilityProfile(
        network=bool(cap_raw.get("network", False)),
        filesystem=bool(cap_raw.get("filesystem", False)),
        environment=bool(cap_raw.get("environment", False)),
        execution=bool(cap_raw.get("execution", False)),
        software_libraries=cap_raw.get("software_libraries", []),
    )

    return ToolProfile(
        tool_name=tool_name,
        data_sources=sources,
        data_destinations=destinations,
        capabilities=capabilities,
        semantic_domain=data.get("semantic_domain", ""),
        description_ambiguities=data.get("description_ambiguities", []),
    )
