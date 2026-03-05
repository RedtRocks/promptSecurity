"""Stage 3.5 — Least Privilege Deployment Specification.

Maps capability annotations to concrete container-level enforcement directives
and recommends an MCP server isolation level.
"""

from __future__ import annotations

from agent_hardener.shared.schemas import (
    CapabilityAnnotations,
    ContainerEnforcement,
    DeploymentSpec,
)

# Maps capability name → (Docker/container mechanism, directive template)
_CAP_ENFORCEMENT_TEMPLATES: dict[str, tuple[str, str]] = {
    "network": (
        "Docker network namespace",
        "--network=none  # or: --network=<custom-bridge> with strict iptables rules",
    ),
    "filesystem": (
        "Docker volume mount + seccomp",
        "--read-only --tmpfs /tmp:size=64m  # mount only required paths: -v <allowed_path>:<allowed_path>:ro",
    ),
    "environment": (
        "Docker --env whitelist",
        "Pass only allowed env vars via --env <VAR>=<value>. Do not use --env-file with a broad .env file.",
    ),
    "execution": (
        "seccomp profile + AppArmor",
        "Apply a custom seccomp profile that blocks execve() for all binaries except the whitelist. "
        "Use AppArmor deny rules for all other executables.",
    ),
    "software_libraries": (
        "Minimal container image",
        "Use a FROM scratch or distroless base image with only required wheels installed. "
        "Run pip install --no-deps to prevent transitive dependency expansion.",
    ),
}

_ISOLATION_LEVELS = {
    "air_gapped": (
        "air_gapped_container",
        "No external network. Strongly recommended when network=false and write_confidentiality=high.",
    ),
    "separate": (
        "separate_container",
        "Isolated network namespace. Recommended for tools with restricted network access.",
    ),
    "shared": (
        "shared_host",
        "Minimal isolation. Only appropriate when all capabilities are false or strictly scoped "
        "and no private data is accessed.",
    ),
}


def build_deployment_spec(capabilities: CapabilityAnnotations) -> DeploymentSpec:
    """Generate container-level enforcement directives from capability annotations.

    Args:
        capabilities: Stage 3.1 CapabilityAnnotations.

    Returns:
        A DeploymentSpec with per-capability directives and an isolation level recommendation.
    """
    enforcements: list[ContainerEnforcement] = []

    cap_map: dict[str, object] = {
        "network": capabilities.network,
        "filesystem": capabilities.filesystem,
        "environment": capabilities.environment,
        "execution": capabilities.execution,
        "software_libraries": capabilities.software_libraries,
    }

    for cap_name, cap_value in cap_map.items():
        mechanism, directive_template = _CAP_ENFORCEMENT_TEMPLATES[cap_name]

        if cap_value is False:
            # Capability is completely disabled
            enforcements.append(
                ContainerEnforcement(
                    capability=cap_name,
                    mechanism=mechanism,
                    directive=f"[DISABLED] {directive_template}",
                )
            )
        elif isinstance(cap_value, list) and cap_value:
            # Capability is restricted to a specific scope
            scope = ", ".join(str(v) for v in cap_value)
            enforcements.append(
                ContainerEnforcement(
                    capability=cap_name,
                    mechanism=mechanism,
                    directive=f"[RESTRICTED to: {scope}] {directive_template}",
                )
            )
        # If cap_value is an empty list or True, no restriction needed (don't add directive)

    isolation_level = _recommend_isolation(capabilities)

    return DeploymentSpec(
        isolation_level=isolation_level,
        container_enforcements=enforcements,
    )


def _recommend_isolation(capabilities: CapabilityAnnotations) -> str:
    """Choose an isolation level based on capability annotations.

    Decision logic:
      - network=False → air_gapped_container (no external network interface)
      - network=list (restricted) → separate_container (isolated but with limited egress)
      - network=True (unrestricted, not blocked) → separate_container minimum
    """
    if capabilities.network is False:
        return _ISOLATION_LEVELS["air_gapped"][0]
    elif isinstance(capabilities.network, list):
        return _ISOLATION_LEVELS["separate"][0]
    else:
        # Network unrestricted — still prefer a separate container
        return _ISOLATION_LEVELS["separate"][0]
