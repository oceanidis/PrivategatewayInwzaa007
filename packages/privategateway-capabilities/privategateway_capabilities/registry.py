from __future__ import annotations

from .contracts import Capability, CapabilitySpec


class CapabilityRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, CapabilitySpec] = {}

    @classmethod
    def strict(cls) -> "CapabilityRegistry":
        return cls()

    def register_gateway_tool(self, name: str, capability: Capability, *, resource_fields: tuple[str, ...]) -> None:
        if capability not in {Capability.DIRECTORY_BROWSE, Capability.METADATA_INSPECT, Capability.SAFE_TABLE_READ, Capability.SAFE_TEXT_READ, Capability.SAFE_COPY_CREATE, Capability.SAFE_EXPORT}:
            raise ValueError("INVALID_GATEWAY_CAPABILITY")
        self._register(name, CapabilitySpec(capability, tuple(resource_fields)))

    def register_execution_tool(self, name: str, *, sandboxed: bool) -> None:
        self._register(name, CapabilitySpec(Capability.SANDBOXED_EXECUTION, sandboxed=sandboxed))

    def get(self, name: str) -> CapabilitySpec | None:
        return self._specs.get(name)

    def names(self) -> frozenset[str]:
        return frozenset(self._specs)

    def _register(self, name: str, spec: CapabilitySpec) -> None:
        if not isinstance(name, str) or not name or name in self._specs:
            raise ValueError("DUPLICATE_OR_INVALID_TOOL")
        self._specs[name] = spec
