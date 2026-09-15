"""
Plugin registry — decorator-based self-registration + dependency resolution.

Modules call `@register` on a Plugin subclass to add themselves. The
pipeline then asks the registry for a dependency-ordered execution plan
instead of main.py hard-coding "run recon, then web, then cve, ...".
"""

from __future__ import annotations

from typing import Dict, List, Type

from core.plugin import Plugin


class PluginRegistry:
    def __init__(self) -> None:
        self._classes: Dict[str, Type[Plugin]] = {}

    def register(self, cls: Type[Plugin]) -> Type[Plugin]:
        if not cls.name:
            raise ValueError(f"Plugin {cls.__name__} must set a non-empty `name`")
        if cls.name in self._classes:
            raise ValueError(f"Duplicate plugin name: {cls.name!r}")
        self._classes[cls.name] = cls
        return cls

    def get(self, name: str) -> Type[Plugin]:
        return self._classes[name]

    def all(self) -> List[Type[Plugin]]:
        return list(self._classes.values())

    def names(self) -> List[str]:
        return list(self._classes.keys())

    def instantiate_all(self) -> List[Plugin]:
        return [cls() for cls in self._classes.values()]

    def resolve_order(self, plugins: List[Plugin]) -> List[List[Plugin]]:
        """
        Topologically sort `plugins` into ordered "waves": each wave is a
        list of plugins whose dependencies are all satisfied by earlier
        waves, so every plugin within a wave can run concurrently.

        Dependencies on a plugin that isn't in `plugins` (e.g. it was
        disabled for this run) are ignored rather than treated as an error,
        so turning a plugin off never breaks the rest of the graph.
        """
        by_name = {p.name: p for p in plugins}
        remaining = dict(by_name)
        done: set = set()
        waves: List[List[Plugin]] = []

        while remaining:
            wave = [
                p for p in remaining.values()
                if all(dep in done or dep not in by_name for dep in p.depends_on)
            ]
            if not wave:
                # Circular dependency among registered plugins — a bug in a
                # plugin's `depends_on`, not something a user can trigger.
                stuck = ", ".join(remaining.keys())
                raise RuntimeError(f"Circular or unresolvable plugin dependency among: {stuck}")
            for p in wave:
                del remaining[p.name]
                done.add(p.name)
            waves.append(wave)

        return waves


registry = PluginRegistry()


def register(cls: Type[Plugin]) -> Type[Plugin]:
    """Class decorator: @register on a Plugin subclass adds it to the global registry."""
    return registry.register(cls)
