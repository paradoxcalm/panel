"""Рендер пользовательских шаблонов с поддержкой Jinja2 и спинтакса."""
from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

from jinja2 import Environment, StrictUndefined

from models import Link, Template

_SPIN_PATTERN = re.compile(r"\{([^{}]+)\}")


@dataclass
class RenderResult:
    text: str
    context: Dict[str, Any]


def _apply_spintax(value: str) -> str:
    """Раскрыть конструкции вида ``{a|b|c}``.

    Функция выполняет многократную замену, пока не останется вариантов.
    """

    if "{" not in value:
        return value

    def _replace_once(match: re.Match[str]) -> str:
        options = [opt.strip() for opt in match.group(1).split("|") if opt.strip()]
        if not options:
            return ""
        return random.choice(options)

    previous = None
    current = value
    while previous != current:
        previous = current
        current = _SPIN_PATTERN.sub(_replace_once, current)
    return current


class LinkAccessor:
    """Предоставляет доступ к активным ссылкам через атрибуты."""

    def __init__(self, links: Mapping[str, Mapping[str, Any]]):
        self._links = links

    def __getattr__(self, name: str) -> str:
        data = self._links.get(name)
        if not data:
            return ""
        if not data.get("url"):
            return ""
        utm = data.get("utm") or {}
        url = data["url"]
        if utm:
            separator = "&" if "?" in url else "?"
            kv = "&".join(
                f"{key}={value}" for key, value in utm.items() if key and value
            )
            if kv:
                return f"{url}{separator}{kv}"
        return url

    def __contains__(self, name: str) -> bool:  # pragma: no cover - поддержка in
        data = self._links.get(name)
        return bool(data and data.get("url"))


class TemplateRenderer:
    def __init__(self):
        self.env = Environment(autoescape=False, undefined=StrictUndefined, trim_blocks=True)

    @staticmethod
    def _utm_helper(name: str, link_accessor: Optional[LinkAccessor] = None) -> str:
        if not name:
            return ""
        data = link_accessor._links.get(name) if link_accessor else None  # type: ignore[attr-defined]
        if data:
            utm = data.get("utm") or {}
            if utm:
                return "&".join(
                    f"{key}={value}" for key, value in utm.items() if key and value
                )
        return ""

    def build_context(
        self,
        template: Template,
        *,
        context: Optional[Mapping[str, Any]] = None,
        links: Optional[Iterable[Link]] = None,
    ) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {}
        ctx.update(template.default_context or {})
        if context:
            ctx.update(context)
        link_map: Dict[str, Dict[str, Any]] = {}
        for link in links or []:
            if not link.is_active:
                continue
            link_map[link.slug] = {
                "url": link.url,
                "utm": link.utm_params or {},
            }
        for key, override in (template.utm_sets or {}).items():
            if not isinstance(override, Mapping):
                continue
            entry = link_map.setdefault(key, {"url": "", "utm": {}})
            utm = dict(entry.get("utm") or {})
            for k, v in override.items():
                if not k or v is None:
                    continue
                utm[k] = str(v)
            entry["utm"] = utm
        accessor = LinkAccessor(link_map)
        ctx.setdefault("links", accessor)
        if "utm" not in ctx:
            ctx["utm"] = lambda name, _accessor=accessor: self._utm_helper(name, _accessor)
        return ctx

    def render(
        self,
        template: Template,
        *,
        context: Optional[Mapping[str, Any]] = None,
        links: Optional[Iterable[Link]] = None,
        apply_spintax: bool = True,
    ) -> RenderResult:
        ctx = self.build_context(template, context=context, links=links)
        jinja_template = self.env.from_string(template.body)
        rendered = jinja_template.render(ctx)
        if apply_spintax:
            rendered = _apply_spintax(rendered)
        return RenderResult(text=rendered.strip(), context=ctx)


def parse_context(raw: str) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:  # pragma: no cover - пользовательский ввод
        raise ValueError(f"Некорректный JSON контекста: {exc}") from exc
    if not isinstance(data, MutableMapping):
        raise ValueError("Контекст должен быть JSON-объектом")
    return dict(data)
