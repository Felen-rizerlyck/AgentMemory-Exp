"""Deterministic candidate signature features and grouping.

This is step 1 of candidate normalisation: extract CVE, product and discriminative
technique tokens, build a grouping key, and say *how* that key was derived. No fuzzy
merge happens here and no candidate status is touched.

Grouping rule (backlog P1-2, "未归组"):

* candidates with discriminative terms group by their deterministic ``signature_key``;
* candidates without terms are **not** hashed into one singleton group each. They go
  into a single explicit ``ungrouped`` bucket, because an uninterpretable hash is not
  evidence of a shared technique. Merging such candidates is a reviewed action
  (``allow_ungrouped=True`` in :mod:`attack_memory.candidates`), not an automatic one.

The product/action vocabulary can be extended without code changes through
``data/signature_lexicon.json``. Any load failure falls back to the built-in tables so
the demo always runs.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from pathlib import Path

from . import storage

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
LEXICON_PATH = storage.DATA_DIR / "signature_lexicon.json"
UNGROUPED_KEY = "ungrouped"
SIGNATURE_SOURCES = ("terms", "fallback")

BUILTIN_PRODUCTS = OrderedDict([
    ("spring", r"\bspring(?:4shell)?\b"),
    ("spring-cloud-gateway", r"spring\s+cloud\s+gateway"),
    ("tomcat", r"\btomcat\b"),
    ("gitlab", r"\bgitlab\b"),
    ("confluence", r"\bconfluence\b"),
    ("ofbiz", r"\bofbiz\b"),
    ("node", r"\bnode(?:\.js)?\b"),
    ("jenkins", r"\bjenkins\b"),
    ("weblogic", r"\bweblogic\b"),
    ("struts", r"\bstruts2?\b"),
    ("fastjson", r"\bfastjson\b"),
    ("solr", r"\bsolr\b"),
    ("php", r"\bphp(?:-fpm)?\b"),
    ("django", r"\bdjango\b"),
    ("rails", r"\brails\b"),
    ("exchange", r"\bexchange\b"),
    ("sharepoint", r"\bsharepoint\b"),
    ("log4j", r"\blog4j|log4shell\b"),
    ("shiro", r"\bshiro\b"),
    ("nacos", r"\bnacos\b"),
    ("grafana", r"\bgrafana\b"),
    ("metabase", r"\bmetabase\b"),
    ("airflow", r"\bairflow\b"),
    ("druid", r"\bdruid\b"),
    ("webmin", r"\bwebmin\b"),
    ("apisix", r"\bapisix\b"),
    ("dubbo", r"\bdubbo\b"),
    ("h2", r"\bh2\b"),
    ("axis2", r"\baxis2\b"),
    ("jboss", r"\bjboss\b"),
    ("zabbix", r"\bzabbix\b"),
    ("phpmyadmin", r"\bphpmyadmin\b"),
    ("symfony", r"\bsymfony\b"),
    ("drupal", r"\bdrupal\b"),
])

BUILTIN_ACTIONS = OrderedDict([
    ("spring4shell", r"spring4shell|class\.module\.classloader|classloader\.first|pipeline\.first"),
    ("actuator", r"/actuator|actuator"),
    ("gateway", r"\bgateway\b"),
    ("spel", r"\bspel\b"),
    ("ognl", r"\bognl\b"),
    ("jndi", r"\bjndi\b"),
    ("ldap", r"\bldap\b"),
    ("log4shell", r"log4shell|jndi:ldap"),
    ("xmlrpc", r"xml-rpc|xmlrpc"),
    ("groovy", r"\bgroovy\b"),
    ("exiftool", r"\bexiftool\b"),
    ("djvu", r"\bdjvu\b"),
    ("vm-escape", r"\bvm2?\b|process\.binding|spawn_sync|sandbox"),
    ("postinstall", r"\bpostinstall\b"),
    ("ci-token", r"ci_job_token|\.git-credentials|id_rsa"),
    ("vssadmin", r"\bvssadmin\b"),
    ("cipher", r"\bcipher\b"),
    ("bcdedit", r"\bbcdedit\b"),
    ("dcsync", r"\bdcsync\b|secretsdump"),
    ("kerberoast", r"kerberoast"),
    ("asrep", r"as-rep|getnpusers"),
    ("ntds", r"\bntdsutil\b|ntds\.dit"),
    ("schtasks", r"\bschtasks\b"),
    ("webshell", r"webshell|\.jsp\b|\.aspx\b"),
    ("jmx", r"jmx-console|wls-wsat|htmladaptor"),
    ("mlet", r"\bmlet\b"),
    ("aar", r"\.aar\b"),
    ("heapdump", r"\bheapdump\b"),
    ("nacos", r"\bnacos\b"),
    ("h2-console", r"h2-console|runscript"),
    ("phar", r"phar://"),
    ("ignition", r"ignition|execute-solution"),
    ("struts2", r"s2-0\d+|struts2"),
    ("t3", r"\bt3\b|java-serialized-object"),
    ("dns", r"\bdns\b"),
    ("sql-injection", r"sql\s*注入|union\s+select|xp_dirtree|copy\s+to\s+program"),
    ("xxe", r"\bxxe\b|xml\s+external"),
])

# Backwards-compatible aliases for callers that imported the baseline tables directly.
PRODUCTS = BUILTIN_PRODUCTS
ACTIONS = BUILTIN_ACTIONS


def builtin_lexicon() -> dict:
    return {"schema_version": 1, "products": OrderedDict(BUILTIN_PRODUCTS),
            "actions": OrderedDict(BUILTIN_ACTIONS), "source": "builtin"}


def _compiled_table(name: str, table: object) -> OrderedDict[str, str]:
    if not isinstance(table, dict) or not table:
        raise ValueError(f"lexicon '{name}' must be a non-empty object")
    compiled: OrderedDict[str, str] = OrderedDict()
    for token, pattern in table.items():
        if not isinstance(token, str) or not token.strip():
            raise ValueError(f"lexicon '{name}' contains an empty token")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError(f"lexicon '{name}/{token}': pattern must be a non-empty string")
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"lexicon '{name}/{token}': invalid regex ({error})") from error
        compiled[token.strip()] = pattern
    return compiled


def load_lexicon(path: Path | str | None = None) -> dict:
    """Load the external vocabulary; any failure falls back to the built-in tables."""
    target = Path(path) if path is not None else LEXICON_PATH
    try:
        data = storage.load_json(target, None)
        if data is None:
            raise ValueError(f"{target}: lexicon file is missing")
        if not isinstance(data, dict):
            raise ValueError(f"{target}: lexicon must be a JSON object")
        version = data.get("schema_version", 1)
        if version != 1:
            raise ValueError(f"{target}: unsupported schema_version {version!r}")
        products = _compiled_table("products", data.get("products"))
        actions = _compiled_table("actions", data.get("actions"))
    except (ValueError, json.JSONDecodeError, OSError) as error:
        lexicon = builtin_lexicon()
        lexicon["fallback_reason"] = str(error)
        return lexicon
    return {"schema_version": version, "products": products, "actions": actions,
            "source": "file"}


def _matches(text: str, actions: OrderedDict[str, str] | None = None) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for token, pattern in (actions if actions is not None else ACTIONS).items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            found.append((match.start(), token))
    return sorted(found)


def _product_matches(text: str,
                     products: OrderedDict[str, str] | None = None) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for token, pattern in (products if products is not None else PRODUCTS).items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            found.append((match.start(), token))
    return sorted(found)


def extract_features(label: str, contents: list[str], sources: list[str],
                     family_id: str) -> dict:
    """Extract deterministic features plus the provenance of the grouping decision."""
    lexicon = load_lexicon()
    products_table = lexicon["products"]
    actions_table = lexicon["actions"]
    label_text = label or ""
    content_text = "\n".join(contents)
    combined = label_text + "\n" + content_text
    cves = sorted({match.upper() for match in CVE_RE.findall(combined)})
    products = sorted({token for _, token in _product_matches(combined, products_table)})
    label_actions = _matches(label_text, actions_table)
    content_actions = _matches(content_text, actions_table)
    all_actions = sorted({token for _, token in label_actions + content_actions})
    label_products = _product_matches(label_text, products_table)
    content_products = _product_matches(content_text, products_table)
    primary_product = (label_products[0][1] if label_products
                       else (content_products[0][1] if content_products else ""))
    primary = label_actions[0][1] if label_actions else (content_actions[0][1] if content_actions else "")
    if cves:
        key_terms = cves + ([primary_product] if primary_product else []) + ([primary] if primary else [])
    elif primary_product and primary:
        key_terms = [primary_product, primary]
    else:
        key_terms = []
    if key_terms:
        raw = family_id + "|" + "|".join(key_terms)
        key: str | None = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
        signature_source = "terms"
    else:
        # No discriminator: do not pretend a content hash is a technique signature.
        key = None
        signature_source = "fallback"
    return {
        "signature_key": key,
        "signature_source": signature_source,
        "signature_terms": cves + products + all_actions,
        "cves": cves,
        "products": products,
        "actions": all_actions,
        "primary_product": primary_product,
        "primary_action": primary,
        "sources": sorted({source for source in sources if source}),
        "label_used": bool(label_text.strip()),
        "lexicon_source": lexicon["source"],
    }


def is_ungrouped(candidate: dict) -> bool:
    """True when the candidate has no explainable signature, so it must not auto-group."""
    if (candidate.get("signature_source") or "").strip() == "fallback":
        return True
    terms = [term for term in candidate.get("signature_terms") or [] if term]
    if terms:
        return False
    # Legacy records were hashed even without terms; their stored key is a content hash,
    # not a technique signature, so they belong to the reviewed ungrouped bucket too.
    return True


def candidate_group_key(candidate: dict) -> str | None:
    """Return the group key, or ``None`` for the ungrouped bucket."""
    if is_ungrouped(candidate):
        return None
    key = candidate.get("signature_key")
    if isinstance(key, str) and key.strip():
        return key.strip()
    # Missing key but usable terms: keep the old per-signature behaviour instead of
    # silently guessing an equivalence class.
    legacy = (candidate.get("signature") or candidate.get("candidate_id") or "").strip()
    return legacy or None


def group_candidates(candidates: list[dict]) -> list[dict]:
    """Group by signature; every ungrouped candidate lands in one visible bucket."""
    groups: dict[str, dict] = {}
    ungrouped: list[dict] = []
    for candidate in candidates:
        key = candidate_group_key(candidate)
        if key is None:
            ungrouped.append(candidate)
            continue
        group = groups.setdefault(key, {"signature_key": key, "signature_source": "terms",
                                        "ungrouped": False, "terms": [], "candidates": []})
        for term in candidate.get("signature_terms") or []:
            if term and term not in group["terms"]:
                group["terms"].append(term)
        group["candidates"].append(candidate)
    result = sorted(groups.values(),
                    key=lambda group: (-len(group["candidates"]), group["signature_key"]))
    if ungrouped:
        result.append({"signature_key": UNGROUPED_KEY, "signature_source": "fallback",
                       "ungrouped": True, "terms": [], "candidates": ungrouped})
    return result
