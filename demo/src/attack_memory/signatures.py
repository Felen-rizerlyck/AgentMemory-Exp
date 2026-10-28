"""Deterministic candidate signature features.

This is step 1 of candidate normalisation: extract CVE, product and discriminative
technique tokens, build a grouping key, and leave the candidate status untouched.
No fuzzy merge happens here.
"""
from __future__ import annotations

import hashlib
import re
from collections import OrderedDict

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

PRODUCTS = OrderedDict([
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

ACTIONS = OrderedDict([
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


def _matches(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for token, pattern in ACTIONS.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            found.append((match.start(), token))
    return sorted(found)


def _product_matches(text: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for token, pattern in PRODUCTS.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            found.append((match.start(), token))
    return sorted(found)


def extract_features(label: str, contents: list[str], sources: list[str],
                     family_id: str) -> dict:
    label_text = label or ""
    content_text = "\n".join(contents)
    combined = label_text + "\n" + content_text
    cves = sorted({match.upper() for match in CVE_RE.findall(combined)})
    products = sorted({token for _, token in _product_matches(combined)})
    label_actions = _matches(label_text)
    content_actions = _matches(content_text)
    all_actions = sorted({token for _, token in label_actions + content_actions})
    label_products = _product_matches(label_text)
    content_products = _product_matches(content_text)
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
        key = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
    else:
        normalized = re.sub(r"\s+", " ", combined.strip().lower())[:500]
        key = hashlib.sha1((family_id + "|fallback|" + normalized).encode("utf-8")).hexdigest()[:16]
    return {
        "signature_key": key,
        "signature_terms": cves + products + all_actions,
        "cves": cves,
        "products": products,
        "actions": all_actions,
        "primary_product": primary_product,
        "primary_action": primary,
        "sources": sorted({source for source in sources if source}),
        "label_used": bool(label_text.strip()),
    }


def group_candidates(candidates: list[dict]) -> list[dict]:
    groups: dict[str, dict] = {}
    for candidate in candidates:
        key = candidate.get("signature_key") or candidate.get("signature") or candidate["candidate_id"]
        group = groups.setdefault(key, {"signature_key": key, "terms": [], "candidates": []})
        for term in candidate.get("signature_terms") or []:
            if term not in group["terms"]:
                group["terms"].append(term)
        group["candidates"].append(candidate)
    return sorted(groups.values(), key=lambda group: (-len(group["candidates"]), group["signature_key"]))
