"""Lectura de resultados XML de nmap (-oX/-oA). Lo usan Escaneo de red, SMB y Web."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Port:
    port: int
    proto: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.port}/{'ssl/' if self.tunnel == 'ssl' else ''}{self.service or '?'}"

    @property
    def is_web(self) -> bool:
        return "http" in self.service or self.port in (80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000, 5001)

    @property
    def is_tls(self) -> bool:
        return self.tunnel == "ssl" or self.service in ("https", "ssl", "https-alt") or self.port in (443, 8443, 636, 5001)


@dataclass
class Host:
    ip: str
    name: str = ""
    mac_vendor: str = ""
    os: str = ""
    up: bool = True
    ports: list[Port] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)

    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    def vulnerable(self) -> list[tuple[str, str]]:
        """(script, título) de los hallazgos marcados VULNERABLE por NSE (sin Slowloris)."""
        out = []
        for p in self.ports:
            for sid, text in p.scripts.items():
                if "State: VULNERABLE" in text and "slowloris" not in sid:
                    title = next((l.strip() for l in text.splitlines() if l.strip() and "VULNERABLE" not in l), sid)
                    out.append((f"{p.port}/{sid}", title))
        for sid, text in self.scripts.items():
            if "State: VULNERABLE" in text:
                out.append((sid, sid))
        return out

    def max_cvss(self) -> float:
        best = 0.0
        for p in self.ports:
            for m in re.finditer(r"\s(\d{1,2}\.\d)\s+https?://vulners", p.scripts.get("vulners", "")):
                best = max(best, float(m.group(1)))
        return best


@dataclass
class Scan:
    path: Path
    args: str = ""
    start: str = ""
    hosts: list[Host] = field(default_factory=list)

    def up(self) -> list[Host]:
        return [h for h in self.hosts if h.up]

    def host(self, ip: str) -> Optional[Host]:
        return next((h for h in self.hosts if h.ip == ip), None)


def parse(path: Path) -> Scan:
    scan = Scan(path)
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return scan
    scan.args = root.get("args", "")
    scan.start = root.get("startstr", "")
    for h in root.findall("host"):
        st = h.find("status")
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "")
        mac = next((a for a in h.findall("address") if a.get("addrtype") == "mac"), None)
        names = [n.get("name", "") for n in h.findall("hostnames/hostname")]
        osm = h.find("os/osmatch")
        host = Host(ip=ip, name=names[0] if names else "", mac_vendor=mac.get("vendor", "") if mac is not None else "",
                    os=osm.get("name", "") if osm is not None else "", up=st is None or st.get("state") == "up")
        for p in h.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            portid = p.get("portid", "")
            if not portid.isdigit():
                continue
            port = Port(int(portid), p.get("protocol", "tcp"), state.get("state", "") if state is not None else "",
                        svc.get("name", "") if svc is not None else "", svc.get("product", "") if svc is not None else "",
                        svc.get("version", "") if svc is not None else "", svc.get("tunnel", "") if svc is not None else "")
            for s in p.findall("script"):
                port.scripts[s.get("id", "")] = s.get("output", "")
            host.ports.append(port)
        for s in h.findall("hostscript/script"):
            host.scripts[s.get("id", "")] = s.get("output", "")
        scan.hosts.append(host)
    return scan


def diff(old: Scan, new: Scan) -> dict:
    """Qué ha cambiado entre dos escaneos del mismo objetivo."""
    o_up = {h.ip for h in old.up()}
    n_up = {h.ip for h in new.up()}
    changes = {"hosts_nuevos": sorted(n_up - o_up), "hosts_desaparecidos": sorted(o_up - n_up),
               "puertos_abiertos": [], "puertos_cerrados": [], "versiones": []}
    for ip in sorted(o_up & n_up):
        oh, nh = old.host(ip), new.host(ip)
        op = {(p.port, p.proto): p for p in oh.open_ports()}
        np_ = {(p.port, p.proto): p for p in nh.open_ports()}
        for k in sorted(np_.keys() - op.keys()):
            changes["puertos_abiertos"].append((ip, np_[k].label))
        for k in sorted(op.keys() - np_.keys()):
            changes["puertos_cerrados"].append((ip, op[k].label))
        for k in sorted(op.keys() & np_.keys()):
            a, b = f"{op[k].product} {op[k].version}".strip(), f"{np_[k].product} {np_[k].version}".strip()
            if a and b and a != b:
                changes["versiones"].append((ip, np_[k].label, a, b))
    return changes
