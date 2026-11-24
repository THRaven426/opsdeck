"""Lectura de XML ajeno (nmap, Nessus, OpenVAS, sslscan...) sin entidades ni referencias externas.

Los informes pueden venir de terceros y se leen como root: defusedxml rechaza entidades (billion
laughs) y DTD o entidades externas (XXE). Para el resto se usa la API de ElementTree."""

from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as _safe

ERRORS = (ParseError, DefusedXmlException)


def fromstring(text: str | bytes) -> Element:
    return _safe.fromstring(text)


def parse_file(path) -> Element:
    return _safe.parse(str(path)).getroot()
