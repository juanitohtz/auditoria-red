#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auditoria_red.py v3 - Auditoria de red EXTERNA (caja negra) de laboratorio.

Plataforma: Kali Linux. La maquina Kali es solo la plataforma; el SUJETO de la
auditoria son los equipos OBJETIVO de la red de laboratorio (propios y
autorizados). NO se realiza explotacion: solo descubrimiento, enumeracion,
versiones, CVEs y configuracion observable desde la red.

Dependencias del sistema (apt, sin pip ni venv):
    sudo apt install nmap python3-weasyprint python3-docx wkhtmltopdf
El script detecta lo que falte y degrada con elegancia.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

VERSION = "4.0"

# Servicios considerados "sin cifrar" (texto claro) cuando estan expuestos.
CLEARTEXT_SERVICES = {
    "telnet": 23, "ftp": 21, "http": 80, "rlogin": 513, "rsh": 514,
    "rexec": 512, "pop3": 110, "imap": 143, "smtp": 25, "snmp": 161,
    "tftp": 69, "microsoft-ds": 445, "netbios-ssn": 139, "vnc": 5900,
}
# Servicios que suelen cifrar por STARTTLS (cifrado oportunista, no garantizado).
STARTTLS_SERVICES = {"ftp", "smtp", "imap", "pop3"}
WEB_PORTS = {80, 443, 8080, 8000, 8443}
WEB_SCRIPTS = "http-headers,http-methods,http-enum,http-title,http-security-headers"
BASE_SCRIPTS = "ssl-enum-ciphers,ftp-anon"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
]
HEADER_SCRIPTS = ("http-headers", "http-security-headers")

# ssl-enum-ciphers: criterios de configuracion TLS debil.
TLS_PROTOCOLS_HIGH = ("SSLv2", "SSLv3")          # -> Alta
TLS_PROTOCOLS_LEGACY = ("TLSv1.0", "TLSv1.1")    # -> Media
WEAK_CIPHER_TOKENS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON"}
WEAK_GRADES = {"C", "D", "E", "F"}

# Orden de estados de un check al deduplicar (gana el mayor).
CHECK_STATUS_RANK = {"Hallazgo": 3, "Informativo": 2, "Correcto": 1,
                     "No verificado": 0, "No aplica": 0}


# --------------------------------------------------------------------------- #
# Modelo de datos
# --------------------------------------------------------------------------- #
@dataclass
class Port:
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""          # "ssl" si nmap detecto TLS implicito (p.ej. 443)
    tls: bool = False         # True si ssl-enum-ciphers obtuvo datos TLS en el puerto

    @property
    def banner(self) -> str:
        parts = [self.product, self.version, self.extrainfo]
        return " ".join(p for p in parts if p).strip()

    @property
    def has_tls(self) -> bool:
        return self.tunnel == "ssl" or self.tls

    @property
    def encryption(self) -> str:
        """Clasificacion de cifrado observable (corrige HTTPS mal marcado)."""
        svc = self.service.lower()
        if self.has_tls:
            if svc in STARTTLS_SERVICES and self.tunnel != "ssl":
                return "Parcial (STARTTLS)"
            return "Cifrado (TLS)"
        if svc in CLEARTEXT_SERVICES:
            return "Sin cifrar"
        return "No aplica"

    @property
    def is_cleartext(self) -> bool:
        # Solo texto claro real: servicio sin cifrar Y sin TLS observado en el puerto.
        return self.service.lower() in CLEARTEXT_SERVICES and not self.has_tls


@dataclass
class Check:
    name: str
    status: str            # Correcto | Hallazgo | No verificado | No aplica | Informativo
    detail: str = ""


@dataclass
class Finding:
    fid: str
    component: str
    title: str
    cve: str = ""
    cvss: float = 0.0
    severity: str = "Informativa"
    description: str = ""
    evidence: str = ""
    status: str = "Confirmado"
    recommendation: str = ""
    kind: str = "config"       # "config" (confirmado) | "cve" (posible, sin validar)

    @property
    def nvd_link(self) -> str:
        if self.cve.upper().startswith("CVE-"):
            return f"https://nvd.nist.gov/vuln/detail/{self.cve.upper()}"
        return ""

    @property
    def priority(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    @property
    def confirmed(self) -> bool:
        return self.kind == "config"

    @property
    def probability(self) -> str:
        # Config observable: comprobado en la red -> Alta. CVE por version: sin validar.
        if self.kind == "cve":
            return "Por determinar (requiere validacion)"
        return {"Critica": "Alta", "Alta": "Alta", "Media": "Media",
                "Baja": "Baja", "Informativa": "Baja"}.get(self.severity, "Media")

    @property
    def impact(self) -> str:
        return {"Critica": "Alto", "Alta": "Alto", "Media": "Medio",
                "Baja": "Bajo", "Informativa": "Bajo"}.get(self.severity, "Medio")


@dataclass
class Target:
    host: str                       # como lo pidio el usuario (IP/host)
    ip: str = ""
    reverse_dns: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    alive: bool = True
    note: str = ""
    ports: list[Port] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw_nmap: str = ""

    @property
    def label(self) -> str:
        return self.ip or self.host

    @property
    def web_ports(self) -> list[int]:
        return [p.port for p in self.ports if p.port in WEB_PORTS and p.state == "open"]


# Severidad -> orden (para ordenar por prioridad) y plazos de remediacion.
SEVERITY_ORDER = {"Critica": 4, "Alta": 3, "Media": 2, "Baja": 1, "Informativa": 0}
SEVERITY_DEADLINE = {  # dias
    "Critica": 7, "Alta": 7, "Media": 30, "Baja": 90, "Informativa": 90,
}
SEVERITY_PRIORITY = {
    "Critica": "P1", "Alta": "P1", "Media": "P2", "Baja": "P3", "Informativa": "P4",
}
SEVERITY_EFFORT = {
    "Critica": "Alto", "Alta": "Medio", "Media": "Medio", "Baja": "Bajo", "Informativa": "Bajo",
}


def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "Critica"
    if cvss >= 7.0:
        return "Alta"
    if cvss >= 4.0:
        return "Media"
    if cvss > 0.0:
        return "Baja"
    return "Informativa"


def bump_severity(sev: str) -> str:
    order = SEVERITY_ORDER.get(sev, 0)
    for name, val in SEVERITY_ORDER.items():
        if val == min(order + 1, 4):
            return name
    return sev


# --------------------------------------------------------------------------- #
# Configuracion (CLI)
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    targets: list[str]
    full: bool
    vulners: bool
    web: bool
    self_audit: bool
    auth: str
    formatos: list[str]
    out_base: Optional[str]
    nmap_dir: Optional[str]
    timing: int
    min_rate: Optional[int]
    auditor: str = ""
    solicitante: str = ""
    estado: str = "Borrador"
    out_scope: str = ""
    funcion: str = ""
    criticidad: str = ""
    propietario: str = ""


def parse_args(argv: Optional[list[str]] = None) -> Config:
    p = argparse.ArgumentParser(
        prog="auditoria_red.py",
        description="Auditoria de red EXTERNA de laboratorio (multi-objetivo). "
                    "Sin explotacion: descubrimiento, enumeracion, CVEs y config observable.",
    )
    p.add_argument("-t", "--target", default="",
                   help="Objetivo(s): IP|host|CIDR|lista separada por comas. "
                        "Sin -t: autodetecta la red local y audita los hosts vivos.")
    p.add_argument("--full", action="store_true",
                   help="Escanear los 65535 puertos (lento). Por defecto top 1000.")
    p.add_argument("--vulners", action="store_true",
                   help="Deteccion de CVEs con nmap --script vulners.")
    p.add_argument("--web", action="store_true",
                   help="Forzar chequeos HTTP (se activan solos si hay 80/443/8080).")
    p.add_argument("--self", dest="self_audit", action="store_true",
                   help="Auditar ademas la propia Kali (hardening local, seccion aparte).")
    p.add_argument("--auth", default="Laboratorio propio autorizado",
                   help="Referencia de autorizacion.")
    p.add_argument("-f", "--formato", default="html,pdf",
                   help="Formatos de salida: html,pdf,docx (def: html,pdf).")
    p.add_argument("-o", "--out", default=None,
                   help="Ruta base de salida (sin extension).")
    p.add_argument("-oA", "--nmap-dir", default=None, dest="nmap_dir",
                   help="Directorio para guardar las salidas crudas de nmap.")
    p.add_argument("--timing", type=int, default=4, choices=range(0, 6),
                   help="Plantilla de temporizacion nmap -T0..-T5 (def: 4).")
    p.add_argument("--min-rate", type=int, default=None, dest="min_rate",
                   help="nmap --min-rate (paquetes/seg) opcional.")
    # Metadatos del informe (si no se indican, aparecen como 'No especificado'/'No verificado').
    p.add_argument("--auditor", default="", help="Nombre y cargo del auditor (seccion 1).")
    p.add_argument("--solicitante", default="", help="Solicitante / responsable del activo (seccion 1).")
    p.add_argument("--estado", default="Borrador", help="Estado del documento: Borrador|Revisado|Final.")
    p.add_argument("--fuera-alcance", default="", dest="out_scope",
                   help="Elementos fuera de alcance (seccion 2).")
    p.add_argument("--funcion", default="", help="Funcion del equipo objetivo (seccion 3).")
    p.add_argument("--criticidad", default="", help="Criticidad del activo: Baja|Media|Alta|Critica (seccion 3).")
    p.add_argument("--propietario", default="", help="Propietario / responsable del activo (seccion 3).")

    a = p.parse_args(argv)
    targets = [t.strip() for t in a.target.split(",") if t.strip()] if a.target else []
    formatos = [f.strip().lower() for f in a.formato.split(",") if f.strip()]
    return Config(
        targets=targets, full=a.full, vulners=a.vulners, web=a.web,
        self_audit=a.self_audit, auth=a.auth, formatos=formatos,
        out_base=a.out, nmap_dir=a.nmap_dir, timing=a.timing, min_rate=a.min_rate,
        auditor=a.auditor, solicitante=a.solicitante, estado=a.estado,
        out_scope=a.out_scope, funcion=a.funcion, criticidad=a.criticidad,
        propietario=a.propietario,
    )


# --------------------------------------------------------------------------- #
# Runner: ejecucion de comandos con timeout + registro de evidencia
# --------------------------------------------------------------------------- #
@dataclass
class CmdRecord:
    cmd: str
    when: str
    rc: int
    note: str = ""


class Runner:
    def __init__(self) -> None:
        self.log: list[CmdRecord] = []

    def run(self, cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
        when = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        printable = " ".join(cmd)
        try:
            cp = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, check=False,
            )
            self.log.append(CmdRecord(printable, when, cp.returncode))
            return cp
        except subprocess.TimeoutExpired:
            self.log.append(CmdRecord(printable, when, -1, "TIMEOUT"))
            return subprocess.CompletedProcess(cmd, -1, "", "TIMEOUT")
        except FileNotFoundError:
            self.log.append(CmdRecord(printable, when, -2, "NO ENCONTRADO"))
            return subprocess.CompletedProcess(cmd, -2, "", "comando no encontrado")


# --------------------------------------------------------------------------- #
# Comprobaciones previas de entorno
# --------------------------------------------------------------------------- #
@dataclass
class Environment:
    is_root: bool
    nmap_ok: bool
    nmap_version: str
    missing_scripts: list[str]
    pdf_engine: Optional[str]
    docx_ok: bool
    warnings: list[str]


def check_environment(runner: Runner, want_vulners: bool) -> Environment:
    warnings: list[str] = []

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0  # type: ignore[attr-defined]
    if not is_root:
        warnings.append("No se ejecuta como root: -O (SO) y algunos scripts pueden "
                        "quedar limitados. Recomendado: sudo.")

    nmap_ok = shutil.which("nmap") is not None
    nmap_version = ""
    if nmap_ok:
        cp = runner.run(["nmap", "--version"], timeout=30)
        m = re.search(r"Nmap version ([\d.]+)", cp.stdout or "")
        nmap_version = m.group(1) if m else "desconocida"
    else:
        warnings.append("nmap NO esta instalado (sudo apt install nmap). Imprescindible.")

    missing_scripts: list[str] = []
    # Sincronizado con los scripts que realmente se lanzan.
    wanted = list(dict.fromkeys(BASE_SCRIPTS.split(",") + WEB_SCRIPTS.split(",")))
    if want_vulners:
        wanted.insert(0, "vulners")
    if nmap_ok:
        for sc in wanted:
            if not _nse_available(runner, sc):
                missing_scripts.append(sc)
        if missing_scripts:
            warnings.append("Scripts NSE no disponibles (se omiten sus chequeos): "
                            + ", ".join(missing_scripts))

    pdf_engine = detect_pdf_engine()
    if pdf_engine is None:
        warnings.append("Sin conversor PDF (weasyprint/wkhtmltopdf/chromium). "
                        "Se dejara el HTML; imprime a PDF desde el navegador.")

    docx_ok = _module_available("docx")

    return Environment(is_root, nmap_ok, nmap_version, missing_scripts,
                       pdf_engine, docx_ok, warnings)


def _nse_available(runner: Runner, script: str) -> bool:
    """nmap --script-help imprime el nombre del script, solo en una linea, como cabecera.

    No se busca "not found" en la salida: la descripcion de algunos scripts
    (p.ej. http-enum, que habla de paginas "404 Not Found") lo contiene.
    """
    cp = runner.run(["nmap", "--script-help", script], timeout=30)
    if cp.returncode != 0:
        return False
    return re.search(rf"^{re.escape(script)}\s*$", cp.stdout or "", re.M) is not None


def _module_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def detect_pdf_engine() -> Optional[str]:
    if _module_available("weasyprint"):
        return "weasyprint"
    if shutil.which("wkhtmltopdf"):
        return "wkhtmltopdf"
    for c in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        if shutil.which(c):
            return c
    return None


# --------------------------------------------------------------------------- #
# Deteccion de red local y descubrimiento
# --------------------------------------------------------------------------- #
def local_cidrs(runner: Runner) -> list[str]:
    cidrs: list[str] = []
    cp = runner.run(["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"], timeout=15)
    for line in (cp.stdout or "").splitlines():
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
        if m:
            cidrs.append(m.group(1))
    return cidrs


def discover_hosts(runner: Runner, cidr: str, timing: int) -> list[Target]:
    """nmap -sn: hosts vivos con IP, MAC, fabricante y DNS inverso."""
    fd, xml_path = tempfile.mkstemp(prefix="audit_disc_", suffix=".xml")
    os.close(fd)
    targets: list[Target] = []
    try:
        cp = runner.run(["nmap", "-sn", "-R", f"-T{timing}", "-oX", xml_path, cidr], timeout=900)
        if cp.returncode != 0 or not os.path.getsize(xml_path):
            return targets
        root = ET.parse(xml_path).getroot()
        for h in root.findall("host"):
            st = h.find("status")
            if st is None or st.get("state") != "up":
                continue
            t = Target(host="")
            for addr in h.findall("address"):
                kind = addr.get("addrtype")
                if kind == "ipv4":
                    t.ip = addr.get("addr", "")
                    t.host = t.ip
                elif kind == "mac":
                    t.mac = addr.get("addr", "")
                    t.vendor = addr.get("vendor", "")
            hn = h.find("hostnames/hostname")
            if hn is not None:
                t.reverse_dns = hn.get("name", "")
            if t.ip:
                targets.append(t)
    finally:
        _safe_unlink(xml_path)
    return targets


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def host_is_up(runner: Runner, host: str, timing: int) -> bool:
    cp = runner.run(["nmap", "-sn", f"-T{timing}", host], timeout=120)
    return "Host is up" in (cp.stdout or "")


# --------------------------------------------------------------------------- #
# Scanner por objetivo
# --------------------------------------------------------------------------- #
class Scanner:
    def __init__(self, runner: Runner, cfg: Config, env: Environment) -> None:
        self.runner = runner
        self.cfg = cfg
        self.env = env

    def _scripts_main(self) -> str:
        scripts = [s for s in BASE_SCRIPTS.split(",") if s not in self.env.missing_scripts]
        if self.cfg.vulners and "vulners" not in self.env.missing_scripts:
            scripts.insert(0, "vulners")
        return ",".join(scripts)

    def scan(self, t: Target) -> None:
        fd, xml_path = tempfile.mkstemp(prefix="audit_scan_", suffix=".xml")
        os.close(fd)
        try:
            cmd = ["nmap", "-sV", "-O", f"-T{self.cfg.timing}"]
            if self.cfg.full:
                cmd.append("-p-")
            if self.cfg.min_rate:
                cmd += ["--min-rate", str(self.cfg.min_rate)]
            scripts = self._scripts_main()
            if scripts:
                cmd += ["--script", scripts]
            cmd += ["-oX", xml_path, t.host]

            cp = self.runner.run(cmd, timeout=3600 if self.cfg.full else 1800)
            t.raw_nmap = (cp.stdout or "").strip()
            if self.cfg.nmap_dir:
                self._save_raw(t, cp.stdout or "")
            if os.path.getsize(xml_path):
                self._parse(xml_path, t)
        finally:
            _safe_unlink(xml_path)

        # Segunda pasada HTTP si procede.
        web_needed = self.cfg.web or bool(t.web_ports)
        if web_needed and t.web_ports:
            self._scan_web(t)

    def _scan_web(self, t: Target) -> None:
        scripts = [s for s in WEB_SCRIPTS.split(",") if s not in self.env.missing_scripts]
        if not scripts:
            return
        ports = ",".join(str(p) for p in t.web_ports)
        fd, xml_path = tempfile.mkstemp(prefix="audit_web_", suffix=".xml")
        os.close(fd)
        try:
            cmd = ["nmap", "-sV", f"-T{self.cfg.timing}", "-p", ports,
                   "--script", ",".join(scripts), "-oX", xml_path, t.host]
            cp = self.runner.run(cmd, timeout=1200)
            if self.cfg.nmap_dir:
                self._save_raw(t, cp.stdout or "", suffix="web")
            if os.path.getsize(xml_path):
                self._parse_scripts_only(xml_path, t)
        finally:
            _safe_unlink(xml_path)

    def _save_raw(self, t: Target, text: str, suffix: str = "") -> None:
        if not self.cfg.nmap_dir:
            return
        os.makedirs(self.cfg.nmap_dir, exist_ok=True)
        name = f"{t.label.replace('/', '_')}{('_' + suffix) if suffix else ''}.txt"
        try:
            with open(os.path.join(self.cfg.nmap_dir, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError:
            pass

    # ---- parseo XML ----
    def _parse(self, xml_path: str, t: Target) -> None:
        root = ET.parse(xml_path).getroot()
        h = root.find("host")
        if h is None:
            t.alive = False
            t.note = "El objetivo no devolvio resultados (posible host caido o filtrado total)."
            return
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            t.alive = False
            t.note = "Host marcado como caido por nmap."
        for addr in h.findall("address"):
            kind = addr.get("addrtype")
            if kind == "ipv4" and not t.ip:
                t.ip = addr.get("addr", "")
            elif kind == "mac":
                t.mac = t.mac or addr.get("addr", "")
                t.vendor = t.vendor or addr.get("vendor", "")
        hn = h.find("hostnames/hostname")
        if hn is not None and not t.reverse_dns:
            t.reverse_dns = hn.get("name", "")
        osm = h.find("os/osmatch")
        if osm is not None:
            t.os_guess = f"{osm.get('name', '')} ({osm.get('accuracy', '?')}%)"

        for pe in h.findall("ports/port"):
            state = pe.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = pe.find("service")
            port = Port(
                port=int(pe.get("portid", "0")),
                proto=pe.get("protocol", "tcp"),
                state="open",
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extrainfo=svc.get("extrainfo", "") if svc is not None else "",
                tunnel=svc.get("tunnel", "") if svc is not None else "",
            )
            t.ports.append(port)
            self._apply_port_scripts(pe, t, port)

    def _parse_scripts_only(self, xml_path: str, t: Target) -> None:
        root = ET.parse(xml_path).getroot()
        h = root.find("host")
        if h is None:
            return
        for pe in h.findall("ports/port"):
            portid = int(pe.get("portid", "0"))
            port = next((p for p in t.ports if p.port == portid), None)
            if port is None:
                continue
            self._apply_port_scripts(pe, t, port)

    def _apply_port_scripts(self, pe: ET.Element, t: Target, port: Port) -> None:
        # Los dos scripts de cabeceras se evaluan juntos: un unico control por puerto.
        header_outputs: dict[str, str] = {}
        for sc in pe.findall("script"):
            sid = sc.get("id", "")
            out = sc.get("output", "") or ""
            if sid == "vulners":
                self._parse_vulners(sc, t, port)
            elif sid == "ssl-enum-ciphers":
                self._parse_ssl(sc, out, t, port)
            elif sid == "ftp-anon":
                self._parse_ftp_anon(out, t, port)
            elif sid == "http-methods":
                self._parse_http_methods(out, t, port)
            elif sid in HEADER_SCRIPTS:
                header_outputs[sid] = out
            elif sid == "http-enum":
                self._parse_http_enum(out, t, port)
            elif sid == "http-title":
                if out.strip():
                    t.checks.append(Check(f"Título web ({port.port})", "Informativo", out.strip()))
        if header_outputs:
            self._parse_http_headers(header_outputs, t, port)

    # ---- parsers especificos ----
    def _parse_vulners(self, sc: ET.Element, t: Target, port: Port) -> None:
        comp = f"{port.service} {port.banner}".strip() + f" (puerto {port.port})"
        found: dict[str, float] = {}
        for table in sc.iter("table"):
            cve = ""
            cvss = 0.0
            for elem in table.findall("elem"):
                key = elem.get("key", "")
                val = (elem.text or "").strip()
                if key == "id":
                    cve = val
                elif key == "cvss":
                    try:
                        cvss = float(val)
                    except ValueError:
                        cvss = 0.0
            if cve.upper().startswith("CVE-"):
                # dedup: nos quedamos con el CVSS mas alto por CVE
                if cve not in found or cvss > found[cve]:
                    found[cve] = cvss
        for cve, cvss in found.items():
            sev = cvss_to_severity(cvss)
            if port.is_cleartext:
                sev = bump_severity(sev)
            t.findings.append(Finding(
                fid="", component=comp, title=f"{cve} en {port.service or 'servicio'}",
                cve=cve, cvss=cvss, severity=sev, kind="cve",
                description=f"Vulnerabilidad asociada por versión a {port.banner or port.service}.",
                evidence=f"nmap --script vulners sobre {port.service} {port.banner} (puerto {port.port}).",
                status="Posible (sin validar): emparejada por version, pendiente de confirmacion en NVD",
                recommendation="Actualizar el componente a una versión sin esta CVE y validar manualmente.",
            ))

    def _parse_ssl(self, sc: ET.Element, out: str, t: Target, port: Port) -> None:
        # La presencia de ssl-enum-ciphers confirma que el puerto habla TLS.
        port.tls = True
        # Solo cuentan protocolos y nombres/notas de cifrados: ni "compressors: NULL"
        # ni los "warnings" (p.ej. key exchange de menor fuerza) son cifrados debiles.
        protocols, ciphers, warnings, least = _ssl_from_xml(sc)
        if not protocols:
            protocols, ciphers, warnings, least = _ssl_from_text(out)

        high_protos = [p for p in TLS_PROTOCOLS_HIGH if p in protocols]
        old_protos = high_protos + [p for p in TLS_PROTOCOLS_LEGACY if p in protocols]
        weak_names = list(dict.fromkeys(n for n, _ in ciphers if _is_weak_cipher(n)))
        low_names = list(dict.fromkeys(n for n, g in ciphers if g in WEAK_GRADES))
        low_grade = bool(low_names) or least in WEAK_GRADES

        if old_protos or weak_names or low_grade:
            detail = []
            if old_protos:
                detail.append("protocolos obsoletos: " + ", ".join(old_protos))
            if weak_names:
                detail.append("cifrados débiles detectados: " + _short_list(weak_names))
            if low_names:
                detail.append("cifrados con nota baja (C-F): " + _short_list(low_names))
            elif low_grade:
                detail.append(f"grado de cifrado bajo (least strength: {least})")
            dtxt = "; ".join(detail)
            t.checks.append(Check(f"TLS/SSL ({port.port})", "Hallazgo", dtxt))
            sev = "Alta" if high_protos else "Media"
            t.findings.append(Finding(
                fid="", component=f"{port.service or 'TLS'} (puerto {port.port})",
                title=f"Configuración TLS/SSL débil ({port.port})",
                severity=sev,
                description="El servicio acepta protocolos o cifrados criptográficamente débiles.",
                evidence=f"nmap --script ssl-enum-ciphers: {dtxt}.",
                recommendation="Deshabilitar SSLv2/SSLv3/TLS1.0/1.1 y los cifrados débiles; "
                               "usar TLS1.2+ con cifrados fuertes.",
            ))
        else:
            t.checks.append(Check(f"TLS/SSL ({port.port})", "Correcto", "Sin protocolos/cifrados débiles observados."))

        if warnings:
            t.checks.append(Check(f"Avisos TLS ({port.port})", "Informativo",
                                  "; ".join(dict.fromkeys(warnings))))

    def _parse_ftp_anon(self, out: str, t: Target, port: Port) -> None:
        if "Anonymous FTP login allowed" in out or "anonymous" in out.lower():
            t.checks.append(Check(f"FTP anónimo ({port.port})", "Hallazgo", "Login anónimo permitido."))
            t.findings.append(Finding(
                fid="", component=f"FTP (puerto {port.port})",
                title="FTP anónimo permitido", severity="Alta",
                description="El servidor FTP admite acceso anónimo.",
                evidence="nmap --script ftp-anon: 'Anonymous FTP login allowed'.",
                recommendation="Deshabilitar el acceso anonimo o retirar el servicio FTP; usar FTPS/SFTP.",
            ))

    def _parse_http_methods(self, out: str, t: Target, port: Port) -> None:
        dangerous = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if re.search(rf"\b{m}\b", out)]
        if dangerous:
            dtxt = ", ".join(dangerous)
            t.checks.append(Check(f"Métodos HTTP ({port.port})", "Hallazgo", f"Métodos peligrosos: {dtxt}"))
            t.findings.append(Finding(
                fid="", component=f"HTTP (puerto {port.port})",
                title=f"Métodos HTTP peligrosos habilitados ({port.port})", severity="Media",
                description=f"El servidor web permite métodos peligrosos: {dtxt}.",
                evidence=f"nmap --script http-methods: {dtxt}.",
                recommendation="Deshabilitar PUT/DELETE/TRACE/CONNECT salvo necesidad justificada.",
            ))
        else:
            t.checks.append(Check(f"Métodos HTTP ({port.port})", "Correcto", "Sin métodos peligrosos."))

    def _parse_http_headers(self, outputs: dict[str, str], t: Target, port: Port) -> None:
        """Evalua juntas las salidas de http-headers y http-security-headers."""
        present: set[str] = set()
        server = ""
        # http-headers: lineas "Nombre: valor" de la respuesta real.
        for ln in outputs.get("http-headers", "").splitlines():
            m = re.match(r"\s*([A-Za-z0-9-]+):\s*(.*)$", ln)
            if m:
                name = m.group(1).lower()
                present.add(name)
                if name == "server" and not server:
                    server = m.group(2).strip()
        # http-security-headers: secciones con guion bajo (Strict_Transport_Security)
        # y, si la cabecera existe, una linea "Header: Nombre: valor".
        for m in re.finditer(r"^\s*Header:\s*([A-Za-z0-9-]+):", outputs.get("http-security-headers", ""),
                             re.M | re.I):
            present.add(m.group(1).lower())

        sources = ", ".join(s for s in HEADER_SCRIPTS if s in outputs)
        missing = [h for h in SECURITY_HEADERS if h not in present]
        if missing:
            dtxt = ", ".join(missing)
            t.checks.append(Check(f"Cabeceras de seguridad ({port.port})", "Hallazgo", f"Ausentes: {dtxt}"))
            t.findings.append(Finding(
                fid="", component=f"HTTP (puerto {port.port})",
                title=f"Cabeceras de seguridad ausentes ({port.port})", severity="Baja",
                description=f"Faltan cabeceras de seguridad: {dtxt}.",
                evidence=f"nmap --script {sources} (ausencia de cabeceras).",
                recommendation="Añadir HSTS, CSP, X-Frame-Options y X-Content-Type-Options.",
            ))
        else:
            t.checks.append(Check(f"Cabeceras de seguridad ({port.port})", "Correcto", "Presentes las cabeceras clave."))
        # Banner del servidor expuesto
        if server:
            t.checks.append(Check(f"Banner servidor web ({port.port})", "Informativo", server))

    def _parse_http_enum(self, out: str, t: Target, port: Port) -> None:
        lines = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("/")]
        if lines:
            detail = "; ".join(lines[:15])
            t.checks.append(Check(f"Rutas/paneles web ({port.port})", "Hallazgo", detail))
            t.findings.append(Finding(
                fid="", component=f"HTTP (puerto {port.port})",
                title=f"Rutas o paneles conocidos expuestos ({port.port})", severity="Baja",
                description="http-enum descubrió rutas/paneles potencialmente sensibles.",
                evidence=f"nmap --script http-enum: {detail}",
                recommendation="Restringir o retirar paneles/rutas no necesarios; aplicar autenticación.",
            ))


# --------------------------------------------------------------------------- #
# ssl-enum-ciphers: extraccion de protocolos, cifrados (nombre, nota) y avisos
# --------------------------------------------------------------------------- #
SslData = tuple[list[str], list[tuple[str, str]], list[str], str]

_SSL_PROTO_RE = re.compile(r"^\s*(SSLv[23]|TLSv1\.\d):\s*$")
_SSL_CIPHER_RE = re.compile(r"^\s*((?:TLS|SSL)\d?_[A-Za-z0-9_]+)\b.*?(?:-\s*([A-F]))?\s*$")


def _ssl_from_xml(sc: ET.Element) -> SslData:
    """Lee la estructura <table> del XML de nmap (fuente principal)."""
    protocols: list[str] = []
    ciphers: list[tuple[str, str]] = []
    warnings: list[str] = []
    for ptab in sc.findall("table"):
        proto = ptab.get("key", "")
        if not proto:
            continue
        protocols.append(proto)
        for ctab in ptab.findall("table[@key='ciphers']/table"):
            name = (ctab.findtext("elem[@key='name']") or "").strip()
            grade = (ctab.findtext("elem[@key='strength']") or "").strip().upper()
            if name:
                ciphers.append((name, grade))
        for w in ptab.findall("table[@key='warnings']/elem"):
            if (w.text or "").strip():
                warnings.append(w.text.strip())
    least = (sc.findtext("elem[@key='least strength']") or "").strip().upper()
    return protocols, ciphers, warnings, least


def _ssl_from_text(out: str) -> SslData:
    """Respaldo si el XML no trae tablas: parseo por lineas del texto del script."""
    protocols: list[str] = []
    ciphers: list[tuple[str, str]] = []
    warnings: list[str] = []
    warn_indent: Optional[int] = None
    for ln in out.splitlines():
        s = ln.strip()
        indent = len(ln) - len(ln.lstrip())
        if warn_indent is not None:
            if s and indent > warn_indent:
                warnings.append(s)
                continue
            warn_indent = None
        if s == "warnings:":
            warn_indent = indent
            continue
        m = _SSL_PROTO_RE.match(ln)
        if m:
            protocols.append(m.group(1))
            continue
        m = _SSL_CIPHER_RE.match(ln)
        if m:
            ciphers.append((m.group(1), (m.group(2) or "").upper()))
    m = re.search(r"least strength:\s*([A-F])", out)
    return protocols, ciphers, warnings, (m.group(1) if m else "")


def _is_weak_cipher(name: str) -> bool:
    """Busca keywords debiles como tokens del nombre IANA (TLS_RSA_WITH_3DES_EDE_CBC_SHA)."""
    tokens = name.upper().split("_")
    return any(tok in WEAK_CIPHER_TOKENS or tok.startswith("EXPORT") for tok in tokens)


def _short_list(items: list[str], limit: int = 6) -> str:
    extra = f" (+{len(items) - limit} mas)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + extra


# --------------------------------------------------------------------------- #
# Chequeos observables derivados (servicios sin cifrar, banners)
# --------------------------------------------------------------------------- #
def derive_observable_checks(t: Target) -> None:
    # Servicios sin cifrar expuestos
    cleartext = [p for p in t.ports if p.is_cleartext]
    if cleartext:
        for p in cleartext:
            t.checks.append(Check(
                f"Servicio sin cifrar ({p.service}/{p.port})", "Hallazgo",
                f"{p.service} expuesto en el puerto {p.port} (tráfico sin cifrar)."))
            sev = bump_severity("Media")
            t.findings.append(Finding(
                fid="", component=f"{p.service} (puerto {p.port})",
                title=f"Servicio sin cifrar expuesto: {p.service} ({p.port})", severity=sev,
                description=f"El servicio {p.service} transmite en texto claro y está accesible desde la red.",
                evidence=f"nmap -sV: puerto {p.port}/{p.proto} abierto, servicio {p.service} {p.banner}.",
                recommendation="Sustituir por su equivalente cifrado (SSH/HTTPS/FTPS) o restringir el acceso.",
            ))
    else:
        t.checks.append(Check("Servicios sin cifrar", "Correcto", "No se observan servicios en texto claro."))

    # Banners de version expuestos
    bannered = [p for p in t.ports if p.banner]
    if bannered:
        detail = "; ".join(f"{p.port}/{p.service}: {p.banner}" for p in bannered[:12])
        t.checks.append(Check("Banners de versión expuestos", "Informativo", detail))

    # Controles que requieren credenciales (no verificables en caja negra)
    for name in ("Política de contraseñas", "Configuración de sudo",
                 "Parches internos del sistema", "Cuentas locales"):
        t.checks.append(Check(name, "No verificado",
                              "No verificado (auditoría externa sin credenciales)."))


def dedupe_target(t: Target) -> None:
    """Quita checks/findings repetidos del objetivo, conservando el orden de aparicion.

    Checks: clave = nombre (incluye tipo de control y puerto); gana el estado mas grave.
    Findings: clave = (componente/puerto, titulo, CVE); gana la mayor severidad/CVSS.
    """
    checks: dict[str, Check] = {}
    for c in t.checks:
        prev = checks.get(c.name)
        if prev is None or CHECK_STATUS_RANK.get(c.status, 0) > CHECK_STATUS_RANK.get(prev.status, 0):
            checks[c.name] = c
    t.checks = list(checks.values())

    findings: dict[tuple[str, str, str], Finding] = {}
    for f in t.findings:
        key = (f.component, f.title, f.cve.upper())
        prev = findings.get(key)
        if prev is None or (f.priority, f.cvss) > (prev.priority, prev.cvss):
            findings[key] = f
    t.findings = list(findings.values())


def assign_finding_ids(t: Target) -> None:
    t.findings.sort(key=lambda f: (-f.priority, -f.cvss))
    for i, f in enumerate(t.findings, 1):
        f.fid = f"{t.label}-F{i:03d}"


# --------------------------------------------------------------------------- #
# Auditoria local opcional (--self): hardening de la propia Kali
# --------------------------------------------------------------------------- #
def self_audit(runner: Runner) -> Target:
    t = Target(host="localhost (Kali)", ip="127.0.0.1", os_guess="Kali Linux (local)")
    t.note = "Auditoria de hardening LOCAL de la plataforma (seccion complementaria)."

    def add(name: str, status: str, detail: str = "") -> None:
        t.checks.append(Check(name, status, detail))

    def read(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""

    # SSH
    sshd = read("/etc/ssh/sshd_config")
    if sshd:
        prl = re.search(r"^\s*PermitRootLogin\s+(\S+)", sshd, re.I | re.M)
        pa = re.search(r"^\s*PasswordAuthentication\s+(\S+)", sshd, re.I | re.M)
        prl_v = prl.group(1).lower() if prl else "yes (por defecto)"
        pa_v = pa.group(1).lower() if pa else "yes (por defecto)"
        add("SSH PermitRootLogin", "Hallazgo" if prl_v in ("yes",) else "Correcto", prl_v)
        add("SSH PasswordAuthentication", "Hallazgo" if pa_v in ("yes", "yes (por defecto)") else "Correcto", pa_v)
    else:
        add("SSH", "No aplica", "sshd_config no encontrado (SSH no instalado).")

    # Politica de contrasenas
    pw = read("/etc/security/pwquality.conf")
    m = re.search(r"^\s*minlen\s*=\s*(\d+)", pw, re.M) if pw else None
    if m:
        n = int(m.group(1))
        add("Politica de contrasenas (minlen)", "Correcto" if n >= 12 else "Hallazgo", f"minlen={n}")
    else:
        add("Politica de contrasenas (minlen)", "Hallazgo", "minlen no definido en pwquality.conf.")

    # Cuentas sin contrasena
    shadow = read("/etc/shadow")
    if shadow:
        empty = [ln.split(":")[0] for ln in shadow.splitlines()
                 if len(ln.split(":")) > 1 and ln.split(":")[1] == ""]
        add("Cuentas sin contrasena", "Hallazgo" if empty else "Correcto",
            ("Cuentas: " + ", ".join(empty)) if empty else "Ninguna.")
    else:
        add("Cuentas sin contrasena", "No verificado", "/etc/shadow no legible (requiere root).")

    # Usuarios sudo
    cp = runner.run(["getent", "group", "sudo"], timeout=15)
    if cp.returncode == 0 and ":" in (cp.stdout or ""):
        members = cp.stdout.strip().split(":")[-1]
        add("Usuarios sudo", "Informativo", members or "(sin miembros)")

    # Cortafuegos
    ufw = runner.run(["ufw", "status"], timeout=15)
    if ufw.returncode == 0 and ufw.stdout:
        active = "Status: active" in ufw.stdout
        add("Cortafuegos (ufw)", "Correcto" if active else "Hallazgo",
            "activo" if active else "inactivo")
    else:
        ipt = runner.run(["iptables", "-S"], timeout=15)
        rules = len([l for l in (ipt.stdout or "").splitlines() if l.startswith("-A")])
        add("Cortafuegos (iptables)", "Correcto" if rules else "Hallazgo",
            f"{rules} reglas" if rules else "sin reglas / no verificable")

    ipf = read("/proc/sys/net/ipv4/ip_forward").strip()
    if ipf:
        add("ip_forward", "Hallazgo" if ipf == "1" else "Correcto", ipf)

    # Permisos de /etc/shadow
    try:
        mode = oct(os.stat("/etc/shadow").st_mode)[-3:]
        add("Permisos /etc/shadow", "Correcto" if mode in ("600", "640", "000") else "Hallazgo", mode)
    except OSError:
        add("Permisos /etc/shadow", "No verificado", "no accesible.")

    # Ficheros world-writable (acotado)
    ww = runner.run(["find", "/etc", "-xdev", "-type", "f", "-perm", "-0002"], timeout=120)
    files = [l for l in (ww.stdout or "").splitlines() if l.strip()]
    add("Ficheros world-writable en /etc", "Hallazgo" if files else "Correcto",
        ("; ".join(files[:10])) if files else "ninguno")

    # /tmp noexec
    mounts = read("/proc/mounts")
    tmp_line = next((l for l in mounts.splitlines() if " /tmp " in l), "")
    if tmp_line:
        add("/tmp noexec", "Correcto" if "noexec" in tmp_line else "Hallazgo",
            "noexec presente" if "noexec" in tmp_line else "sin noexec")
    else:
        add("/tmp noexec", "Informativo", "/tmp no es un montaje separado.")

    # Actualizaciones
    up = runner.run(["apt", "list", "--upgradable"], timeout=120)
    pend = [l for l in (up.stdout or "").splitlines() if "/" in l and "upgradable" in l]
    add("Actualizaciones pendientes", "Hallazgo" if pend else "Correcto",
        f"{len(pend)} paquetes actualizables" if pend else "sistema al dia")
    add("unattended-upgrades", "Correcto" if shutil.which("unattended-upgrade") else "Hallazgo",
        "instalado" if shutil.which("unattended-upgrade") else "no instalado")

    # Registro y tiempo
    for svc in ("auditd", "rsyslog", "systemd-journald"):
        st = runner.run(["systemctl", "is-active", svc], timeout=15)
        state = (st.stdout or "").strip() or "desconocido"
        add(f"Servicio de registro: {svc}", "Correcto" if state == "active" else "Hallazgo", state)
    ntp = runner.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=15)
    val = (ntp.stdout or "").strip()
    add("Sincronizacion NTP", "Correcto" if val == "yes" else "Hallazgo", val or "desconocido")

    # Hallazgos locales -> findings (severidad conservadora)
    for c in t.checks:
        if c.status == "Hallazgo":
            t.findings.append(Finding(
                fid="", component="Kali (local)", title=c.name, severity="Media",
                description=c.detail, evidence=f"Chequeo local: {c.name} = {c.detail}",
                recommendation="Revisar y endurecer la configuracion local segun guia CIS.",
            ))
    dedupe_target(t)
    assign_finding_ids(t)
    return t


# --------------------------------------------------------------------------- #
# Informe HTML
# --------------------------------------------------------------------------- #
def e(x: object) -> str:
    return html.escape(str(x), quote=True)


SEV_COLOR = {
    "Critica": "#7f1d1d", "Alta": "#dc2626", "Media": "#ea8a0b",
    "Baja": "#2563eb", "Informativa": "#64748b",
}
RISK_COLOR = {
    "Critico": "#7f1d1d", "Alto": "#dc2626", "Medio": "#ea8a0b",
    "Bajo": "#2563eb", "Informativo": "#64748b",
}


class ReportBuilder:
    def __init__(self, cfg: Config, env: Environment, runner: Runner,
                 targets: list[Target], self_t: Optional[Target]) -> None:
        self.cfg = cfg
        self.env = env
        self.runner = runner
        self.targets = targets
        self.self_t = self_t
        self.now = _dt.datetime.now()
        self.code = "AUD-" + self.now.strftime("%Y%m%d-%H%M")

    # --- agregados ---
    def all_findings(self) -> list[Finding]:
        fs: list[Finding] = []
        for t in self.targets:
            fs.extend(t.findings)
        return sorted(fs, key=lambda f: (-f.priority, -f.cvss))

    def confirmed_findings(self) -> list[Finding]:
        return [f for f in self.all_findings() if f.confirmed]

    def potential_findings(self) -> list[Finding]:
        return [f for f in self.all_findings() if not f.confirmed]

    def severity_counts(self, findings: Optional[list[Finding]] = None) -> dict[str, int]:
        if findings is None:
            findings = self.all_findings()
        counts = {k: 0 for k in SEVERITY_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @staticmethod
    def _risk_from_counts(c: dict[str, int]) -> str:
        if c.get("Critica"):
            return "Critico"
        if c.get("Alta"):
            return "Alto"
        if c.get("Media"):
            return "Medio"
        if c.get("Baja"):
            return "Bajo"
        return "Informativo"

    def global_risk(self) -> str:
        """Riesgo CONFIRMADO: solo hallazgos de configuracion verificados."""
        return self._risk_from_counts(self.severity_counts(self.confirmed_findings()))

    def potential_risk(self) -> str:
        """Riesgo POTENCIAL: si se validaran las CVE asociadas por version."""
        return self._risk_from_counts(self.severity_counts(self.all_findings()))

    def scan_window(self) -> tuple[str, str]:
        times = [r.when for r in self.runner.log if r.when]
        if not times:
            s = self.now.strftime("%Y-%m-%d %H:%M")
            return s, s
        return min(times), max(times)

    def build(self) -> str:
        p: list[str] = []
        p.append(self._head())
        p.append(self._s1_general())
        p.append(self._s2_scope())
        p.append(self._s3_identification())
        p.append(self._s4_inventory())
        p.append(self._s5_review())
        p.append(self._s6_vulnerabilities())
        p.append(self._s7_executive())
        p.append(self._s8_remediation())
        p.append(self._s9_methodology())
        p.append(self._s10_annexes())
        p.append("</body></html>")
        return "\n".join(p)

    # --- plantilla ---
    def _head(self) -> str:
        css = """
        @page { size:A4; margin:16mm 14mm; }
        * { box-sizing:border-box; }
        body { font-family:'Segoe UI',Helvetica,Arial,sans-serif; color:#1f2328; margin:0;
               line-height:1.4; font-size:10.5px; }
        h1 { font-size:21px; color:#0f172a; margin:0 0 2px; letter-spacing:-.2px; }
        .subtitle { color:#64748b; font-size:11px; margin:0 0 14px; }
        h2 { font-size:13.5px; color:#0f172a; margin:18px 0 6px; padding-bottom:3px;
             border-bottom:2px solid #0f172a; page-break-after:avoid; }
        h3 { font-size:11.5px; color:#334155; margin:12px 0 4px; text-transform:uppercase;
             letter-spacing:.4px; page-break-after:avoid; }
        h4 { font-size:10.5px; color:#475569; margin:8px 0 3px; }
        p { margin:5px 0; }
        table { border-collapse:collapse; width:100%; margin:6px 0 10px; font-size:9.6px;
                page-break-inside:auto; }
        th,td { border:1px solid #e2e8f0; padding:3px 6px; text-align:left; vertical-align:top; }
        th { background:#0f172a; color:#fff; font-weight:600; font-size:9px; text-transform:uppercase;
             letter-spacing:.3px; }
        tbody tr:nth-child(even) { background:#f8fafc; }
        tr { page-break-inside:avoid; }
        .meta { display:grid; grid-template-columns:1fr 1fr; gap:2px 18px; background:#f1f5f9;
                border:1px solid #e2e8f0; border-left:3px solid #0f172a; padding:9px 14px;
                border-radius:4px; font-size:10px; }
        .sev { color:#fff; padding:1px 6px; border-radius:10px; font-weight:600; font-size:8.5px;
               display:inline-block; white-space:nowrap; }
        .finding { border:1px solid #e2e8f0; border-left:4px solid #888; border-radius:4px;
                   padding:7px 11px; margin:7px 0; page-break-inside:avoid; font-size:9.8px; }
        .finding b { color:#0f172a; }
        .kpibar { display:flex; gap:7px; margin:8px 0 2px; }
        .kpi { flex:1; text-align:center; padding:8px 4px; border-radius:5px; color:#fff; }
        .kpi .n { font-size:19px; font-weight:700; display:block; line-height:1; }
        .kpi .l { font-size:8px; text-transform:uppercase; letter-spacing:.4px; }
        .risk { display:inline-block; padding:3px 12px; border-radius:4px; color:#fff;
                font-weight:700; font-size:12px; }
        code { font-family:'Consolas',monospace; font-size:9px; background:#f1f5f9; padding:0 3px;
               border-radius:3px; }
        pre { background:#0f172a; color:#e2e8f0; padding:8px 10px; border-radius:4px;
              font-size:8.4px; white-space:pre-wrap; word-break:break-word; }
        .warn { background:#fef9ec; border:1px solid #f0d58a; border-left:3px solid #d99e2b;
                padding:6px 11px; border-radius:4px; font-size:9.6px; }
        .muted { color:#94a3b8; }
        a { color:#2563eb; text-decoration:none; }
        details { margin:4px 0; } summary { cursor:pointer; color:#475569; font-size:9.4px; }
        @media print { h2 { page-break-before:auto; } }
        """
        return (f"<!DOCTYPE html><html lang='es'><head><meta charset='utf-8'>"
                f"<title>Informe de auditoría externa {e(self.code)}</title>"
                f"<style>{css}</style></head><body>"
                f"<h1>Informe de auditoría de seguridad externa</h1>"
                f"<p class='subtitle'>Evaluación de vulnerabilidades (caja negra) &middot; "
                f"{e(self.code)} &middot; {e(self.now.strftime('%Y-%m-%d'))}</p>")

    def _sev_badge(self, sev: str) -> str:
        return f"<span class='sev' style='background:{SEV_COLOR.get(sev, '#888')}'>{e(sev)}</span>"

    def _s1_general(self) -> str:
        auditor = self.cfg.auditor.strip() or "No especificado"
        solicitante = self.cfg.solicitante.strip() or "No especificado"
        risk = self.global_risk()
        return (
            "<h2>1. Datos generales</h2>"
            "<div class='meta'>"
            f"<div><b>Código / referencia:</b> {e(self.code)}</div>"
            f"<div><b>Fecha de la auditoría:</b> {e(self.now.strftime('%Y-%m-%d %H:%M'))}</div>"
            f"<div><b>Auditor:</b> {e(auditor)}</div>"
            f"<div><b>Solicitante / responsable:</b> {e(solicitante)}</div>"
            f"<div><b>Versión y estado:</b> v1.0 &ndash; {e(self.cfg.estado)}</div>"
            f"<div><b>Tipo:</b> Evaluación de vulnerabilidades externa (caja negra)</div>"
            f"<div><b>Riesgo confirmado:</b> "
            f"<span class='risk' style='background:{RISK_COLOR.get(risk, '#64748b')}'>{e(risk)}</span></div>"
            f"<div><b>Herramienta:</b> auditoria_red.py v{e(VERSION)} (nmap {e(self.env.nmap_version or '-')})</div>"
            f"<div style='grid-column:1/3'><b>Nivel de confidencialidad:</b> Confidencial. "
            f"Uso restringido al propietario del laboratorio.</div>"
            "</div>")

    def _s2_scope(self) -> str:
        rows = "".join(
            f"<tr><td>{e(t.host)}</td><td>{e(t.label)}</td></tr>" for t in self.targets)
        warns = ""
        if self.env.warnings:
            warns = "<div class='warn'><b>Avisos de entorno:</b><ul>" + \
                "".join(f"<li>{e(w)}</li>" for w in self.env.warnings) + "</ul></div>"
        ini, fin = self.scan_window()
        out_scope = self.cfg.out_scope.strip() or (
            "Explotación de vulnerabilidades; ataques de denegación de servicio (DoS); "
            "ingeniería social; pruebas sobre equipos ajenos al objetivo indicado.")
        return (
            "<h2>2. Alcance y autorización</h2>"
            "<p>Auditoría de tipo <b>caja negra</b> (sin credenciales) realizada desde una plataforma "
            "Kali Linux contra el objetivo del laboratorio. El sujeto de la auditoría es el equipo "
            "objetivo; la Kali es únicamente la plataforma de análisis.</p>"
            "<table>"
            f"<tr><th style='width:30%'>Activo(s) evaluado(s)</th><td>"
            + ", ".join(e(t.label) for t in self.targets) + "</td></tr>"
            f"<tr><th>Tipo de análisis</th><td>Caja negra (sin credenciales), no intrusivo</td></tr>"
            f"<tr><th>Autorización</th><td>{e(self.cfg.auth)}</td></tr>"
            f"<tr><th>Ventana de pruebas</th><td>Inicio {e(ini)} &rarr; fin {e(fin)}</td></tr>"
            f"<tr><th>Elementos fuera de alcance</th><td>{e(out_scope)}</td></tr>"
            f"<tr><th>Limitaciones</th><td>Auditoría sin credenciales: los controles internos "
            "(cuentas, parches, permisos) no son verificables. La validación de CVE y cualquier "
            "explotación son manuales y quedan fuera de este trabajo. <b>No se realiza explotación.</b>"
            "</td></tr>"
            "</table>"
            "<p><b>Objetivos:</b></p>"
            f"<table><tr><th>Solicitado</th><th>Dirección</th></tr>{rows}</table>"
            f"{warns}")

    def _s3_identification(self) -> str:
        nv_int = "No verificado: requiere acceso al sistema operativo"
        funcion = self.cfg.funcion.strip() or "No especificado por el propietario"
        crit = self.cfg.criticidad.strip() or "No especificada por el propietario"
        prop = self.cfg.propietario.strip() or "Pendiente de asignación"
        out = ["<h2>3. Identificación del equipo</h2>",
               "<p class='muted'>Los datos observables se obtienen del escaneo externo (Nmap). "
               "Los datos internos no son verificables sin acceso al sistema.</p>"]
        for t in self.targets:
            out.append(f"<h3>Objetivo: {e(t.label)}</h3>")
            if not t.alive:
                out.append(f"<p class='warn'>{e(t.note or 'Host no disponible durante la auditoría.')}</p>")
            out.append(
                "<table>"
                f"<tr><th style='width:26%'>Nombre de host</th><td>{e(t.reverse_dns or nv_int)}</td></tr>"
                f"<tr><th>Dirección IP</th><td>{e(t.ip or '-')}</td></tr>"
                f"<tr><th>Dirección MAC</th><td>{e(t.mac or '-')} "
                f"({e(t.vendor or 'fabricante no determinado')})</td></tr>"
                f"<tr><th>SO (estimado por Nmap)</th><td>{e(t.os_guess or 'No determinado')} "
                "<span class='muted'>&mdash; estimación por huella de red, no versión exacta</span></td></tr>"
                f"<tr><th>Versión exacta de SO</th><td>{nv_int}</td></tr>"
                f"<tr><th>Versión del kernel</th><td>{nv_int}</td></tr>"
                f"<tr><th>Tipo de equipo</th><td>"
                + (f"Máquina virtual ({e(t.vendor)})" if t.vendor else "No determinado")
                + "</td></tr>"
                f"<tr><th>Último arranque</th><td>{nv_int}</td></tr>"
                f"<tr><th>Función / servicio</th><td>{e(funcion)}</td></tr>"
                f"<tr><th>Criticidad del activo</th><td>{e(crit)}</td></tr>"
                f"<tr><th>Propietario / responsable</th><td>{e(prop)}</td></tr>"
                "</table>")
        return "".join(out)

    # Servicios heredados/inseguros tipicos que conviene revisar o retirar.
    LEGACY_SERVICES = {"telnet", "rlogin", "rsh", "rexec", "exec", "login", "shell",
                       "distccd", "x11", "doom", "tftp", "finger"}

    def _port_obs(self, p: Port) -> str:
        notes = []
        if p.service.lower() in self.LEGACY_SERVICES:
            notes.append("protocolo heredado/inseguro")
        enc = p.encryption
        if enc == "Sin cifrar":
            notes.append("tráfico en claro")
        elif enc == "Parcial (STARTTLS)":
            notes.append("cifrado oportunista (STARTTLS)")
        if not p.version and p.service:
            notes.append("versión no identificada")
        return "; ".join(notes) or "—"

    def _s4_inventory(self) -> str:
        out = ["<h2>4. Inventario de servicios y puertos</h2>",
               "<p class='muted'>&laquo;Accesible desde&raquo; = alcanzable en el escaneo externo. "
               "&laquo;Proceso/usuario&raquo; requiere acceso al sistema (no verificable en caja negra).</p>"]
        for t in self.targets:
            out.append(f"<h3>Objetivo: {e(t.label)}</h3>")
            if not t.ports:
                out.append("<p class='muted'>Sin puertos abiertos detectados.</p>")
                continue
            rows = []
            unneeded = []
            for p in sorted(t.ports, key=lambda x: x.port):
                legacy = p.service.lower() in self.LEGACY_SERVICES
                necesario = "Revisar (posible innecesario)" if legacy else "Revisar"
                if legacy:
                    unneeded.append(f"{p.port}/{p.service}")
                rows.append(
                    f"<tr><td>{p.port}/{e(p.proto)}</td><td>{e(p.service or '-')}</td>"
                    f"<td>{e(p.product or '-')}</td><td>{e(p.version or '-')}</td>"
                    f"<td>{e(p.encryption)}</td><td>{e(necesario)}</td>"
                    f"<td>Red (escaneo externo)</td><td>No verificado</td>"
                    f"<td>{e(self._port_obs(p))}</td></tr>")
            out.append(
                "<table><tr><th>Puerto</th><th>Servicio</th><th>Producto</th><th>Versión</th>"
                "<th>Cifrado</th><th>¿Necesario?</th><th>Accesible desde</th>"
                f"<th>Proceso/usuario</th><th>Observaciones</th></tr>{''.join(rows)}</table>")
            if unneeded:
                out.append(
                    "<p><b>Servicios potencialmente innecesarios:</b> " + ", ".join(e(u) for u in unneeded)
                    + ". <b>Recomendación:</b> confirmar su necesidad con el propietario y, si no se usan, "
                    "deshabilitarlos o restringir su acceso por cortafuegos.</p>")
        return "".join(out)

    @staticmethod
    def _detail_cell(detail: str, limit: int = 220) -> str:
        detail = detail or ""
        if len(detail) <= limit:
            return e(detail)
        return f"{e(detail[:limit].rstrip())}&hellip; <span class='muted'>[resumido]</span>"

    NV_EXT = "Auditoría externa sin credenciales"

    @staticmethod
    def _agg_checks(t: Target, *keys: str) -> tuple[str, str]:
        """Agrega los checks observables cuyo nombre contiene alguna clave.

        Devuelve (estado Cumple/No cumple/Parcial/No verificado, evidencia)."""
        matched = [c for c in t.checks if any(k.lower() in c.name.lower() for k in keys)]
        if not matched:
            return "No verificado", "No evaluado en este escaneo."
        if any(c.status == "Hallazgo" for c in matched):
            state = "No cumple"
        elif all(c.status == "Correcto" for c in matched):
            state = "Cumple"
        elif any(c.status in ("Correcto",) for c in matched):
            state = "Parcial"
        else:
            state = "Informativo"
        ev = "; ".join(f"{c.name}: {c.detail}" for c in matched if c.detail)
        return state, (ev or "Ver sección 6.")

    def _ctrl_row(self, control: str, state: str, evidence: str, obs: str) -> str:
        return (f"<tr><td>{e(control)}</td><td>{e(state)}</td>"
                f"<td>{self._detail_cell(evidence, 260)}</td><td>{e(obs)}</td></tr>")

    def _s5_review(self) -> str:
        out = ["<h2>5. Revisión de configuración</h2>",
               "<p>Controles agrupados en seis categorías. En auditoría de caja negra, los controles "
               "internos no son verificables sin credenciales y se marcan como <b>No verificado</b> "
               "(motivo: auditoría externa sin credenciales). Estados: Cumple / No cumple / Parcial / "
               "No aplica / No verificado.</p>"]
        nv = self.NV_EXT
        for t in self.targets:
            out.append(f"<h3>Objetivo: {e(t.label)}</h3>")

            # 5.1 Cuentas y autenticación (interno -> no verificable externamente)
            out.append("<h4>5.1 Cuentas y autenticación</h4><table>"
                       "<tr><th style='width:24%'>Control</th><th>Estado</th>"
                       "<th>Evidencia</th><th>Observaciones</th></tr>"
                       + self._ctrl_row("Acceso SSH directo como root", "No verificado", nv,
                                        "Requiere leer sshd_config en el sistema.")
                       + self._ctrl_row("Política de contraseñas", "No verificado", nv, "")
                       + self._ctrl_row("Cuentas sin contraseña o inactivas", "No verificado", nv, "")
                       + self._ctrl_row("Usuarios con privilegios sudo", "No verificado", nv, "")
                       + self._ctrl_row("Autenticación multifactor (MFA)", "No verificado", nv, "")
                       + "</table>")

            # 5.2 Red y cortafuegos (parcialmente observable)
            abiertos = len([p for p in t.ports if p.state == "open"])
            out.append("<h4>5.2 Red y cortafuegos</h4><table>"
                       "<tr><th style='width:24%'>Control</th><th>Estado</th>"
                       "<th>Evidencia</th><th>Observaciones</th></tr>"
                       + self._ctrl_row("Estado y política del cortafuegos", "No verificado", nv,
                                        "No determinable con fiabilidad desde el exterior.")
                       + self._ctrl_row("Servicios escuchando expuestos", "Parcial",
                                        f"{abiertos} puertos abiertos accesibles desde la red (sección 4).",
                                        "Reducir la superficie expuesta a lo imprescindible.")
                       + self._ctrl_row("Configuración de IPv6", "No verificado", nv, "")
                       + self._ctrl_row("Reenvío de paquetes (ip_forward)", "No verificado", nv, "")
                       + "</table>")

            # 5.3 Sistema de archivos y permisos (interno)
            out.append("<h4>5.3 Sistema de archivos y permisos</h4><table>"
                       "<tr><th style='width:24%'>Control</th><th>Estado</th>"
                       "<th>Evidencia</th><th>Observaciones</th></tr>"
                       + self._ctrl_row("Permisos de ficheros sensibles", "No verificado", nv, "")
                       + self._ctrl_row("Archivos con escritura global", "No verificado", nv, "")
                       + self._ctrl_row("Opciones de montaje y particiones", "No verificado", nv, "")
                       + "</table>")

            # 5.4 Actualizaciones y parches (interno; observación por versiones expuestas)
            old = [f"{p.port}/{p.service} {p.banner}" for p in t.ports if p.banner]
            obs_upd = ("Se observan versiones antiguas expuestas (sección 6.2); el estado de parches "
                       "interno no es verificable sin acceso.") if old else nv
            out.append("<h4>5.4 Actualizaciones y parches</h4><table>"
                       "<tr><th style='width:24%'>Control</th><th>Estado</th>"
                       "<th>Evidencia</th><th>Observaciones</th></tr>"
                       + self._ctrl_row("Estado de actualizaciones del sistema", "No verificado", nv, obs_upd)
                       + self._ctrl_row("Parches de seguridad pendientes", "No verificado", nv, "")
                       + self._ctrl_row("Actualizaciones automáticas", "No verificado", nv, "")
                       + "</table>")

            # 5.5 Registros y copias de seguridad (interno)
            out.append("<h4>5.5 Registros y copias de seguridad</h4><table>"
                       "<tr><th style='width:24%'>Control</th><th>Estado</th>"
                       "<th>Evidencia</th><th>Observaciones</th></tr>"
                       + self._ctrl_row("Registro de eventos / centralización", "No verificado", nv, "")
                       + self._ctrl_row("Sincronización horaria (NTP)", "No verificado", nv, "")
                       + self._ctrl_row("Copias de seguridad verificadas", "No verificado", nv, "")
                       + "</table>")

            # 5.6 Seguridad de servicios (observable -> se rellena con el escaneo)
            s_ver, e_ver = ("No cumple", "Banners de versión expuestos en los servicios (sección 4/6).") \
                if any(p.banner for p in t.ports) else ("No verificado", "")
            s_tls, e_tls = self._agg_checks(t, "TLS/SSL")
            s_hdr, e_hdr = self._agg_checks(t, "Cabeceras de seguridad")
            s_met, e_met = self._agg_checks(t, "Metodos HTTP", "Métodos HTTP")
            s_ftp, e_ftp = self._agg_checks(t, "FTP anonimo", "FTP anónimo")
            s_pan, e_pan = self._agg_checks(t, "Rutas/paneles")
            out.append("<h4>5.6 Seguridad de servicios</h4><table>"
                       "<tr><th style='width:24%'>Control</th><th>Estado</th>"
                       "<th>Evidencia</th><th>Observaciones</th></tr>"
                       + self._ctrl_row("Exposición de versiones", s_ver, e_ver,
                                        "Ocultar banners de versión donde sea posible.")
                       + self._ctrl_row("Configuración TLS", s_tls, e_tls, "")
                       + self._ctrl_row("Cabeceras HTTP de seguridad", s_hdr, e_hdr, "")
                       + self._ctrl_row("Métodos HTTP peligrosos", s_met, e_met, "")
                       + self._ctrl_row("Acceso anónimo FTP", s_ftp, e_ftp, "")
                       + self._ctrl_row("Exposición de paneles administrativos", s_pan, e_pan, "")
                       + "</table>")
        return "".join(out)

    def _s6_vulnerabilities(self) -> str:
        out = ["<h2>6. Vulnerabilidades y hallazgos</h2>"]
        findings = self.all_findings()
        if not findings:
            out.append("<p class='muted'>No se identificaron hallazgos.</p>")
            return "".join(out)

        config = [f for f in findings if f.confirmed]
        cve_f = [f for f in findings if not f.confirmed]
        out.append(
            f"<p><b>{len(config)} hallazgos de configuración confirmados</b> (verificados desde la red) y "
            f"<b>{len(cve_f)} posibles vulnerabilidades</b> asociadas automáticamente por versión "
            "(pendientes de validación). Ambos conjuntos se presentan por separado y no se suman.</p>")

        # ---- 6.1 Hallazgos CONFIRMADOS (configuración) ----
        out.append("<h3>6.1 Hallazgos de configuración (confirmados)</h3>")
        if not config:
            out.append("<p class='muted'>Sin hallazgos de configuración observable.</p>")
        else:
            # Tabla resumen de los principales
            srows = "".join(
                f"<tr><td>{e(f.fid)}</td><td>{e(f.title)}</td><td>{e(f.component)}</td>"
                f"<td>{self._sev_badge(f.severity)}</td>"
                f"<td>{e(SEVERITY_PRIORITY.get(f.severity, 'P3'))}</td></tr>"
                for f in config)
            out.append("<h4>Tabla resumen</h4>"
                       "<table><tr><th>ID</th><th>Hallazgo</th><th>Componente</th>"
                       f"<th>Severidad</th><th>Prioridad</th></tr>{srows}</table>")
            out.append("<h4>Fichas de hallazgo</h4>")
            for f in config:
                out.append(
                    f"<div class='finding' style='border-left-color:{SEV_COLOR.get(f.severity, '#888')}'>"
                    f"<b>{e(f.fid)} &middot; {e(f.title)}</b> {self._sev_badge(f.severity)} "
                    f"<span class='muted'>[{e(SEVERITY_PRIORITY.get(f.severity, 'P3'))}]</span><br>"
                    f"<b>Componente:</b> {e(f.component)}<br>"
                    f"<b>Descripción:</b> {e(f.description)}<br>"
                    f"<b>Herramienta de detección:</b> nmap &nbsp;|&nbsp; "
                    f"<b>Evidencia:</b> {e(f.evidence)}<br>"
                    f"<b>Severidad:</b> {e(f.severity)} &nbsp;|&nbsp; "
                    f"<b>Probabilidad:</b> {e(f.probability)} &nbsp;|&nbsp; "
                    f"<b>Impacto:</b> {e(f.impact)} &nbsp;|&nbsp; "
                    f"<b>Exploit público:</b> No verificado<br>"
                    f"<b>Estado:</b> Confirmado (observado en la red)<br>"
                    f"<b>Recomendación:</b> {e(f.recommendation)}"
                    "</div>")

        # ---- 6.2 Posibles vulnerabilidades por versión (CVE) ----
        out.append("<h3>6.2 Posibles vulnerabilidades por versión (CVE)</h3>")
        if not cve_f:
            out.append("<p class='muted'>Sin CVE emparejadas por versión.</p>")
            return "".join(out)

        groups = self._group_cves_by_component(cve_f)
        out.append(
            f"<p><b>Posibles vulnerabilidades detectadas automáticamente, pendientes de validación.</b> "
            f"Se emparejaron <b>{sum(len(g['cves']) for g in groups)} CVE</b> por versión en "
            f"<b>{len(groups)} componentes</b> mediante <i>nmap vulners</i>. Una coincidencia banner&rarr;CVE "
            "no confirma que el equipo sea vulnerable: deben validarse manualmente en NVD. "
            "El estado de todas ellas es <b>Posible (sin validar)</b>, nunca «Confirmada».</p>")
        rows = []
        for g in groups:
            top = " ".join(
                f"<a href='https://nvd.nist.gov/vuln/detail/{c}'>{e(c)}</a>"
                f"<span class='muted'>({cv:.1f})</span>"
                for c, cv in g["top"])
            extra = f" <span class='muted'>+{len(g['cves']) - len(g['top'])} más</span>" \
                if len(g["cves"]) > len(g["top"]) else ""
            rows.append(
                f"<tr><td>{e(g['component'])}</td>"
                f"<td style='text-align:center'>{len(g['cves'])}</td>"
                f"<td style='text-align:center'>{g['max_cvss']:.1f}</td>"
                f"<td>{self._sev_badge(g['severity'])}</td>"
                f"<td>Posible (sin validar)</td>"
                f"<td>{top}{extra}</td></tr>")
        out.append(
            "<table><tr><th>Componente / versión</th><th>CVE</th><th>CVSS máx</th>"
            "<th>Severidad</th><th>Estado</th><th>CVE destacadas (NVD)</th></tr>"
            f"{''.join(rows)}</table>")
        # Nota sobre mismo componente en varios puertos
        multi = self._same_component_multi_port(cve_f)
        if multi:
            out.append("<p class='muted'><b>Nota:</b> un mismo componente aparece expuesto en varios "
                       "puertos (" + "; ".join(e(m) for m in multi) + "), por lo que sus CVE se repiten. "
                       "Al corregir el componente se resuelven todas sus instancias.</p>")
        out.append("<p class='muted'>Listado completo de CVE por componente en el anexo 10.2. "
                   "CVSS proporcionado automáticamente por <i>vulners</i>; exploit público: No verificado.</p>")
        return "".join(out)

    @staticmethod
    def _same_component_multi_port(cve_f: list[Finding]) -> list[str]:
        base: dict[str, set] = {}
        for f in cve_f:
            root = re.sub(r"\s*\(puerto\s*\d+\)", "", f.component).strip()
            m = re.search(r"puerto\s*(\d+)", f.component)
            if m:
                base.setdefault(root, set()).add(m.group(1))
        return [f"{k}: puertos {', '.join(sorted(v, key=int))}"
                for k, v in base.items() if len(v) > 1]

    @staticmethod
    def _group_cves_by_component(cve_f: list[Finding]) -> list[dict]:
        groups: dict[str, dict] = {}
        for f in cve_f:
            g = groups.setdefault(f.component, {
                "component": f.component, "cves": [], "max_cvss": 0.0, "severity": "Informativa"})
            g["cves"].append((f.cve.upper(), f.cvss))
            if f.cvss > g["max_cvss"]:
                g["max_cvss"] = f.cvss
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(g["severity"], 0):
                g["severity"] = f.severity
        for g in groups.values():
            # dedup CVEs conservando el CVSS mas alto, orden por CVSS desc
            best: dict[str, float] = {}
            for c, cv in g["cves"]:
                if c not in best or cv > best[c]:
                    best[c] = cv
            g["cves"] = sorted(best.items(), key=lambda x: -x[1])
            g["top"] = g["cves"][:5]
        return sorted(groups.values(), key=lambda x: -x["max_cvss"])

    def _s7_executive(self) -> str:
        confirmed = self.confirmed_findings()
        potential = self.potential_findings()
        counts = self.severity_counts(confirmed)          # KPIs = solo confirmados
        kpis = "".join(
            f"<div class='kpi' style='background:{SEV_COLOR[s]}'>"
            f"<span class='n'>{counts.get(s, 0)}</span><span class='l'>{e(s)}</span></div>"
            for s in ("Critica", "Alta", "Media", "Baja", "Informativa"))
        risk, prisk = self.global_risk(), self.potential_risk()

        # Top-3 confirmados SIN repetir el mismo tipo de problema (por raiz del titulo).
        top, seen = [], set()
        for f in confirmed:
            key = re.sub(r"\s*\(\d+\)|\s*\d+", "", f.title).strip().lower()
            if key in seen:
                continue
            seen.add(key)
            top.append(f)
            if len(top) == 3:
                break
        top_html = "".join(
            f"<li>{e(f.title)} ({self._sev_badge(f.severity)})</li>" for f in top) \
            or "<li>Sin hallazgos de configuración confirmados.</li>"

        # Causas, positivos
        causas = []
        if any("sin cifrar" in f.title.lower() for f in confirmed):
            causas.append("servicios que transmiten en texto claro")
        if any("ftp" in f.title.lower() for f in confirmed):
            causas.append("acceso anónimo FTP")
        if any("tls" in f.title.lower() for f in confirmed):
            causas.append("configuración TLS/SSL débil")
        if potential:
            causas.append("software en versiones antiguas con múltiples CVE asociadas")
        causas_txt = ", ".join(causas) or "debilidades de configuración observables"

        positivos = []
        tls_ok = any(c.status == "Correcto" and "TLS" in c.name for t in self.targets for c in t.checks)
        if tls_ok:
            positivos.append("parte de los servicios TLS presentan configuración correcta")
        if any(p.has_tls for t in self.targets for p in t.ports):
            positivos.append("los servicios web sobre 443/8443/9443 usan cifrado TLS")
        positivos_txt = "; ".join(positivos) or "no se identificaron fortalezas destacables"

        per_target = []
        for t in self.targets:
            cc = self.severity_counts([f for f in t.findings if f.confirmed])
            pc = len([f for f in t.findings if not f.confirmed])
            resumen = ", ".join(f"{cc[s]} {s.lower()}" for s in ("Critica", "Alta", "Media", "Baja") if cc[s])
            per_target.append(
                f"<li><b>{e(t.label)}:</b> {e(resumen) if resumen else 'sin hallazgos confirmados relevantes'}; "
                f"{pc} posibles CVE pendientes de validación.</li>")

        return (
            "<h2>7. Resumen ejecutivo</h2>"
            f"<p><b>Conclusión.</b> El equipo auditado presenta un riesgo <b>confirmado "
            f"<span class='risk' style='background:{RISK_COLOR.get(risk, '#64748b')}'>{e(risk)}</span></b>, "
            f"derivado de {e(causas_txt)}. Si se validaran las CVE asociadas por versión, el riesgo potencial "
            f"ascendería a <b>{e(prisk)}</b>. La prioridad inmediata es eliminar los servicios en texto claro "
            "y el acceso anónimo, y actualizar el software expuesto.</p>"
            f"<p><b>Cómo se cuentan los hallazgos:</b> {len(confirmed)} hallazgos de configuración "
            f"<b>confirmados</b> (los KPIs de abajo) y {len(potential)} <b>posibles</b> CVE por versión "
            "(sección 6.2), que no se contabilizan como confirmadas.</p>"
            "<p class='muted'>KPIs = hallazgos de configuración confirmados por severidad.</p>"
            f"<div class='kpibar'>{kpis}</div>"
            "<h3>Principales puntos (confirmados)</h3><ul>" + top_html + "</ul>"
            f"<h3>Qué corregir primero</h3><p>{e(causas_txt.capitalize())}. "
            "Empezar por los hallazgos P1 de la sección 8.</p>"
            f"<h3>Aspectos positivos</h3><p>{positivos_txt.capitalize()}.</p>"
            "<h3>Resumen por objetivo</h3><ul>" + "".join(per_target) + "</ul>")

    @staticmethod
    def _temp_mitigation(rec: str) -> str:
        r = rec.lower()
        if "anonimo" in r or "anónimo" in r or "ftp" in r:
            return "Restringir el puerto por cortafuegos hasta deshabilitar el acceso."
        if "ssl" in r or "tls" in r:
            return "Limitar el acceso a redes de confianza mientras se reconfigura TLS."
        if "cifrado" in r or "ssh/https" in r:
            return "Permitir el servicio solo desde IP autorizadas por cortafuegos."
        if "actualizar" in r:
            return "Aislar el servicio o filtrar su acceso hasta aplicar la actualización."
        if "metodo" in r or "método" in r:
            return "Bloquear los métodos en el proxy/WAF si existe."
        if "cabecera" in r:
            return "Añadir las cabeceras en el proxy inverso si lo hay."
        return "Restringir el acceso por cortafuegos mientras se corrige."

    def _s8_remediation(self) -> str:
        # Agrupar por accion recomendada: colapsa cientos de CVE en pocas acciones.
        actions: dict[str, dict] = {}
        for f in self.all_findings():
            rec = f.recommendation or f.title
            comp = re.sub(r"\s*\(puerto\s*\d+\)", "", f.component).strip()
            a = actions.setdefault(rec, {"rec": rec, "comps": set(), "fids": [],
                                         "severity": "Informativa"})
            a["comps"].add(comp)
            if f.confirmed:                      # enlazamos IDs de hallazgos confirmados
                a["fids"].append(f.fid)
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(a["severity"], 0):
                a["severity"] = f.severity
        ordered = sorted(actions.values(), key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0))
        rows = []
        for i, a in enumerate(ordered, 1):
            sev = a["severity"]
            dl = (self.now + _dt.timedelta(days=SEVERITY_DEADLINE.get(sev, 90))).strftime("%Y-%m-%d")
            rel = ", ".join(sorted(set(a["fids"]))) if a["fids"] else \
                f"CVE por versión ({', '.join(sorted(a['comps']))})"
            rows.append(
                f"<tr><td>R{i:02d}</td><td>{e(rel)}</td><td>{e(a['rec'])}</td>"
                f"<td>{e(SEVERITY_PRIORITY.get(sev, 'P3'))} {self._sev_badge(sev)}</td>"
                f"<td>{e(self._temp_mitigation(a['rec']))}</td>"
                f"<td>Pendiente de asignación</td>"
                f"<td>{e(SEVERITY_EFFORT.get(sev, 'Medio'))}</td>"
                f"<td>{dl}</td><td>Pendiente</td></tr>")
        body = "".join(rows) or "<tr><td colspan='9' class='muted'>Sin acciones pendientes.</td></tr>"
        return (
            "<h2>8. Plan de remediación</h2>"
            "<p>Acciones agrupadas por medida correctiva, priorizadas por gravedad y exposición. "
            "Criterios: <b>P1</b> inmediata (0&ndash;7 días), <b>P2</b> corto plazo (&le;30 días), "
            "<b>P3</b> medio plazo (&le;90 días), <b>P4</b> buenas prácticas.</p>"
            "<table><tr><th>ID</th><th>Hallazgo relacionado</th><th>Acción correctiva</th>"
            "<th>Prioridad</th><th>Mitigación temporal</th><th>Responsable</th><th>Esfuerzo</th>"
            f"<th>Fecha límite</th><th>Estado</th></tr>{body}</table>")

    def _s9_methodology(self) -> str:
        tools = "".join(
            f"<tr><td>{e(r.when)}</td><td><code>{e(r.cmd)}</code></td>"
            f"<td>{e(str(r.rc))}{(' - ' + e(r.note)) if r.note else ''}</td></tr>"
            for r in self.runner.log)
        ini, fin = self.scan_window()
        return (
            "<h2>9. Metodología y herramientas</h2>"
            "<p>Marco de referencia: <b>PTES</b> (Penetration Testing Execution Standard) y "
            "<b>OWASP Testing Guide</b> para la parte web. Herramienta única: <b>nmap "
            f"{e(self.env.nmap_version or 'desconocida')}</b> (no se emplearon otras).</p>"
            "<h3>Fases de la auditoría</h3><ul>"
            "<li><b>Reconocimiento:</b> descubrimiento de host vivo (<code>nmap -sn</code>) e "
            "identificación básica (IP, MAC, fabricante, DNS inverso).</li>"
            "<li><b>Enumeración:</b> escaneo de puertos y detección de servicios/versiones "
            "(<code>nmap -sV -O</code>) y de la configuración observable (TLS, cabeceras, métodos HTTP, "
            "FTP anónimo).</li>"
            "<li><b>Análisis:</b> asociación automática de CVE por versión (<code>--script vulners</code>) "
            "y priorización por severidad. La validación de esas CVE es manual y queda fuera del alcance.</li>"
            "</ul>"
            "<p><b>Resultados automáticos vs validados:</b> los hallazgos de configuración (sección 6.1) "
            "están <b>confirmados</b> por observación directa. Las CVE (sección 6.2) son <b>automáticas, "
            "sin validar</b>: proceden de emparejar el banner de versión con bases de CVE.</p>"
            "<p><b>Limitaciones de la herramienta:</b> <i>vulners</i> empareja por versión y puede generar "
            "falsos positivos; no comprueba parches retroportados (backports) ni mitigaciones aplicadas. "
            "La estimación de SO (<code>-O</code>) es aproximada.</p>"
            "<p><b>Declaración:</b> NO se realiza explotación de vulnerabilidades. El trabajo se limita a "
            "descubrimiento, enumeración, identificación de versiones y configuración observable desde la red.</p>"
            f"<p><b>Ventana de ejecución registrada:</b> {e(ini)} &rarr; {e(fin)} (coincide con las horas "
            "de los comandos de la tabla siguiente).</p>"
            "<h3>Comandos ejecutados</h3>"
            "<table><tr><th>Hora</th><th>Comando</th><th>Resultado</th></tr>"
            f"{tools}</table>")

    def _s10_annexes(self) -> str:
        auditor = self.cfg.auditor.strip() or "No especificado"
        resp = self.cfg.propietario.strip() or "Pendiente de asignación"
        out = ["<h2>10. Anexos, evidencias y firmas</h2>",
               "<p class='muted'>Se incluyen exclusivamente evidencias reales obtenidas en el escaneo. "
               "Cuando no se dispone de una salida, se indica que no está disponible.</p>"]

        # 10.1 Evidencias de Nmap (salida real; recortada en PDF)
        out.append("<h3>10.1 Evidencias de Nmap</h3>"
                   "<p class='muted'>Relacionado con las secciones 3, 4 y 6.</p>")
        any_raw = False
        for t in self.targets:
            raw = (t.raw_nmap or "").strip()
            if not raw:
                continue
            any_raw = True
            snippet = raw if len(raw) <= 3500 else raw[:3500] + "\n[...recortado; salida completa guardada con -oA...]"
            out.append(f"<h4>{e(t.label)}</h4><pre>{e(snippet)}</pre>")
        if not any_raw:
            out.append("<p class='muted'>Salida cruda de Nmap no disponible en esta ejecución.</p>")

        # 10.2 Listado de CVE por componente
        cve_groups = self._group_cves_by_component(
            [f for t in self.targets for f in t.findings if not f.confirmed])
        out.append("<h3>10.2 Listado de CVE por componente</h3>"
                   "<p class='muted'>Relacionado con la sección 6.2. Posibles, sin validar.</p>")
        if cve_groups:
            for g in cve_groups:
                ids = ", ".join(
                    f"<a href='https://nvd.nist.gov/vuln/detail/{c}'>{e(c)}</a>"
                    for c, _ in g["cves"])
                out.append(f"<h4>{e(g['component'])} ({len(g['cves'])} CVE)</h4>"
                           f"<p style='font-size:8.6px'>{ids}</p>")
        else:
            out.append("<p class='muted'>Sin CVE asociadas.</p>")

        # 10.3 Evidencias de configuración TLS
        out.append("<h3>10.3 Evidencias de configuración TLS</h3>"
                   "<p class='muted'>Relacionado con la sección 5.6 y 6.1.</p>")
        tls_rows = "".join(
            f"<tr><td>{e(t.label)}</td><td>{e(c.name)}</td><td>{e(c.status)}</td>"
            f"<td>{self._detail_cell(c.detail, 400)}</td></tr>"
            for t in self.targets for c in t.checks if "TLS" in c.name)
        out.append(f"<table><tr><th>Objetivo</th><th>Control</th><th>Estado</th><th>Evidencia</th></tr>"
                   f"{tls_rows or '<tr><td colspan=4 class=muted>Sin evidencias TLS.</td></tr>'}</table>")

        # 10.4 Evidencias de servicios y puertos
        out.append("<h3>10.4 Evidencias de servicios y puertos</h3>"
                   "<p class='muted'>Relacionado con la sección 4.</p>")
        for t in self.targets:
            prows = "".join(
                f"<tr><td>{p.port}/{e(p.proto)}</td><td>{e(p.service or '-')}</td>"
                f"<td>{e(p.banner or '-')}</td><td>{e(p.encryption)}</td></tr>"
                for p in sorted(t.ports, key=lambda x: x.port))
            out.append(f"<h4>{e(t.label)}</h4><table><tr><th>Puerto</th><th>Servicio</th>"
                       f"<th>Banner</th><th>Cifrado</th></tr>{prows}</table>")

        # 10.5 Hardening local (si --self)
        if self.self_t:
            out.append("<h3>10.5 Hardening local de la plataforma (Kali)</h3>")
            rows = "".join(
                f"<tr><td>{e(c.name)}</td><td>{e(c.status)}</td><td>{e(c.detail)}</td></tr>"
                for c in self.self_t.checks)
            out.append(f"<table><tr><th>Control</th><th>Estado</th><th>Detalle</th></tr>{rows}</table>")

        # 10.6 Control de versiones y firmas
        out.append("<h3>10.5 Control de versiones del documento</h3>"
                   if not self.self_t else "<h3>10.6 Control de versiones del documento</h3>")
        out.append(f"<table><tr><th>Versión</th><th>Fecha</th><th>Estado</th><th>Descripción</th></tr>"
                   f"<tr><td>1.0</td><td>{e(self.now.strftime('%Y-%m-%d'))}</td><td>{e(self.cfg.estado)}</td>"
                   f"<td>Emisión inicial del informe {e(self.code)}.</td></tr></table>")
        out.append("<h3>Firmas y revisión</h3>"
                   "<table><tr><th>Auditor</th><th>Responsable del activo / laboratorio</th></tr>"
                   f"<tr><td>{e(auditor)}<br>Fecha: {e(self.now.strftime('%Y-%m-%d'))}"
                   "<br><br>Firma: ________________</td>"
                   f"<td>{e(resp)}<br>Fecha: ____________"
                   "<br><br>Firma: ________________</td></tr></table>")
        return "".join(out)


# --------------------------------------------------------------------------- #
# Exportacion PDF / docx
# --------------------------------------------------------------------------- #
def export_pdf(html_path: str, pdf_path: str, engine: Optional[str], runner: Runner) -> bool:
    if engine is None:
        return False
    try:
        if engine == "weasyprint":
            import weasyprint  # type: ignore
            weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
            return os.path.exists(pdf_path)
        if engine == "wkhtmltopdf":
            cp = runner.run(["wkhtmltopdf", "--enable-local-file-access", html_path, pdf_path], timeout=300)
            return cp.returncode == 0 and os.path.exists(pdf_path)
        # chromium/chrome headless
        cp = runner.run([engine, "--headless", "--no-sandbox", "--disable-gpu",
                         f"--print-to-pdf={pdf_path}", "--print-to-pdf-no-header",
                         f"file://{os.path.abspath(html_path)}"], timeout=300)
        return cp.returncode == 0 and os.path.exists(pdf_path)
    except Exception as exc:  # degradar sin romper
        print(f"[!] No se pudo generar el PDF ({engine}): {exc}")
        return False


def export_docx(report: ReportBuilder, docx_path: str) -> bool:
    try:
        from docx import Document  # type: ignore
        from docx.shared import Pt
    except Exception:
        print("[!] python3-docx no disponible: se omite el .docx.")
        return False
    try:
        doc = Document()
        doc.add_heading("Informe de auditoría de seguridad externa", 0)
        doc.add_paragraph(f"Código: {report.code}  -  Fecha: {report.now.strftime('%Y-%m-%d %H:%M')}")
        doc.add_paragraph(f"Auditor: {report.cfg.auditor.strip() or 'No especificado'}  -  "
                          f"Estado: {report.cfg.estado}")
        doc.add_paragraph(f"Autorización: {report.cfg.auth}")
        doc.add_paragraph(f"Riesgo confirmado: {report.global_risk()}  -  "
                          f"Riesgo potencial (si se validan CVE): {report.potential_risk()}")

        findings = report.all_findings()
        config = [f for f in findings if f.confirmed]
        cve_f = [f for f in findings if not f.confirmed]

        doc.add_heading("Resumen por severidad (hallazgos confirmados)", level=1)
        counts = report.severity_counts(config)
        for s in ("Critica", "Alta", "Media", "Baja", "Informativa"):
            doc.add_paragraph(f"{s}: {counts.get(s, 0)}", style="List Bullet")
        doc.add_paragraph(f"Posibles CVE por versión (sin validar): {len(cve_f)}", style="List Bullet")

        for t in report.targets:
            doc.add_heading(f"Objetivo: {t.label}", level=1)
            doc.add_paragraph(f"IP: {t.ip or '-'}  DNS: {t.reverse_dns or '-'}  "
                              f"MAC: {t.mac or '-'} ({t.vendor or '-'})  SO estimado: {t.os_guess or '-'}")
            if t.ports:
                table = doc.add_table(rows=1, cols=4)
                hdr = table.rows[0].cells
                hdr[0].text, hdr[1].text, hdr[2].text, hdr[3].text = "Puerto", "Servicio", "Versión", "Cifrado"
                for p in sorted(t.ports, key=lambda x: x.port):
                    c = table.add_row().cells
                    c[0].text = f"{p.port}/{p.proto}"
                    c[1].text = p.service or "-"
                    c[2].text = (f"{p.product} {p.version}".strip()) or "-"
                    c[3].text = p.encryption

        doc.add_heading("Hallazgos de configuración (confirmados)", level=1)
        if not config:
            doc.add_paragraph("Sin hallazgos de configuración observable.")
        for f in config:
            doc.add_heading(f"{f.fid} - {f.title} [{f.severity} / {SEVERITY_PRIORITY.get(f.severity,'P3')}]", level=2)
            doc.add_paragraph(f"Componente: {f.component}")
            doc.add_paragraph(f"Descripción: {f.description}")
            doc.add_paragraph(f"Evidencia (nmap): {f.evidence}")
            doc.add_paragraph(f"Probabilidad: {f.probability}  -  Impacto: {f.impact}  -  "
                              f"Exploit público: No verificado")
            doc.add_paragraph(f"Estado: Confirmado  -  Recomendación: {f.recommendation}")

        doc.add_heading("Posibles vulnerabilidades por versión (CVE) - sin validar", level=1)
        doc.add_paragraph("Asociaciones automáticas por versión (nmap vulners), pendientes de "
                          "validación en NVD. Estado: Posible (sin validar).")
        groups = ReportBuilder._group_cves_by_component(cve_f)
        if not groups:
            doc.add_paragraph("Sin CVE emparejadas por versión.")
        else:
            table = doc.add_table(rows=1, cols=5)
            hdr = table.rows[0].cells
            for j, h in enumerate(("Componente", "CVE", "CVSS max", "Severidad", "Destacadas")):
                hdr[j].text = h
            for g in groups:
                c = table.add_row().cells
                c[0].text = g["component"]
                c[1].text = str(len(g["cves"]))
                c[2].text = f"{g['max_cvss']:.1f}"
                c[3].text = g["severity"]
                c[4].text = ", ".join(cv for cv, _ in g["top"])

        doc.add_heading("Plan de remediacion", level=1)
        acts: dict = {}
        for f in findings:
            rec = f.recommendation or f.title
            comp = re.sub(r"\s*\(puerto\s*\d+\)", "", f.component).strip()
            a = acts.setdefault(rec, {"rec": rec, "comps": set(), "sev": "Informativa"})
            a["comps"].add(comp)
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(a["sev"], 0):
                a["sev"] = f.severity
        rt = doc.add_table(rows=1, cols=4)
        rh = rt.rows[0].cells
        for j, h in enumerate(("Accion", "Componentes", "Prioridad", "Severidad")):
            rh[j].text = h
        for a in sorted(acts.values(), key=lambda x: -SEVERITY_ORDER.get(x["sev"], 0)):
            c = rt.add_row().cells
            c[0].text = a["rec"]
            c[1].text = ", ".join(sorted(a["comps"]))
            c[2].text = SEVERITY_PRIORITY.get(a["sev"], "P3")
            c[3].text = a["sev"]

        doc.save(docx_path)
        return os.path.exists(docx_path)
    except Exception as exc:
        print(f"[!] No se pudo generar el .docx: {exc}")
        return False


# --------------------------------------------------------------------------- #
# Orquestacion
# --------------------------------------------------------------------------- #
def resolve_targets(runner: Runner, cfg: Config) -> list[Target]:
    targets: list[Target] = []
    if cfg.targets:
        for tok in cfg.targets:
            if "/" in tok:  # CIDR -> descubrimiento
                print(f"[*] Descubrimiento en {tok} ...")
                targets.extend(discover_hosts(runner, tok, cfg.timing))
            else:
                t = Target(host=tok)
                if host_is_up(runner, tok, cfg.timing):
                    t.alive = True
                else:
                    t.alive = False
                    t.note = "El objetivo no respondio a la fase de descubrimiento."
                targets.append(t)
    else:
        print("[*] Sin -t: autodetectando red local ...")
        for cidr in local_cidrs(runner):
            print(f"[*] Descubrimiento en {cidr} ...")
            targets.extend(discover_hosts(runner, cidr, cfg.timing))
    # Dedup por IP
    seen: set[str] = set()
    uniq: list[Target] = []
    for t in targets:
        key = t.ip or t.host
        if key in seen:
            continue
        seen.add(key)
        uniq.append(t)
    return uniq


def output_dir(cfg: Config) -> str:
    stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M")
    if cfg.out_base:
        base = os.path.dirname(os.path.abspath(cfg.out_base)) or "."
        name = os.path.basename(cfg.out_base)
        d = os.path.join(base, f"{name}_{stamp}")
    else:
        d = os.path.join(os.getcwd(), f"auditoria_{stamp}")
    os.makedirs(d, exist_ok=True)
    return d


def main(argv: Optional[list[str]] = None) -> int:
    cfg = parse_args(argv)
    runner = Runner()

    print("[*] Comprobaciones previas de entorno ...")
    env = check_environment(runner, cfg.vulners)
    for w in env.warnings:
        print(f"    [!] {w}")
    if not env.nmap_ok:
        print("[X] nmap es imprescindible. Instala con: sudo apt install nmap")
        return 2

    targets = resolve_targets(runner, cfg)
    if not targets and not cfg.self_audit:
        print("[X] No se encontraron objetivos que auditar.")
        return 3

    scanner = Scanner(runner, cfg, env)
    for t in targets:
        if not t.alive:
            print(f"[!] {t.label}: no responde, se incluye como no disponible.")
            continue
        print(f"[*] Escaneando {t.label} ...")
        scanner.scan(t)
        derive_observable_checks(t)
        dedupe_target(t)
        assign_finding_ids(t)

    self_t = None
    if cfg.self_audit:
        print("[*] Auditando hardening local de la Kali (--self) ...")
        self_t = self_audit(runner)

    # Si --self, lo anadimos como objetivo adicional al final.
    report_targets = targets + ([self_t] if self_t else [])
    report = ReportBuilder(cfg, env, runner, report_targets, self_t)
    html_doc = report.build()

    outdir = output_dir(cfg)
    base = os.path.join(outdir, os.path.basename(cfg.out_base) if cfg.out_base else "informe")
    html_path = base + ".html"
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    print(f"[OK] HTML: {html_path}")

    if cfg.nmap_dir:
        print(f"[OK] Salidas nmap en: {cfg.nmap_dir}")

    if "pdf" in cfg.formatos:
        pdf_path = base + ".pdf"
        if export_pdf(html_path, pdf_path, env.pdf_engine, runner):
            print(f"[OK] PDF: {pdf_path}")
        else:
            print("[!] PDF no generado. Abre el HTML e imprime a PDF desde el navegador.")

    if "docx" in cfg.formatos:
        docx_path = base + ".docx"
        if export_docx(report, docx_path):
            print(f"[OK] DOCX: {docx_path}")

    print(f"[*] Auditoria finalizada. Riesgo global: {report.global_risk()}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
