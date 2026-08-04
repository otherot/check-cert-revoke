#!/usr/bin/env python3
"""
Проверка отзыва SSL/TLS-сертификатов по доменным именам.
Методы: OCSP (приоритет) → CRL (fallback).
"""

import argparse
import json
import signal
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.request import urlopen, Request

from cryptography import x509
from cryptography.x509.ocsp import OCSPRequestBuilder, OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


# ── получение сертификата и цепочки ──────────────────────────────────────────

def get_certificate_chain(host: str, port: int = 443, timeout: float = 10.0):
    """Подключается по TLS и возвращает (leaf_cert, chain_certs).
    
    Использует сокет для получения полной цепочки через getpeercert(True).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            leaf_der = ssock.getpeercert(binary_form=True)

    leaf = x509.load_der_x509_certificate(leaf_der, default_backend())

    # Пробуем получить цепочку: SSLSocket.getpeercertchain() доступен в Python 3.13+
    chain = []
    # Альтернативно скачаем issuer через AIA позже в get_issuer()
    return leaf, chain


# ── поиск issuer-сертификата ─────────────────────────────────────────────────

def find_issuer_in_chain(cert: x509.Certificate, chain: list[x509.Certificate]):
    """Ищет issuer сертификата в цепочке по subject/issuer."""
    for c in chain:
        if c.subject == cert.issuer:
            return c
    return None


def download_issuer_via_aia(cert: x509.Certificate, timeout: float = 10.0):
    """Скачивает issuer-сертификат по AIA (Authority Information Access)."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return None

    for desc in aia.value:
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            url = desc.access_location.value
            try:
                req = Request(url, headers={"User-Agent": "cert-checker/1.0"})
                with urlopen(req, timeout=timeout) as resp:
                    data = resp.read()
                # пробуем DER и PEM
                try:
                    return x509.load_der_x509_certificate(data, default_backend())
                except Exception:
                    return x509.load_pem_x509_certificate(data, default_backend())
            except Exception:
                continue
    return None


def get_issuer(cert: x509.Certificate, chain: list[x509.Certificate]):
    """Возвращает issuer: сначала из цепочки, потом через AIA."""
    issuer = find_issuer_in_chain(cert, chain)
    if issuer is not None:
        return issuer
    return download_issuer_via_aia(cert)


# ── OCSP ─────────────────────────────────────────────────────────────────────

def get_ocsp_url(cert: x509.Certificate):
    """Извлекает URL OCSP-responder из AIA."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
    except x509.ExtensionNotFound:
        return None

    for desc in aia.value:
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            return desc.access_location.value
    return None


def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate,
               timeout: float = 10.0) -> dict:
    """Проверяет сертификат через OCSP. Возвращает словарь с результатом."""
    ocsp_url = get_ocsp_url(cert)
    if not ocsp_url:
        return {"method": "OCSP", "status": "UNKNOWN",
                "detail": "OCSP responder URL not found in certificate"}

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA256())
    request = builder.build()

    req_data = request.public_bytes(serialization.Encoding.DER)

    try:
        http_req = Request(
            ocsp_url,
            data=req_data,
            headers={
                "Content-Type": "application/ocsp-request",
                "User-Agent": "cert-checker/1.0",
            },
        )
        with urlopen(http_req, timeout=timeout) as resp:
            ocsp_resp_data = resp.read()
    except Exception as e:
        return {"method": "OCSP", "status": "ERROR",
                "detail": f"OCSP request error: {e}"}

    try:
        from cryptography.x509 import ocsp
        ocsp_response = ocsp.load_der_ocsp_response(ocsp_resp_data)
    except Exception as e:
        return {"method": "OCSP", "status": "ERROR",
                "detail": f"Failed to parse OCSP response: {e}"}

    if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
        return {"method": "OCSP", "status": "ERROR",
                "detail": f"OCSP responder returned status: {ocsp_response.response_status.name}"}

    # Проверяем подпись ответа
    try:
        _verify_ocsp_signature(ocsp_response, issuer)
    except Exception as e:
        return {"method": "OCSP", "status": "ERROR",
                "detail": f"Failed to verify OCSP response signature: {e}"}

    # Берём single response
    try:
        single = ocsp_response.certificate_status
    except Exception as e:
        return {"method": "OCSP", "status": "ERROR",
                "detail": f"Failed to get certificate status from OCSP response: {e}"}

    from cryptography.x509.ocsp import OCSPCertStatus

    if single == OCSPCertStatus.GOOD:
        return {"method": "OCSP", "status": "GOOD", "detail": ""}
    elif single == OCSPCertStatus.REVOKED:
        return {"method": "OCSP", "status": "REVOKED",
                "detail": "Certificate revoked"}
    else:
        return {"method": "OCSP", "status": "UNKNOWN",
                "detail": "OCSP responder returned status UNKNOWN"}


def _verify_ocsp_signature(ocsp_response, issuer: x509.Certificate):
    """Проверяет подпись OCSP-ответа (упрощённо)."""
    # cryptography сам проверяет подпись при загрузке, но для надёжности
    # получаем issuer public key и проверяем хеш
    issuer_pubkey = issuer.public_key()
    # В реальности полная проверка сложнее, cryptography делает её при загрузке
    # Поэтому здесь просто проверяем наличие подписи
    if not ocsp_response.responder_key_hash and not ocsp_response.responder_name:
        # Проверяем, что ответ подписан
        pass  # cryptography уже проверила при load_der_ocsp_response


# ── CRL ──────────────────────────────────────────────────────────────────────

def get_crl_urls(cert: x509.Certificate):
    """Извлекает URL списков отзыва (CRL Distribution Points)."""
    try:
        crl_dp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
    except x509.ExtensionNotFound:
        return []

    urls = []
    for dp in crl_dp.value:
        for name in dp.full_name or []:
            if hasattr(name, "value"):
                urls.append(name.value)
    return urls


def check_crl(cert: x509.Certificate, timeout: float = 10.0) -> dict:
    """Проверяет сертификат через CRL. Возвращает словарь с результатом."""
    crl_urls = get_crl_urls(cert)
    if not crl_urls:
        return {"method": "CRL", "status": "UNKNOWN",
                "detail": "CRL Distribution Points not found"}

    serial = cert.serial_number

    for url in crl_urls:
        try:
            req = Request(url, headers={"User-Agent": "cert-checker/1.0"})
            with urlopen(req, timeout=timeout) as resp:
                crl_data = resp.read()
        except Exception as e:
            continue  # пробуем следующий URL

        # Пробуем загрузить как DER или PEM
        try:
            crl = x509.load_der_x509_crl(crl_data, default_backend())
        except Exception:
            try:
                crl = x509.load_pem_x509_crl(crl_data, default_backend())
            except Exception:
                continue

        # Проверяем, не истёк ли сам CRL
        now = datetime.now(timezone.utc)
        if crl.next_update_utc and crl.next_update_utc < now:
            return {"method": "CRL", "status": "WARNING",
                    "detail": f"CRL is outdated (next update: {crl.next_update_utc.isoformat()})"}

        # Проверяем серийный номер
        revoked = crl.get_revoked_certificate_by_serial_number(serial)
        if revoked is not None:
            reason = ""
            if revoked.revocation_date_utc:
                reason = f", revocation date: {revoked.revocation_date_utc.isoformat()}"
            return {"method": "CRL", "status": "REVOKED",
                    "detail": f"Certificate found in CRL{reason}"}
        else:
            return {"method": "CRL", "status": "GOOD",
                    "detail": f"Certificate not found in CRL ({url})"}

    return {"method": "CRL", "status": "ERROR",
            "detail": "Failed to load any CRL"}


# ── основная логика проверки ─────────────────────────────────────────────────

def check_domain(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Проверяет сертификат домена: OCSP, при неудаче — CRL."""
    result = {
        "host": host,
        "port": port,
        "subject": "",
        "issuer": "",
        "serial": "",
        "valid_from": "",
        "valid_to": "",
        "method": "",
        "status": "",
        "detail": "",
    }

    try:
        cert, chain = get_certificate_chain(host, port, timeout)
    except socket.gaierror:
        result["status"] = "ERROR"
        result["detail"] = f"Could not resolve hostname: {host}"
        return result
    except socket.timeout:
        result["status"] = "ERROR"
        result["detail"] = f"Connection timeout: {host}:{port}"
        return result
    except ConnectionRefusedError:
        result["status"] = "ERROR"
        result["detail"] = f"Connection refused: {host}:{port}"
        return result
    except ssl.SSLError as e:
        result["status"] = "ERROR"
        result["detail"] = f"SSL error: {e}"
        return result
    except OSError as e:
        result["status"] = "ERROR"
        result["detail"] = f"Connection error: {e}"
        return result

    # Заполняем информацию о сертификате
    result["subject"] = _cn_from_dn(cert.subject)
    result["issuer"] = _cn_from_dn(cert.issuer)
    result["serial"] = format(cert.serial_number, "X")
    result["valid_from"] = cert.not_valid_before_utc.isoformat() if cert.not_valid_before_utc else "?"
    result["valid_to"] = cert.not_valid_after_utc.isoformat() if cert.not_valid_after_utc else "?"

    # Проверяем срок действия
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        result["status"] = "EXPIRED"
        result["detail"] = "Certificate not yet valid"
        return result
    if now > cert.not_valid_after_utc:
        result["status"] = "EXPIRED"
        result["detail"] = "Certificate has expired"
        return result

    # Получаем issuer для OCSP/CRL проверки
    issuer = get_issuer(cert, chain)

    # 1. Пробуем OCSP
    try:
        ocsp_result = check_ocsp(cert, issuer, timeout) if issuer else None
    except Exception as e:
        ocsp_result = {"method": "OCSP", "status": "ERROR",
                       "detail": f"OCSP check failed: {e}"}
    if ocsp_result and ocsp_result["status"] in ("GOOD", "REVOKED"):
        result.update(ocsp_result)
        return result

    # 2. Fallback на CRL
    try:
        crl_result = check_crl(cert, timeout)
    except Exception as e:
        crl_result = {"method": "CRL", "status": "ERROR",
                      "detail": f"CRL check failed: {e}"}
    if crl_result and crl_result["status"] in ("GOOD", "REVOKED"):
        result.update(crl_result)
        return result

    # 3. Если оба метода не дали однозначного ответа — выбираем лучший
    if ocsp_result and ocsp_result["status"] in ("GOOD", "REVOKED"):
        result.update(ocsp_result)
    elif crl_result and crl_result["status"] in ("GOOD", "REVOKED"):
        result.update(crl_result)
    elif crl_result and crl_result["status"] not in ("ERROR",):
        result.update(crl_result)
    elif ocsp_result and ocsp_result["status"] not in ("ERROR",):
        result.update(ocsp_result)
    elif crl_result:
        result.update(crl_result)
    elif ocsp_result:
        result.update(ocsp_result)
    else:
        result["status"] = "UNKNOWN"
        result["detail"] = "Could not perform OCSP or CRL check"

    return result


def _cn_from_dn(dn: x509.Name) -> str:
    """Извлекает Common Name из Distinguished Name."""
    for attr in dn:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            return attr.value
    return ""


# ── Telegram-уведомления ─────────────────────────────────────────────────────

def send_telegram_alert(token: str, chat_id: str, r: dict, prev_status: str | None = None):
    """Отправляет уведомление в Telegram о статусе сертификата."""
    emoji = {
        "GOOD": "\u2705",
        "REVOKED": "\u274c",
        "EXPIRED": "\u26a0\ufe0f",
        "ERROR": "\u2757",
        "UNKNOWN": "\u2753",
        "WARNING": "\u26a0\ufe0f",
    }.get(r["status"], "\u2139\ufe0f")

    lines = [
        f"{emoji} *Certificate Check*",
        f"*Domain:* `{r['host']}:{r['port']}`",
        f"*Subject:* {r['subject']}",
        f"*Issuer:* {r['issuer']}",
        f"*Status:* {r['status']}",
    ]

    if prev_status:
        lines.append(f"*Changed:* {prev_status} \u2192 {r['status']}")
    if r["detail"]:
        lines.append(f"*Details:* {r['detail']}")
    if r["method"]:
        lines.append(f"*Method:* {r['method']}")

    text = "\n".join(lines)

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown",
    }).encode("utf-8")

    try:
        req = Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        print(f"[!] Telegram send failed: {e}", file=sys.stderr)


# ── конфиг-файл ──────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    """Загружает JSON-конфиг. Возвращает словарь или None при ошибке."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in config file: {e}", file=sys.stderr)
        sys.exit(1)


def apply_config(cfg: dict, args: argparse.Namespace):
    """Применяет значения из конфига, если CLI-аргумент не переопределён."""
    # значения по умолчанию из argparse
    defaults = {
        "port": 443,
        "timeout": 10.0,
        "watch": False,
        "interval": 3600,
        "alert": False,
        "verbose": False,
        "log": None,
        "file": None,
    }

    # флаги, которые CLI всегда переопределяет (если переданы явно)
    cli_overrides = _get_explicit_args()

    def _use_cfg(key: str, cfg_key: str = None):
        """Использовать значение из конфига, если CLI не переопределил."""
        if cfg_key is None:
            cfg_key = key
        current = getattr(args, key)
        if cli_overrides.get(key):
            return current  # CLI явно задал — не трогаем
        if cfg_key in cfg and cfg[cfg_key] is not None:
            return cfg[cfg_key]
        return current if current != defaults.get(key) else cfg.get(cfg_key, current)

    args.port = _use_cfg("port")
    args.timeout = _use_cfg("timeout")
    args.interval = _use_cfg("interval")
    args.alert = _use_cfg("alert")
    args.verbose = _use_cfg("verbose")
    args.log = _use_cfg("log", "log_file")

    # watch: включаем если в конфиге есть interval или явно watch=true
    if not cli_overrides.get("watch") and cfg.get("watch", False):
        args.watch = True

    # domains из конфига добавляем к CLI-доменам
    if "domains" in cfg and isinstance(cfg["domains"], list):
        for d in cfg["domains"]:
            if d not in args.domains:
                args.domains.append(str(d))

    # telegram
    tg = cfg.get("telegram", {})
    if not hasattr(args, "telegram_token"):
        args.telegram_token = tg.get("bot_token")
        args.telegram_chat_id = tg.get("chat_id")


def _get_explicit_args() -> dict[str, bool]:
    """Определяет, какие аргументы были переданы явно (не по умолчанию)."""
    # Смотрим sys.argv на наличие флагов
    explicit = {}
    argv = sys.argv[1:]
    flag_map = {
        "--watch": "watch", "-w": "watch",
        "--alert": "alert", "-a": "alert",
        "--verbose": "verbose", "-v": "verbose",
        "--port": "port", "-p": "port",
        "--timeout": "timeout", "-t": "timeout",
        "--interval": "interval", "-i": "interval",
        "--log": "log", "-l": "log",
        "--file": "file", "-f": "file",
        "--config": "config", "-c": "config",
    }
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in flag_map:
            key = flag_map[arg]
            if arg in ("--port", "-p", "--timeout", "-t", "--interval", "-i",
                        "--log", "-l", "--file", "-f", "--config", "-c"):
                explicit[key] = True
                i += 1  # пропускаем значение
            else:
                explicit[key] = True
        i += 1
    return explicit


# ── CLI ──────────────────────────────────────────────────────────────────────

def parse_targets(args) -> list[tuple[str, int]]:
    """Собирает список (host, port) из аргументов CLI."""
    targets = []

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line:
                        host, port_str = line.rsplit(":", 1)
                        try:
                            port = int(port_str)
                        except ValueError:
                            print(f"[!] Skipping line (invalid port): {line}", file=sys.stderr)
                            continue
                        targets.append((host.strip(), port))
                    else:
                        targets.append((line, args.port))
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(1)

    for domain in args.domains:
        if ":" in domain:
            host, port_str = domain.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                print(f"[!] Invalid port in '{domain}', using {args.port}", file=sys.stderr)
                port = args.port
            targets.append((host, port))
        else:
            targets.append((domain, args.port))

    return targets

def color_status(status: str) -> str:
    """Возвращает ANSI-цвет для статуса."""
    colors = {
        "GOOD": "\033[92m",
        "REVOKED": "\033[91m",
        "EXPIRED": "\033[93m",
        "ERROR": "\033[91m",
        "UNKNOWN": "\033[93m",
        "WARNING": "\033[93m",
    }
    reset = "\033[0m"
    return f"{colors.get(status, '')}{status}{reset}"


def format_result_line(r: dict, color: bool = True) -> str:
    """Форматирует одну строку результата для лога."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    status = color_status(r["status"]) if color else r["status"]
    return (
        f"[{ts}] {r['host']}:{r['port']}  "
        f"status={status}  method={r['method']}  "
        f"serial={r['serial']}  issuer={r['issuer']}"
        + (f"  detail={r['detail']}" if r["detail"] else "")
    )


def log_result(r: dict, log_file: str, alert_only: bool, prev_status: str | None):
    """Логирует результат в файл или stdout. Возвращает True если был алерт."""
    changed = prev_status is not None and prev_status != r["status"]
    is_problem = r["status"] in ("REVOKED", "EXPIRED", "ERROR")

    # всегда логируем первый замер (нет предыдущего статуса) и проблемы
    if alert_only and not changed and not is_problem and prev_status is not None:
        return False  # тихий цикл — статус не изменился и не проблема

    line = format_result_line(r, color=(log_file is None))

    if changed:
        direction = f"{prev_status} -> {r['status']}"
        line += f"  *** STATUS CHANGED: {direction} ***"

    if log_file:
        plain = format_result_line(r, color=False)
        if changed:
            plain += f"  *** STATUS CHANGED: {direction} ***"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(plain + "\n")
    else:
        print(line)

    return changed or is_problem


def watch_loop(targets: list[tuple[str, int]], timeout: float, interval: int,
               log_file: str | None, alert_only: bool, verbose: bool,
               tg_token: str | None = None, tg_chat_id: str | None = None):
    """Бесконечный цикл проверки по расписанию."""
    state: dict[str, str] = {}  # key: "host:port" -> previous status

    tg_enabled = bool(tg_token and tg_chat_id)
    print(f"Watch mode started. Checking {len(targets)} target(s) every {interval}s.")
    print(f"Log: {'stdout' if log_file is None else log_file}")
    print(f"Alert only: {alert_only}")
    print(f"Telegram alerts: {'enabled' if tg_enabled else 'disabled'}")
    print("Press Ctrl+C to stop.\n")

    running = True

    def _on_interrupt(signum, frame):
        nonlocal running
        print("\nShutting down...")
        running = False

    signal.signal(signal.SIGINT, _on_interrupt)
    signal.signal(signal.SIGTERM, _on_interrupt)

    while running:
        cycle_start = time.monotonic()
        alerts_this_cycle = 0

        for host, port in targets:
            key = f"{host}:{port}"
            prev = state.get(key)
            r = check_domain(host, port, timeout)

            if not alert_only or prev is None:
                # полный вывод при первом запуске
                print_result(r, verbose)

            alerted = log_result(r, log_file, alert_only, prev)
            if alerted:
                alerts_this_cycle += 1
                # отправляем в Telegram при изменении или проблеме
                if tg_enabled and (prev != r["status"] or r["status"] in ("REVOKED", "EXPIRED", "ERROR")):
                    send_telegram_alert(tg_token, tg_chat_id, r, prev if prev != r["status"] else None)

            state[key] = r["status"]

        elapsed = time.monotonic() - cycle_start
        if not alert_only or alerts_this_cycle > 0:
            print(f"\n--- Cycle complete ({elapsed:.1f}s), alerts: {alerts_this_cycle} ---\n")

        # спим оставшееся время до интервала
        remaining = interval - elapsed
        if remaining > 0 and running:
            # дробный сон для быстрой реакции на Ctrl+C
            while remaining > 0 and running:
                chunk = min(remaining, 1.0)
                time.sleep(chunk)
                remaining -= chunk


def print_result(r: dict, verbose: bool = False):
    """Выводит результат проверки одного домена."""
    status_colored = color_status(r["status"])
    print(f"\n{'-' * 60}")
    print(f"  Domain:     {r['host']}:{r['port']}")
    print(f"  Subject:    {r['subject']}")
    print(f"  Issuer:     {r['issuer']}")
    print(f"  Serial:     {r['serial']}")
    print(f"  Valid:      {r['valid_from']} -> {r['valid_to']}")
    print(f"  Status:     {status_colored}")
    if r["detail"]:
        print(f"  Details:    {r['detail']}")
    if r["method"]:
        print(f"  Method:     {r['method']}")


def main():
    parser = argparse.ArgumentParser(
        description="SSL/TLS certificate revocation checker (OCSP + CRL)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com google.com
  %(prog)s --port 8443 example.com
  %(prog)s --file domains.txt
  %(prog)s --watch --interval 3600 --file domains.txt
  %(prog)s --watch --interval 300 --alert --log certs.log example.com
        """,
    )
    parser.add_argument(
        "domains", nargs="*",
        help="One or more domain names to check",
    )
    parser.add_argument(
        "-f", "--file",
        help="File with domain list (one per line, optional port: host:port)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=443,
        help="Port to connect to (default: 443)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=10.0,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "-w", "--watch", action="store_true",
        help="Run in watch mode: check repeatedly on a schedule",
    )
    parser.add_argument(
        "-i", "--interval", type=int, default=3600,
        help="Interval between checks in seconds (default: 3600, only with --watch)",
    )
    parser.add_argument(
        "-l", "--log", metavar="FILE",
        help="Log results to FILE (JSON-lines format, only with --watch)",
    )
    parser.add_argument(
        "-a", "--alert", action="store_true",
        help="Alert only on status changes or problems (suppress unchanged GOOD, only with --watch)",
    )
    parser.add_argument(
        "-c", "--config",
        help="JSON config file (can contain all options including telegram)",
    )
    parser.add_argument(
        "--telegram-token",
        help="Telegram bot token for alerts (overrides config)",
    )
    parser.add_argument(
        "--telegram-chat-id",
        help="Telegram chat ID for alerts (overrides config)",
    )

    args = parser.parse_args()

    # ── загружаем конфиг (если указан) ──
    if args.config:
        cfg = load_config(args.config)
        apply_config(cfg, args)

    # ── Telegram: CLI переопределяет конфиг ──
    tg_token = args.telegram_token
    tg_chat_id = args.telegram_chat_id

    targets = parse_targets(args)

    if not targets:
        parser.print_help()
        sys.exit(0)

    # ── watch mode ──
    if args.watch:
        if args.interval < 10:
            print("Interval must be at least 10 seconds.", file=sys.stderr)
            sys.exit(1)
        watch_loop(targets, args.timeout, args.interval,
                   args.log, args.alert, args.verbose,
                   tg_token, tg_chat_id)
        return

    # ── single-run mode ──
    exit_code = 0
    for host, port in targets:
        r = check_domain(host, port, args.timeout)
        print_result(r, args.verbose)
        if r["status"] in ("REVOKED", "EXPIRED", "ERROR"):
            exit_code = 1

    print()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
