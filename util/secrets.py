import re
import math
import string
from urllib.parse import urlparse, parse_qs


def compile_re(s):
    return re.compile(r"^" + s + r"$", re.IGNORECASE)


ignored_query_string_parameters = ["_ga", "__gda__", "_gac", "gclid", "msclkid", "_hsenc", "mkt_tok"]
ignored_query_string_prefixes = ["utm_"]

SECRET_REGEX = {
    compile_re("'^[a-f0-9]{8}-?[a-f0-9]{4}-?4[a-f0-9]{3}-?[89ab][a-f0-9]{3}-?[a-f0-9]{12}\Z'"): ["UUID"],
    compile_re(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)'): ["base64"],
    compile_re(r"[a-f0-9]{32}(:.+)?"):  ["MD5", "MD4", "MD2", "Double MD5", "LM", "RIPEMD-128", "Haval-128", "Tiger-128", "Skein-256(128)", "Skein-512(128", "Lotus Notes/Domino 5", "Skype", "ZipMonster", "PrestaShop"],
    compile_re(r"[a-f0-9]{64}(:.+)?"):  ["SHA-256", "RIPEMD-256", "SHA3-256", "Haval-256", "GOST R 34.11-94", "GOST CryptoPro S-Box", "Skein-256", "Skein-512(256)", "Ventrilo"],
    compile_re(r"[a-f0-9]{128}(:.+)?"): ["SHA-512", "Whirlpool", "Salsa10", "Salsa20", "SHA3-512", "Skein-512", "Skein-1024(512)"],
    compile_re(r"[a-f0-9]{56}"):        ["SHA-224", "Haval-224", "SHA3-224", "Skein-256(224)", "Skein-512(224)"],
    compile_re(r"[a-f0-9]{40}(:.+)?"):  ["SHA-1", "Double SHA-1", "RIPEMD-160", "Haval-160", "Tiger-160", "HAS-160", "LinkedIn", "Skein-256(160)", "Skein-512(160)", "MangoWeb Enhanced CMS"],
    compile_re(r"[a-f0-9]{96}"):        ["SHA-384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)"],
    compile_re(r"[a-f0-9]{16}"):        ["MySQL323", "DES(Oracle)", "Half MD5", "Oracle 7-10g", "FNV-164", "CRC-64"],
    compile_re(r"\*[a-f0-9]{40}"):      ["MySQL5.x", "MySQL4.1"],
    compile_re(r"[a-f0-9]{48}"):        ["Haval-192", "Tiger-192", "SHA-1(Oracle)", "XSHA (v10.4 - v10.6)"]
}


def is_secret(check_hash):
    check_hash = check_hash.replace("-", "").replace("_", "")
    for algorithm, items in SECRET_REGEX.items():
        if algorithm.match(check_hash):
            return True
    return False


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in string.printable):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def calculate_url_score(url):
    score = 1
    parsed = urlparse(url)
    parts = parsed.netloc.split(".")
    parts.extend([p for p in parsed.path.split("/") if p])

    splitted_last_part = parts[-1].lower().split(".", 1)
    if len(splitted_last_part) > 1:
        if splitted_last_part[1] in ["js", "css"]:
            return 1

    for part in parts:
        if is_secret(part):
            score += 100

    qs = parse_qs(parsed.query)
    if parsed.query and len(qs.items()) == 0:
        qs[""] = [parsed.query]
    for k, value in qs.items():
        k = k.lower()
        value = value[0]
        if any([k.startswith(prefix) for prefix in ignored_query_string_prefixes]) or k in ignored_query_string_parameters:
            continue

        if urlparse(value).netloc:
            score += calculate_url_score(value)
        elif "id" in k or "token" in k or is_secret(value) or calculate_entropy(value) > 3:
            score += 100

    return score
