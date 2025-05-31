# mutations.py
import base64
import zlib
import html
import json
import urllib.parse
import random
import unicodedata
import os
from typing import Generator, Tuple, Dict, Any, Optional


def generate_mutations(input_path: str = "/", waf_type: str = "unknown") -> Generator[
    Tuple[str, Any, Dict], None, None]:
    """
    Generate all mutations as (name, value, metadata) tuples.

    Args:
        input_path: The path to mutate (default "/")
        waf_type: The detected WAF type for vendor-specific mutations

    Yields:
        Tuple of (mutation_name, mutation_value, metadata_dict)
    """

    # Genetic mutations - simple and fast
    yield ("genetic_reverse", input_path[::-1], {"category": "genetic", "complexity": 1})
    yield ("genetic_upper", input_path.upper(), {"category": "genetic", "complexity": 1})
    yield ("genetic_lower", input_path.lower(), {"category": "genetic", "complexity": 1})
    yield ("genetic_swapcase", ''.join(c.swapcase() for c in input_path), {"category": "genetic", "complexity": 1})

    if len(input_path) >= 2:
        mid = len(input_path) // 2
        yield ("genetic_crossover", input_path[mid:] + input_path[:mid], {"category": "genetic", "complexity": 1})

    # Character shuffling
    chars = list(input_path)
    random.shuffle(chars)
    yield ("genetic_shuffle", ''.join(chars), {"category": "genetic", "complexity": 1})

    # URL encodings - multiple levels
    encoded = input_path
    yield ("url_encode_1x", urllib.parse.quote(encoded, safe=''), {"category": "encoding", "complexity": 2})

    encoded = urllib.parse.quote(encoded, safe='')
    yield ("url_encode_2x", urllib.parse.quote(encoded, safe=''), {"category": "encoding", "complexity": 2})

    encoded = urllib.parse.quote(encoded, safe='')
    yield ("url_encode_3x", urllib.parse.quote(encoded, safe=''), {"category": "encoding", "complexity": 2})

    # Base64 variations
    b64 = base64.b64encode(input_path.encode()).decode()
    yield ("base64", b64, {"category": "encoding", "complexity": 2})
    yield ("base64_url", urllib.parse.quote(b64), {"category": "encoding", "complexity": 3})

    # HTML encoding
    html_escaped = html.escape(input_path)
    yield ("html_escape", html_escaped, {"category": "encoding", "complexity": 2})
    yield ("html_base64", base64.b64encode(html_escaped.encode()).decode(), {"category": "encoding", "complexity": 3})

    # Compression encoding (more expensive)
    compressed = zlib.compress(input_path.encode())
    yield ("compress_base64", base64.b64encode(compressed).decode(), {"category": "encoding", "complexity": 4})

    # Hex encoding
    yield ("hex_encode", input_path.encode().hex(), {"category": "encoding", "complexity": 2})

    # Unicode encodings
    yield ("unicode_escape", ''.join(f'\\u{ord(c):04x}' for c in input_path), {"category": "encoding", "complexity": 3})
    yield ("unicode_escape_upper", ''.join(f'\\U{ord(c):08x}' for c in input_path),
           {"category": "encoding", "complexity": 3})

    # Homoglyphs
    homoglyphs = {
        'a': 'а', 'e': 'е', 'i': 'і', 'o': 'о', 'p': 'р', 'c': 'с', 'y': 'у', 'x': 'х',
        'A': 'А', 'E': 'Е', 'O': 'О', 'P': 'Р', 'C': 'С', 'Y': 'У', 'X': 'Х'
    }
    homoglyph_path = ''.join(homoglyphs.get(c, c) for c in input_path)
    yield ("homoglyphs", homoglyph_path, {"category": "char_mutation", "complexity": 2})

    # Zero-width characters
    yield ("zero_width_space", ''.join(c + '\u200b' for c in input_path),
           {"category": "char_mutation", "complexity": 3})
    yield ("zero_width_joiner", ''.join(c + '\u200d' for c in input_path),
           {"category": "char_mutation", "complexity": 3})
    yield ("zero_width_nonjoiner", ''.join(c + '\u200c' for c in input_path),
           {"category": "char_mutation", "complexity": 3})

    # Mixed invisible characters
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
    mixed_invisible = ''.join(c + random.choice(invisible_chars) for c in input_path)
    yield ("mixed_invisible", mixed_invisible, {"category": "char_mutation", "complexity": 3})

    # Unicode normalization forms
    for form in ['NFC', 'NFKC', 'NFD', 'NFKD']:
        normalized = unicodedata.normalize(form, input_path)
        yield (f"unicode_{form.lower()}", normalized, {"category": "unicode", "complexity": 2})

    # Bidirectional text
    ltr = '\u202A'
    rtl = '\u202B'
    pdf = '\u202C'
    yield ("bidi_ltr", f"{ltr}{input_path}{pdf}", {"category": "unicode", "complexity": 3})
    yield ("bidi_rtl", f"{rtl}{input_path}{pdf}", {"category": "unicode", "complexity": 3})
    yield ("bidi_reversed", f"{ltr}{input_path[::-1]}{pdf}", {"category": "unicode", "complexity": 3})

    # ROT13
    rot13 = ''.join(
        chr((ord(c) - 97 + 13) % 26 + 97) if 'a' <= c <= 'z' else
        chr((ord(c) - 65 + 13) % 26 + 65) if 'A' <= c <= 'Z' else c
        for c in input_path
    )
    yield ("rot13", rot13, {"category": "encoding", "complexity": 2})
    yield ("rot13_base64", base64.b64encode(rot13.encode()).decode(), {"category": "encoding", "complexity": 3})

    # Base32
    yield ("base32", base64.b32encode(input_path.encode()).decode(), {"category": "encoding", "complexity": 2})

    # Polyglot payloads
    polyglot_html_b64 = f"/*{html.escape(input_path)}*/\n<![CDATA[{b64}]]>"
    yield ("polyglot_html", polyglot_html_b64, {"category": "polyglot", "complexity": 4})

    # Protocol polyglots
    yield ("data_uri", f"data:text/plain;base64,{b64}", {"category": "polyglot", "complexity": 3})
    yield ("javascript_uri", f"javascript:{urllib.parse.quote(input_path)}", {"category": "polyglot", "complexity": 3})
    yield ("file_uri", f"file:///{urllib.parse.quote(input_path)}", {"category": "polyglot", "complexity": 3})

    # Header-based bypasses (these include metadata for headers to add)
    yield ("xff_localhost", input_path, {
        "category": "header",
        "complexity": 1,
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
        }
    })

    yield ("xff_private", input_path, {
        "category": "header",
        "complexity": 1,
        "headers": {
            "X-Forwarded-For": "10.0.0.1",
            "X-Originating-IP": "192.168.1.1",
            "Client-IP": "172.16.0.1",
        }
    })

    yield ("xff_chain", input_path, {
        "category": "header",
        "complexity": 2,
        "headers": {
            "X-Forwarded-For": f"127.0.0.1, {_get_random_ip()}, {_get_random_ip()}",
            "X-Real-IP": _get_random_ip(),
        }
    })

    yield ("method_override", input_path, {
        "category": "header",
        "complexity": 1,
        "headers": {
            "X-HTTP-Method-Override": "GET",
            "X-HTTP-Method": "GET",
            "X-Method-Override": "GET",
        }
    })

    yield ("host_override", input_path, {
        "category": "header",
        "complexity": 2,
        "headers": {
            "X-Forwarded-Host": "localhost",
            "X-Forwarded-Server": "localhost",
            "X-Original-Host": "localhost",
        }
    })

    # Protocol mutations
    yield ("websocket_upgrade", input_path, {
        "category": "protocol",
        "complexity": 3,
        "headers": {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode()
        }
    })

    yield ("chunked_encoding", input_path, {
        "category": "protocol",
        "complexity": 2,
        "headers": {
            "Transfer-Encoding": "chunked"
        }
    })

    # Cache bypass headers
    yield ("cache_bypass", input_path, {
        "category": "header",
        "complexity": 1,
        "headers": {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "X-Cache-Bypass": "1",
        }
    })

    # Vendor-specific bypasses based on detected WAF
    if waf_type == "cloudflare":
        yield ("cf_bypass_ip", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "CF-Connecting-IP": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
            }
        })

        yield ("cf_bypass_ray", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "CF-RAY": "0000000000000000-LAX",
                "CF-Visitor": '{"scheme":"https"}',
            }
        })

    elif waf_type == "akamai":
        yield ("akamai_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "True-Client-IP": "127.0.0.1",
                "Akamai-Origin-Hop": "1",
                "X-Akamai-Edgescape": "georegion=246,country_code=US,city=LOCALHOST",
            }
        })

    elif waf_type == "aws":
        yield ("aws_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-AMZ-CF-ID": "bypass",
                "X-Amzn-Trace-Id": "Root=1-00000000-000000000000000000000000",
                "X-Amz-Security-Token": "null",
            }
        })

    elif waf_type == "imperva":
        yield ("imperva_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Forwarded-For-Imperva": "127.0.0.1",
                "X-Iinfo": "0-0000000-0000000 0NNN RT(0000000000 000) q(0 0 0 -1) r(0 0)",
            }
        })

    elif waf_type == "f5":
        yield ("f5_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Host": "localhost",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Port": "443",
            }
        })

    # Generic vendor bypass for unknown WAF
    yield ("generic_bypass", input_path, {
        "category": "vendor",
        "complexity": 1,
        "headers": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
        }
    })

    yield ("json_simple_wrap", json.dumps({"payload": input_path}), {"category": "json", "complexity": 2})
    yield ("json_nested", json.dumps({"data": {"request": {"payload": input_path}}}),
           {"category": "json", "complexity": 3})
    yield ("json_array_wrap", json.dumps([{"payload": input_path}]), {"category": "json", "complexity": 2})

    # JSON with unicode escape
    unicode_payload = ''.join(f'\\u{ord(c):04x}' for c in input_path)
    yield ("json_unicode_escape", json.dumps({"payload": unicode_payload}), {"category": "json", "complexity": 3})

    # JSON with base64
    json_b64 = json.dumps({"payload": base64.b64encode(input_path.encode()).decode(), "encoding": "base64"})
    yield ("json_base64", json_b64, {"category": "json", "complexity": 3})

    # JSON with whitespace
    json_whitespace = f'{{\n  "payload": {json.dumps(input_path)}\n}}'
    yield ("json_whitespace", json_whitespace, {"category": "json", "complexity": 2})

    # JSON with comments (invalid but might work)
    json_comments = f'{{\n  "payload": {json.dumps(input_path)}  /* comment */\n}}'
    yield ("json_comments", json_comments, {"category": "json", "complexity": 3})

    # More polyglot payloads
    html_enc = html.escape(input_path)
    json_enc = json.dumps(input_path)
    unicode_enc = ''.join(f'\\u{ord(c):04x}' for c in input_path)

    multi_context = f"/*{html_enc}*/\n<![CDATA[{b64}]]>\n<!--{json_enc}-->\n`{unicode_enc}`"
    yield ("polyglot_multi_context", multi_context, {"category": "polyglot", "complexity": 5})

    # Format polyglot
    xml_variant = f'<?xml version="1.0"?><root><![CDATA[{input_path}]]></root>'
    html_variant = f'<!--{html.escape(input_path)}-->'
    format_polyglot = '\n'.join([json_enc, xml_variant, html_variant, urllib.parse.quote(input_path)])
    yield ("polyglot_format", format_polyglot, {"category": "polyglot", "complexity": 5})

    # Advanced homoglyphs (more complete set)
    advanced_homoglyphs = {
        'a': ['а', 'ɑ', 'α', '𝐚', '𝑎', '𝒂', '𝓪', '𝔞', '𝕒', '𝖆', '𝗮', '𝘢', '𝙖', '𝚊'],
        'b': ['б', 'ƅ', 'Ь', '𝐛', '𝑏', '𝒃', '𝓫', '𝔟', '𝕓', '𝖇', '𝗯', '𝘣', '𝙗', '𝚋'],
        'c': ['с', 'ϲ', '𝐜', '𝑐', '𝒄', '𝓬', '𝔠', '𝕔', '𝖈', '𝗰', '𝘤', '𝙘', '𝚌'],
        'd': ['ԁ', 'ɗ', '𝐝', '𝑑', '𝒅', '𝓭', '𝔡', '𝕕', '𝖉', '𝗱', '𝘥', '𝙙', '𝚍'],
        'e': ['е', 'ｅ', 'ԑ', '𝐞', '𝑒', '𝒆', '𝓮', '𝔢', '𝕖', '𝖊', '𝗲', '𝘦', '𝙚', '𝚎'],
        'f': ['ƒ', '𝐟', '𝑓', '𝒇', '𝓯', '𝔣', '𝕗', '𝖋', '𝗳', '𝘧', '𝙛', '𝚏'],
        'g': ['ɡ', 'ց', '𝐠', '𝑔', '𝒈', '𝓰', '𝔤', '𝕘', '𝖌', '𝗴', '𝘨', '𝙜', '𝚐'],
        'h': ['һ', 'ℎ', '𝐡', '𝒉', '𝒽', '𝓱', '𝔥', '𝕙', '𝖍', '𝗵', '𝘩', '𝙝', '𝚑'],
        'i': ['і', 'ı', '𝐢', '𝑖', '𝒊', '𝓲', '𝔦', '𝕚', '𝖎', '𝗶', '𝘪', '𝙞', '𝚒'],
        'j': ['ϳ', 'ј', '𝐣', '𝑗', '𝒋', '𝓳', '𝔧', '𝕛', '𝖏', '𝗷', '𝘫', '𝙟', '𝚓'],
        'k': ['𝐤', '𝑘', '𝒌', '𝓴', '𝔨', '𝕜', '𝖐', '𝗸', '𝘬', '𝙠', '𝚔'],
        'l': ['ⅼ', 'ℓ', '𝐥', '𝑙', '𝒍', '𝓵', '𝔩', '𝕝', '𝖑', '𝗹', '𝘭', '𝙡', '𝚕'],
        'm': ['ｍ', '𝐦', '𝑚', '𝒎', '𝓶', '𝔪', '𝕞', '𝖒', '𝗺', '𝘮', '𝙢', '𝚖'],
        'n': ['ո', '𝐧', '𝑛', '𝒏', '𝓷', '𝔫', '𝕟', '𝖓', '𝗻', '𝘯', '𝙣', '𝚗'],
        'o': ['о', 'ο', '𝐨', '𝑜', '𝒐', '𝓸', '𝔬', '𝕠', '𝖔', '𝗼', '𝘰', '𝙤', '𝚘'],
        'p': ['р', 'ρ', '𝐩', '𝑝', '𝒑', '𝓹', '𝔭', '𝕡', '𝖕', '𝗽', '𝘱', '𝙥', '𝚙'],
        'q': ['𝐪', '𝑞', '𝒒', '𝓺', '𝔮', '𝕢', '𝖖', '𝗾', '𝘲', '𝙦', '𝚚'],
        'r': ['г', '𝐫', '𝑟', '𝒓', '𝓻', '𝔯', '𝕣', '𝖗', '𝗿', '𝘳', '𝙧', '𝚛'],
        's': ['ѕ', '𝐬', '𝑠', '𝒔', '𝓼', '𝔰', '𝕤', '𝖘', '𝘀', '𝘴', '𝙨', '𝚜'],
        't': ['𝐭', '𝑡', '𝒕', '𝓽', '𝔱', '𝕥', '𝖙', '𝘁', '𝘵', '𝙩', '𝚝'],
        'u': ['υ', 'ս', '𝐮', '𝑢', '𝒖', '𝓾', '𝔲', '𝕦', '𝖚', '𝘂', '𝘶', '𝙪', '𝚞'],
        'v': ['ν', 'ѵ', '𝐯', '𝑣', '𝒗', '𝓿', '𝔳', '𝕧', '𝖛', '𝘃', '𝘷', '𝙫', '𝚟'],
        'w': ['ѡ', 'ԝ', '𝐰', '𝑤', '𝒘', '𝔀', '𝔴', '𝕨', '𝖜', '𝘄', '𝘸', '𝙬', '𝚠'],
        'x': ['х', '𝐱', '𝑥', '𝒙', '𝔁', '𝔵', '𝕩', '𝖝', '𝘅', '𝘹', '𝙭', '𝚡'],
        'y': ['у', 'ү', '𝐲', '𝑦', '𝒚', '𝔂', '𝔶', '𝕪', '𝖞', '𝘆', '𝘺', '𝙮', '𝚢'],
        'z': ['𝐳', '𝑧', '𝒛', '𝔃', '𝔷', '𝕫', '𝖟', '𝘇', '𝘻', '𝙯', '𝚣']
    }

    # Generate multiple random homoglyph variations
    for i in range(5):
        variation = ''
        for c in input_path:
            if c.lower() in advanced_homoglyphs:
                variation += random.choice(advanced_homoglyphs[c.lower()])
            else:
                variation += c
        yield (f"advanced_homoglyph_{i}", variation, {"category": "char_mutation", "complexity": 3})

    # Charset mutations with headers
    yield ("charset_ibm037", input_path, {
        "category": "charset",
        "complexity": 3,
        "headers": {"Content-Type": "application/x-www-form-urlencoded; charset=IBM037"}
    })

    yield ("charset_utf16", input_path, {
        "category": "charset",
        "complexity": 3,
        "headers": {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-16"}
    })

    yield ("charset_utf32", input_path, {
        "category": "charset",
        "complexity": 3,
        "headers": {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-32"}
    })

    yield ("charset_utf7", f"+{base64.b64encode(input_path.encode()).decode()}-", {
        "category": "charset",
        "complexity": 3,
        "headers": {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-7"}
    })

    # Advanced encoding chains
    # Polyglot with multiple encodings
    html_encoded = html.escape(input_path)
    b64_encoded = base64.b64encode(html_encoded.encode()).decode()
    url_encoded = urllib.parse.quote(b64_encoded)
    yield ("chain_html_b64_url", f"data:text/plain;base64,{url_encoded}", {"category": "encoding", "complexity": 5})

    # Rotated encoding
    def rotate_str(s, n):
        return s[n:] + s[:n]

    rotated = rotate_str(input_path, 3)
    yield ("rotated_encoding", base64.b64encode(rotated.encode()).decode(), {"category": "encoding", "complexity": 3})

    # Mixed charset encoding
    ascii_binary = ''.join(bin(ord(c))[2:].zfill(8) for c in input_path)
    chunks = [ascii_binary[i:i + 6] for i in range(0, len(ascii_binary), 6)]
    charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"
    mixed_charset = ''.join(charset[int(chunk.ljust(6, '0'), 2)] for chunk in chunks)
    yield ("mixed_charset", mixed_charset, {"category": "encoding", "complexity": 4})

    # Nested compression
    compressed = zlib.compress(input_path.encode())
    b64_compressed = base64.b64encode(compressed).decode()
    chunks = [b64_compressed[i:i + 3] for i in range(0, len(b64_compressed), 3)]
    nested_compress = base64.b64encode(''.join(reversed(chunks)).encode()).decode()
    yield ("nested_compress", nested_compress, {"category": "encoding", "complexity": 5})

    # Extended vendor bypasses
    if waf_type == "netscaler":
        yield ("netscaler_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Forwarded-For": "localhost",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Port": "443",
                "X-SSL": "on",
                "Client-IP": "127.0.0.1"
            }
        })

    elif waf_type == "signal_sciences":
        yield ("sigsci_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Sigsci-Agent": "null",
                "X-Sigsci-Tags": "whitelist",
                "X-HTTP-Method": "GET",
                "X-Forwarded-Proto": "https",
                "X-Real-IP": "127.0.0.1"
            }
        })

    elif waf_type == "sucuri":
        yield ("sucuri_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "Accept-Encoding": "identity",
                "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Cookie": "sucuri_cloudproxy_uuid_=null",
                "X-Sucuri-Cache": "null",
                "X-Sucuri-ClientIP": "127.0.0.1"
            }
        })

    elif waf_type == "fortinet":
        yield ("fortinet_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Port": "443",
                "X-Forwarded-SSL": "on",
                "X-Forwarded-Server": "localhost"
            }
        })

    elif waf_type == "barracuda":
        yield ("barracuda_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Real-IP": "127.0.0.1",
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Ssl": "on"
            }
        })

    elif waf_type == "modsecurity":
        yield ("modsecurity_bypass", input_path, {
            "category": "vendor",
            "complexity": 2,
            "headers": {
                "X-Forwarded-For": "127.0.0.1",
                "X-Forwarded-Host": "localhost",
                "X-Real-IP": "127.0.0.1",
                "Content-Type": "text/plain"  # Sometimes bypasses rules expecting specific content types
            }
        })

    # More protocol variations
    yield ("http_1_0", input_path, {
        "category": "protocol",
        "complexity": 2,
        "protocol_version": "HTTP/1.0"
    })

    yield ("http_0_9", input_path, {
        "category": "protocol",
        "complexity": 3,
        "protocol_version": "HTTP/0.9"
    })

    # Connection variations
    yield ("keep_alive", input_path, {
        "category": "protocol",
        "complexity": 1,
        "headers": {
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=5, max=1000"
        }
    })

    yield ("connection_close", input_path, {
        "category": "protocol",
        "complexity": 1,
        "headers": {
            "Connection": "close"
        }
    })

    # More encoding variations
    yield ("percent_encode_all", ''.join(f'%{ord(c):02X}' for c in input_path),
           {"category": "encoding", "complexity": 3})
    yield ("percent_encode_mixed", ''.join(f'%{ord(c):02x}' if i % 2 else c for i, c in enumerate(input_path)),
           {"category": "encoding", "complexity": 3})

    # Overlong UTF-8 encoding
    def overlong_utf8(c):
        if ord(c) < 0x80:
            # Create overlong 2-byte sequence
            return f'%C0%{0x80 | ord(c):02X}'
        return c

    overlong = ''.join(overlong_utf8(c) for c in input_path)
    yield ("overlong_utf8", overlong, {"category": "encoding", "complexity": 4})

    # Additional bidirectional overrides
    lro = '\u202D'  # Left-to-right override
    rlo = '\u202E'  # Right-to-left override
    yield ("bidi_override_ltr", f"{lro}{input_path}{pdf}", {"category": "unicode", "complexity": 3})
    yield ("bidi_override_rtl", f"{rlo}{input_path}{pdf}", {"category": "unicode", "complexity": 3})

    # Combining diacritical marks (full range)
    all_combiners = [chr(x) for x in range(0x0300, 0x036F)]
    # Just yield a few variations to avoid explosion
    for i in range(3):
        combiner_set = random.sample(all_combiners, min(5, len(all_combiners)))
        combined = ''.join(c + random.choice(combiner_set) for c in input_path)
        yield (f"combining_full_{i}", combined, {"category": "unicode", "complexity": 4})

    # Advanced combinations (more expensive, so yield later)
    # Combining character encoding
    for i in range(0x0300, 0x0305):  # Just a few combining chars
        combined = ''.join(c + chr(i) for c in input_path)
        yield (f"combining_{hex(i)}", combined, {"category": "unicode", "complexity": 4})

    # Multiple encoding layers
    double_b64 = base64.b64encode(b64.encode()).decode()
    yield ("double_base64", double_b64, {"category": "encoding", "complexity": 4})

    # URL + Base64 + URL
    url_b64_url = urllib.parse.quote(base64.b64encode(urllib.parse.quote(input_path).encode()).decode())
    yield ("url_base64_url", url_b64_url, {"category": "encoding", "complexity": 5})


def _get_random_ip() -> str:
    """Generate a random IP address"""
    return f"{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def count_mutations(input_path: str = "/", waf_type: str = "unknown") -> int:
    """Count total number of mutations without generating them all"""
    count = 0
    for _ in generate_mutations(input_path, waf_type):
        count += 1
    return count


def get_mutation_categories() -> Dict[str, str]:
    """Get description of mutation categories"""
    return {
        "genetic": "Simple transformations like case changes and reversals",
        "encoding": "Various encoding schemes (URL, Base64, Hex, etc)",
        "char_mutation": "Character-level changes (homoglyphs, zero-width)",
        "unicode": "Unicode normalization and bidirectional text",
        "polyglot": "Multi-context payloads",
        "header": "Header-based bypasses",
        "protocol": "Protocol-level manipulations",
        "vendor": "WAF vendor-specific bypasses",
    }