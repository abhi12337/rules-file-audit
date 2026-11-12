"""Line-level detectors for dangerous instructions (RFA020-RFA024, RFA030-RFA032, RFA051).

Each detector returns Hits; the caller turns them into Findings. Natural-language
detectors skip a match when the same clause negates it ("Never pipe curl to bash",
"Do not skip tests"), except for phrasings that only look negative ("never forget to").
Command detectors used on config values (hook commands) do not apply negation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

I = re.IGNORECASE


@dataclass
class Hit:
    rule: str
    severity: str
    message: str
    col: int
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------- helpers
URL_RE = re.compile(r"https?://[^\s<>\"'`)\]}|]+", I)
_LOCAL_HOSTS = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|"
                          r"[\w.-]+\.(localhost|local|internal|lan|home\.arpa))$", I)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def is_external(url: str) -> bool:
    h = host_of(url)
    return bool(h) and not _LOCAL_HOSTS.match(h)


def external_urls(s: str) -> list[re.Match]:
    return [m for m in URL_RE.finditer(s) if is_external(m.group(0).rstrip(".,;:"))]


_BOUNDARY = re.compile(r"[.!?;](?=\s|$)|\s[-\u2013\u2014]\s|\b(?:but|instead|however|then|otherwise)\b", I)
_NEG = re.compile(r"\b(?:never|not|no|don'?t|doesn'?t|won'?t|can'?t|cannot|mustn'?t|shouldn'?t|avoid|avoiding|"
                  r"prohibit(?:ed)?|forbid(?:den)?|disallow(?:ed)?|refuse|without|nor)\b", I)
_AFFIRM = re.compile(r"\b(?:never|don'?t|do\s+not)\s+(?:forget|fail|hesitate|skip\s+(?:this|the\s+step))\b|"
                     r"\bnot\s+optional\b|\bno\s+matter\b|\bwithout\s+(?:fail|exception)\b", I)


def negated(line: str, start: int) -> bool:
    """True when the clause that contains position `start` negates what follows."""
    before = line[max(0, start - 120):start].replace("\u2019", "'")
    cut = 0
    for m in _BOUNDARY.finditer(before):
        cut = m.end()
    clause = before[cut:]
    if _AFFIRM.search(clause):
        return False
    return bool(_NEG.search(clause))


def _short(s: str, n: int = 90) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------- RFA020 remote code
_FETCHER = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)"
PIPE_TO_SHELL = re.compile(
    rf"\b{_FETCHER}\b[^|\n]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+\S+=\S+\s+)*"
    r"(?:(?:ba|z|da|k|fi)?sh|python[23]?|node|perl|ruby|php|iex|invoke-expression|pwsh|powershell)\b", I)
SHELL_FROM_URL = re.compile(
    r"(?:\b(?:ba|z)?sh\s+(?:-s\s+)?<\(\s*(?:curl|wget)\b|\b(?:source|\.)\s+<\(\s*(?:curl|wget)\b|"
    r"\b(?:eval|(?:ba|z)?sh\s+-c)\s+[\"']?\$\(\s*(?:curl|wget)\b|"
    r"\biex\s*\(?\s*(?:\(?\s*new-object\s+(?:system\.)?net\.webclient|iwr|irm|invoke-webrequest|invoke-restmethod)\b|"
    r"\.downloadstring\s*\(\s*['\"]https?://)", I)
DOWNLOAD_AND_RUN = re.compile(
    r"\b(?:download|fetch|get|grab|curl|wget)\b[^.;\n]{0,80}?https?://\S+[^.;\n]{0,60}?\b(?:and|then)\s+"
    r"(?P<verb>run|execute|exec|source|eval|install)\b|"
    r"\b(?:run|execute|source|eval)\s+(?:the\s+)?(?:script|code|installer|commands?|file|payload)\s+"
    r"(?:at|from|hosted\s+at|located\s+at)\s+<?https?://", I)
REMOTE_SCRIPT_TAG = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']?(https?:)?//", I)
KNOWN_INSTALLERS = ("sh.rustup.rs", "rustup.rs", "bun.sh", "astral.sh", "deno.land", "get.docker.com",
                    "install.python-poetry.org", "get.pnpm.io", "fnm.vercel.app", "get.volta.sh", "mise.run",
                    "starship.rs", "claude.ai", "pyenv.run", "get.sdkman.io", "foundry.paradigm.xyz",
                    "sdk.cloud.google.com", "cli.github.com", "deb.nodesource.com", "rpm.nodesource.com")
KNOWN_INSTALLER_PATHS = ("raw.githubusercontent.com/homebrew/", "raw.githubusercontent.com/nvm-sh/")


def _known_installer(text: str) -> bool:
    urls = [m.group(0).lower() for m in URL_RE.finditer(text)]
    if not urls:
        return False
    for u in urls:
        h = host_of(u)
        if not (h in KNOWN_INSTALLERS or any(h.endswith("." + k) for k in KNOWN_INSTALLERS)
                or any(p in u for p in KNOWN_INSTALLER_PATHS)):
            return False
    return True


def detect_remote_code(line: str, nl: bool) -> list[Hit]:
    for pat, what in ((PIPE_TO_SHELL, "pipes a download into an interpreter"),
                      (SHELL_FROM_URL, "executes a downloaded script"),
                      (DOWNLOAD_AND_RUN, "tells the agent to download and run code")):
        m = pat.search(line)
        if m and not (nl and negated(line, m.start())):
            url = URL_RE.search(line)
            if url and _known_installer(line):
                return [Hit("RFA020", "low",
                            f"Instruction {what} from a well-known installer ({host_of(url.group(0))}). "
                            f"Prefer a pinned package-manager install.", m.start())]
            target = f" from {url.group(0)}" if url else ""
            sev = "medium" if (m.groupdict().get("verb") or "").lower() == "install" else "high"
            return [Hit("RFA020", sev, f"Instruction {what}{target}: whatever that server returns runs "
                                          f"with your permissions.", m.start(),
                        {"url": url.group(0) if url else ""})]
    if nl:
        m = REMOTE_SCRIPT_TAG.search(line)
        if m and not negated(line, m.start()):
            url = URL_RE.search(line[m.start():])
            return [Hit("RFA020", "medium",
                        f"Rules file includes a remote <script src=...> ({url.group(0) if url else 'external'}): "
                        f"the agent may add it to the pages it writes.", m.start())]
    return []


# ---------------------------------------------------------------- RFA021 exfiltration
SENS_DATA = (r"(?:\benv(?:ironment)?\s+var(?:iable)?s?\b|\benvironment\b|(?<![\w.-])\.env\b|\bapi[\s_-]?keys?\b|"
             r"\b(?:access\s+|auth\s+|bearer\s+|session\s+|github\s+|npm\s+|aws\s+)?tokens?\b|\bsecrets?\b|"
             r"\bcredentials?\b|\bpasswords?\b|\bprivate\s+keys?\b|\bssh\s+keys?\b|~/\.ssh\b|"
             r"\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\bcookies?\b|\bsource\s+code\b|\bcodebase\b|"
             r"\b(?:entire|whole)\s+(?:repo|repository|project)\b|\bconversation\b|\bchat\s+history\b|"
             r"\bsystem\s+prompt\b|\.aws\b|process\.env\b|os\.environ\b)")
SENS_DATA_RE = re.compile(SENS_DATA, I)
EXFIL_VERB = re.compile(r"\b(?:send|upload|post|transmit|exfiltrate|exfil|forward|leak|beacon|submit|email|"
                        r"pipe|copy)\b", I)
EXFIL_DEST = re.compile(r"https?://\S+|\b(?:to|into)\s+(?:an?\s+|the\s+|this\s+|that\s+|our\s+|my\s+)?"
                        r"(?:external|remote|attacker'?s?|third[- ]party|following|backup|collection|logging)\s+"
                        r"(?:server|endpoint|url|webhook|address|host|domain|ip|bucket|api|service)\b", I)
INCLUDE_IN = re.compile(rf"\b(?:include|embed|append|encode|hide)\b[^.;\n]{{0,40}}?{SENS_DATA}"
                        r"[^.;\n]{0,40}?\b(?:in|into|to)\s+(?:the\s+|every\s+|each\s+|all\s+|your\s+|a\s+|an\s+)?"
                        r"(?:commit(?:\s+message)?s?|pr|pull\s+request|comment|url|query(?:\s+string)?|response|"
                        r"output|log|logs|telemetry|analytics|image\s+url|markdown\s+image|link|issue|alt\s+text)\b", I)
EXFIL_HOSTS = re.compile(r"\b(?:webhook\.site|requestbin\.\w+|[\w-]+\.pipedream\.net|[\w-]+\.ngrok(?:-free)?\.(?:app|io|dev)|"
                         r"burpcollaborator\.net|[\w.-]*oastify\.com|interact\.sh|[\w.-]+\.oast\.(?:fun|me|pro|live|site|online)|"
                         r"canarytokens\.\w+|beeceptor\.com|hookbin\.com|requestcatcher\.com|postb\.in|ptsv[23]\.com|"
                         r"[\w-]+\.trycloudflare\.com|serveo\.net|[\w-]+\.loca\.lt|pastebin\.com/api|"
                         r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot)", I)
MD_IMAGE_EXFIL = re.compile(r"!\[[^\]\n]*\]\(\s*https?://[^)\s]*(?:\{|\$|%7B|<[A-Za-z_]+>)", I)
NET_CMD = re.compile(r"\b(?:curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm|nc|ncat|netcat|scp|"
                     r"rsync|ftp|sftp)\b", I)
UPLOAD_FLAG = re.compile(r"(?:\s-d\b|\s--data(?:-\w+)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|"
                         r"\s-X\s*['\"]?(?:POST|PUT|PATCH)\b|--post-(?:data|file)|\s-Method\s+(?:Post|Put)\b|"
                         r"\s-InFile\b|\s-Body\b)")
HEADER_ARG = re.compile(r"(?:\s-H|\s--header|\s-u|\s--user|\s-Headers)\s+(\"[^\"]*\"|'[^']*'|@\{[^}]*\}|\S+)", I)
CMD_SENSITIVE = re.compile(r"\$\(|`[^`]+`|\$\{?[A-Za-z_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|PASS|CRED|AUTH)[A-Za-z_]*\}?|"
                           r"\$env:\w+|~/\.ssh|\.ssh/|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|(?<![\w.-])\.env\b(?!\.example)|"
                           r"\.aws/|\.netrc\b|\.npmrc\b|\.git-credentials\b|/etc/(?:passwd|shadow)|\bprintenv\b|"
                           r"\benv\s*\||process\.env|os\.environ|\$HOME", I)


def detect_exfil(line: str, nl: bool, hook: bool = False) -> list[Hit]:
    m = EXFIL_HOSTS.search(line)
    if m and not (nl and negated(line, m.start())):
        return [Hit("RFA021", "high", f"Rules reference {m.group(0)}, a request-capture / tunnel service used to "
                                      f"receive exfiltrated data.", m.start())]
    m = MD_IMAGE_EXFIL.search(line)
    if m and not (nl and negated(line, m.start())):
        return [Hit("RFA021", "high", "Markdown image whose URL is filled in with data: when the agent's output is "
                                      "rendered, the image request sends that data to the host.", m.start())]
    m = NET_CMD.search(line)
    if m:
        rest = HEADER_ARG.sub(" ", line[m.start():])      # tokens sent in auth headers to an API are normal
        urls = external_urls(rest)
        url_has_subst = any(re.search(r"\$\(|`", u.group(0)) or CMD_SENSITIVE.search(u.group(0)) for u in urls)
        sens = CMD_SENSITIVE.search(rest)
        what = sens.group(0) if sens else "command output"
        if hook and not sens and re.search(r"@-|\$\(\s*cat\s*\)", rest):
            sens, what = True, "the hook's JSON input: tool names, arguments, file contents"
        if urls and ((UPLOAD_FLAG.search(rest) and sens) or url_has_subst) and not (nl and negated(line, m.start())):
            return [Hit("RFA021", "high",
                        f"Command sends local data ({_short(what, 60)}) "
                        f"to {host_of(urls[0].group(0).rstrip('.,;:'))}.", m.start(),
                        {"url": urls[0].group(0)})]
        if re.match(r"(?:scp|rsync)\b", m.group(0), I) and sens and re.search(r"\S+@[\w.-]+:", rest) \
                and not (nl and negated(line, m.start())):
            return [Hit("RFA021", "high", "Command copies secret files to a remote host.", m.start())]
    if not nl:
        return []
    m = re.search(r"\bexfiltrat\w*", line, I)
    if m and not negated(line, m.start()):
        return [Hit("RFA021", "high", f"Instruction mentions exfiltrating data: \"{_short(line[m.start():])}\"",
                    m.start())]
    for v in EXFIL_VERB.finditer(line):
        clause_end = _clause_end(line, v.end())
        clause = line[v.end():clause_end]
        s = SENS_DATA_RE.search(clause)
        d = EXFIL_DEST.search(clause)
        if s and d and not negated(line, v.start()):
            dest = d.group(0)
            if dest.lower().startswith("http") and not is_external(dest.rstrip(".,;:")):
                continue
            return [Hit("RFA021", "high",
                        f"Instruction to {v.group(0).lower()} {s.group(0)} to {_short(dest, 60)}.", v.start(),
                        {"url": dest if dest.startswith("http") else ""})]
    m = INCLUDE_IN.search(line)
    if m and not negated(line, m.start()):
        return [Hit("RFA021", "high", f"Instruction to put secrets or private data where they leave the machine: "
                                      f"\"{_short(m.group(0))}\"", m.start())]
    return []


def _clause_end(line: str, start: int) -> int:
    m = re.compile(r"[.!?;](?=\s|$)|\n").search(line, start)
    return m.start() if m else len(line)


# ---------------------------------------------------------------- RFA022 secret files
STRONG_SECRET_PATH = (r"(?:~/\.ssh(?:/id_\w+|/\*|/\*\*)?(?=[\s'\"`),:;]|$|/(?:\s|$))|\$HOME/\.ssh\b|%USERPROFILE%\\\.ssh|"
                      r"\.ssh/id_\w+|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.aws/credentials\b|"
                      r"application_default_credentials\.json|\.config/gcloud\b|\.azure/\w|\.kube/config\b|"
                      r"\.docker/config\.json|(?<![\w.-])\.netrc\b|(?<![\w.-])\.git-credentials\b|\.pypirc\b|"
                      r"\.config/gh/hosts\.yml|/etc/shadow\b|/proc/self/environ\b|\.gnupg\b|\.password-store\b|"
                      r"\bwallet\.dat\b)")
ENV_FILE = r"(?<![\w.-])\.env(?:\.(?:local|production|prod|development|dev|staging|test))?\b(?![.\w-])"
STRONG_RE = re.compile(STRONG_SECRET_PATH, I)
ENV_RE = re.compile(ENV_FILE, I)
READ_CMD = re.compile(r"\b(?:cat|type|more|less|head|tail|get-content|gc|base64|xxd|od|hexdump|strings|cp|copy|"
                      r"scp|tar|zip|7z|readfile|readfilesync|read_text|read_bytes|grep|rg|findstr|select-string)\b", I)
READ_VERB = re.compile(r"\b(?:read|reads|open|print|output|show|display|dump|reveal|list|collect|gather|extract|"
                       r"grab|harvest|retrieve|access|load|include|paste|echo|copy|cat|base64[- ]encode|encode)\b", I)
ENV_VERB = re.compile(r"\b(?:print|output|show|display|dump|reveal|cat|echo|paste|include|embed|upload|send|post|"
                      r"base64|encode|leak)\b", I)
HARVEST = re.compile(r"\b(?:collect|gather|extract|dump|harvest|grab|steal|scrape|enumerate)\b[^.;\n]{0,30}?"
                     r"\b(?:all|every|any|the\s+user'?s|users'?|stored|saved|local|their|your)\b[^.;\n]{0,20}?"
                     r"\b(?:api[\s_-]?keys?|tokens?|secrets?|credentials?|passwords?|private\s+keys?|ssh\s+keys?|"
                     r"cookies?|env(?:ironment)?\s+var(?:iable)?s?)\b", I)


def detect_secret_read(line: str, nl: bool) -> list[Hit]:
    for sm in STRONG_RE.finditer(line):
        before = line[max(0, sm.start() - 80):sm.start()]
        cmd = list(READ_CMD.finditer(before))
        verb = list(READ_VERB.finditer(before)) if nl else []
        cand = (cmd or verb)
        if cand:
            start = max(0, sm.start() - 80) + cand[-1].start()
            if not (nl and negated(line, start)):
                return [Hit("RFA022", "high", f"Instruction to read {sm.group(0)}: secrets go into the model "
                                              f"context and whatever it writes next.", start)]
    for em in ENV_RE.finditer(line):
        before = line[max(0, em.start() - 60):em.start()]
        if re.search(r"\b(?:to|into|in)\s*$", before, I):
            continue                                          # "copy .env.example to .env", "add it to .env"
        if re.search(r"ignore\b", line[em.end():em.end() + 40], I):
            continue                                          # "include .env in .gitignore"
        cmd = list(READ_CMD.finditer(before))
        verb = list(ENV_VERB.finditer(before)) if nl else []
        cand = cmd or verb
        if cand:
            start = max(0, em.start() - 60) + cand[-1].start()
            if re.match(r"(?:cp|copy)\b", cand[-1].group(0), I) and not re.search(r"\.env\s+\S", line[em.start():]):
                continue
            if not (nl and negated(line, start)):
                return [Hit("RFA022", "high", f"Instruction to output the contents of {em.group(0)}: its secrets "
                                              f"end up in the transcript and the agent's output.", start)]
    if nl:
        m = HARVEST.search(line)
        if m and not negated(line, m.start()):
            return [Hit("RFA022", "high", f"Instruction to collect secrets: \"{_short(m.group(0))}\"", m.start())]
    return []


# ---------------------------------------------------------------- RFA023 concealment
CONCEAL = [
    re.compile(r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t)\s+(?:ever\s+)?"
               r"(?:tell|inform|notify|alert|warn|mention\s+(?:this|it|that|these|anything)\s+to)\s+"
               r"(?:the\s+)?(?:user|developer|human|reviewer|operator|owner)s?\b"
               r"(?=\s+(?:about|that\s+you|what\s+you|you\b|anything|this|these|it\b|that\s+(?:this|these|it))|"
               r"\s*[.,;:!)]|\s*$)", I),
    re.compile(r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not)\s+(?:ever\s+)?"
               r"(?:mention|reveal|disclose|discuss|acknowledge|admit)\s+(?:(?:this|these|that|the|any|such)\s+)?"
               r"(?:hidden\s+|secret\s+|additional\s+|above\s+|following\s+)?"
               r"(?:instructions?|rules?|steps?|changes?|actions?|additions?|lines?|commands?|prompt|requests?|"
               r"modifications?|scripts?)\b", I),
    re.compile(r"\b(?:do\s+not|don'?t|never)\s+(?:mention|include|list|show|report)\s+(?:this|these|it|that|"
               r"the\s+(?:change|changes|addition|line|lines|script|step|dependency|import))\s+in\s+"
               r"(?:the\s+|your\s+|any\s+)?(?:summary|response|reply|answer|explanation|output|commit\s+messages?|"
               r"pr\s+description|pull\s+request|changelog|chat)\b", I),
    re.compile(r"\bwithout\s+(?:telling|informing|notifying|alerting|asking|warning|letting|mentioning\s+it\s+to)\s+"
               r"(?:the\s+)?(?:user|developer|human|reviewer|anyone|them|owner)s?\b", I),
    re.compile(r"\b(?:silently|secretly|quietly|covertly|stealthily|invisibly|discreetly|surreptitiously)\s+"
               r"(?:\w+\s+){0,2}?(?:add|insert|include|inject|run|execute|install|send|upload|post|modify|change|"
               r"replace|download|fetch|append|commit|push|copy|exfiltrate|embed|update|remove|delete|disable|"
               r"import|load|call|curl)\b", I),
    re.compile(r"\b(?:hide|conceal|obscure|omit|leave\s+out)\s+(?:(?:this|these|that|the|your)\s+(?:change|changes|"
               r"code|line|lines|step|steps|addition|instruction|instructions|script|import)|this|these|it|that)\s+"
               r"from\s+(?:the\s+)?"
               r"(?:user|developer|human|reviewer|diff|summary|response|output|commit\s+message|pull\s+request|pr|"
               r"changelog|explanation)s?\b", I),
]
# phrases whose own words already carry the negation; anything before them is checked
def detect_concealment(line: str) -> list[Hit]:
    for pat in CONCEAL:
        for m in pat.finditer(line):
            if negated(line, m.start()):        # "Never change files without telling the user"
                continue
            return [Hit("RFA023", "high", f"Instruction to hide what the agent does: \"{_short(m.group(0), 70)}\"",
                        m.start())]
    return []


# ---------------------------------------------------------------- RFA024 override
OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+)?"
    r"(?:previous|prior|above|earlier|preceding|original|system|safety|other|existing)\s+"
    r"(?:instructions?|rules?|prompts?|guidelines?|directives?|guardrails?)\b|"
    r"\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|unrestricted|god)\s+mode\b|"
    r"\b(?:new|updated)\s+system\s+prompt\s*:", I)


def detect_override(line: str) -> list[Hit]:
    m = OVERRIDE.search(line)
    if m and not negated(line, m.start()):
        return [Hit("RFA024", "medium", f"Prompt-injection phrase: \"{_short(m.group(0), 70)}\"", m.start())]
    return []


# ---------------------------------------------------------------- RFA030 disable safety
_CHECKS = (r"(?:(?:unit|e2e|integration|failing|flaky|the|all|any)\s+)*(?:tests?|test\s+suites?|specs|linters?|"
           r"linting|lint(?:\s+(?:checks?|rules?|errors?))?|eslint|ruff|flake8|pylint|mypy|pyright|"
           r"type[- ]?check(?:ing|s|er)?|security\s+(?:checks?|scans?|scanning|tests?|rules?|review|hooks?)|sast|"
           r"codeql|dependabot|snyk|semgrep|bandit|secret\s+scanning|pre-commit(?:\s+hooks?)?|git\s+hooks|"
           r"ci(?:\s+checks?)?|status\s+checks|code\s+review|branch\s+protection|signature\s+verification|"
           r"ssl\s+verification|certificate\s+(?:verification|validation|checks?)|tls\s+verification|"
           r"csrf\s+protection|auth(?:entication)?\s+checks?|input\s+validation|sandbox(?:ing)?|"
           r"permission\s+(?:checks?|prompts?)|approvals?)")
SKIP_CHECKS = re.compile(rf"\b(?:skip|disable|bypass|turn\s+off|switch\s+off|remove|delete|comment\s+out|silence|"
                         rf"suppress|circumvent)\s+(?:all\s+|the\s+|any\s+|running\s+|of\s+the\s+)*{_CHECKS}\b", I)
_SCOPED = re.compile(r"^\s*(?:\w+\s+){0,3}?(?:for|in|on|when|if|unless|only|during)\b"
                     r"(?!\s+(?:all|every|any|ci|the\s+ci|production|prod|main|the\s+(?:repo|repository|project)|"
                     r"this\s+(?:repo|repository|project))\b)", I)
NO_VERIFY = re.compile(r"(?:--no-verify\b|\bHUSKY=0\b|\bHUSKY_SKIP_HOOKS\b|\bSKIP_HOOKS?=)", I)
SUPPRESS_COMMENTS = re.compile(r"\b(?:add|use|put|insert|prepend)\b[^.;\n]{0,40}?(?:eslint-disable(?!-next-line|-line)|"
                               r"@ts-nocheck|#\s?nosec|//\s?nolint|#\s?type:\s?ignore|#\s?noqa)\b[^.;\n]{0,40}?"
                               r"\b(?:every|all|each|any|top\s+of)\b", I)
TLS_OFF = re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0|\brejectUnauthorized\s*:\s*false|"
                     r"\bverify\s*=\s*False\b|\bcurl\b[^|\n]*\s(?:-k|--insecure)\b|\bwget\b[^|\n]*--no-check-certificate|"
                     r"\bhttp\.sslVerify\s+false|\bstrict-ssl\s*[= ]\s*false|\b--trusted-host\b|\bPYTHONHTTPSVERIFY\s*=\s*0|"
                     r"\bGIT_SSL_NO_VERIFY\b", I)
AGENT_NO_APPROVAL = re.compile(r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|"
                               r"--permission-mode[ =]bypassPermissions\b|--approval-mode[ =]yolo\b|"
                               r"\b(?:gemini|codex)\b[^\n]*\s--yolo\b", I)


def detect_disable_safety(line: str, in_code: bool) -> list[Hit]:
    m = NO_VERIFY.search(line)
    if m and not negated(line, m.start()):
        return [Hit("RFA030", "medium", f"Instruction bypasses git hooks ({m.group(0)}).", m.start())]
    m = AGENT_NO_APPROVAL.search(line)
    if m and not negated(line, m.start()):
        return [Hit("RFA030", "medium", f"Instruction runs a coding agent with approvals switched off ({m.group(0)}).",
                    m.start())]
    m = TLS_OFF.search(line)
    if m and not negated(line, m.start()):
        return [Hit("RFA030", "medium", f"Instruction turns off TLS certificate verification ({_short(m.group(0), 50)}).",
                    m.start())]
    if not in_code:
        for m in SKIP_CHECKS.finditer(line):
            if negated(line, m.start()) or _SCOPED.match(line[m.end():]):
                continue
            return [Hit("RFA030", "medium", f"Instruction to {_short(m.group(0), 60)}.", m.start())]
        m = SUPPRESS_COMMENTS.search(line)
        if m and not negated(line, m.start()):
            return [Hit("RFA030", "medium", f"Instruction to add check-suppression comments broadly: "
                                            f"\"{_short(m.group(0), 70)}\"", m.start())]
    return []


# ---------------------------------------------------------------- RFA031 registries
OFFICIAL_REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "pypi.python.org",
                       "files.pythonhosted.org", "proxy.golang.org", "rubygems.org", "crates.io",
                       "index.crates.io", "repo.maven.apache.org", "repo1.maven.org", "api.nuget.org")
REGISTRY_SET = re.compile(
    r"(?:\b(?:npm|pnpm|yarn)\s+config\s+set\s+(?:@[\w-]+:)?(?:registry|npmRegistryServer)\b[ =]*(\S*)|"
    r"\byarn\s+config\s+set\s+npmRegistryServer\s+(\S+)|"
    r"--registry[ =](\S+)|"
    r"^\s*(?:@[\w-]+:)?registry\s*=\s*(https?://\S+)|"
    r"\bnpmRegistryServer\s*:\s*['\"]?(\S+?)['\"]?\s*$|"
    r"\bpip3?\s+config\s+set\s+\S*index-url\s+(\S+)|"
    r"--extra-index-url[ =](\S+)|--index-url[ =](\S+)|\bpip3?\s+install\b[^\n]*\s-i\s+(\S+)|"
    r"\b(?:PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|UV_EXTRA_INDEX_URL|UV_DEFAULT_INDEX|UV_INDEX|"
    r"NPM_CONFIG_REGISTRY|npm_config_registry)\s*=\s*['\"]?(\S+?)['\"]?(?:\s|$)|"
    r"\bGOPROXY\s*=\s*['\"]?(\S+?)['\"]?(?:\s|$)|\bgo\s+env\s+-w\s+GOPROXY=(\S+)|"
    r"\bgem\s+sources\s+(?:--add|-a)\s+(\S+))", I | re.M)
INSTALL_FROM_URL = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:i|install|add)\b[^\n|;&]*?\s(git\+\S+|https?://\S+|github:\S+)|"
    r"\b(?:pip3?|uv\s+pip|pipx|uv)\s+(?:install|add)\b[^\n|;&]*?\s(git\+\S+|https?://\S+)", I)


def detect_registry(line: str) -> list[Hit]:
    m = REGISTRY_SET.search(line)
    if m and not negated(line, m.start()):
        value = next((g for g in m.groups() if g), "")
        value = value.strip("'\"`,)").rstrip(".,;:`'\")")
        h = host_of(value) if "://" in value else value.lower()
        extra_index = "extra-index" in m.group(0).lower() or "EXTRA_INDEX" in m.group(0).upper()
        if extra_index:
            return [Hit("RFA031", "medium", f"Instruction adds an extra package index ({_short(value, 60)}): "
                                            f"dependency confusion, the highest version on any index wins.", m.start())]
        goproxy = "goproxy" in m.group(0).lower()
        if goproxy and all(p.strip() in ("https://proxy.golang.org", "direct", "off", "")
                           for p in re.split(r"[,|]", value)):
            return []
        if any(h == r or h.endswith("." + r) for r in OFFICIAL_REGISTRIES) or not value:
            return []
        return [Hit("RFA031", "medium", f"Instruction changes the package registry to {_short(value, 60)}: "
                                        f"packages would come from a source you have not vetted.", m.start(),
                    {"url": value})]
    m = INSTALL_FROM_URL.search(line)
    if m and not negated(line, m.start()):
        src = next(g for g in m.groups() if g)
        return [Hit("RFA031", "medium", f"Instruction installs a package straight from {_short(src, 60)}, bypassing "
                                        f"the registry and the lockfile.", m.start(), {"url": src})]
    return []


# ---------------------------------------------------------------- RFA032 lifecycle scripts
LIFECYCLE = re.compile(r"[\"'](?:preinstall|postinstall|install)[\"']\s*:\s*[\"']|"
                       r"\b(?:add|create|insert|include|write|set\s+up|define|register)\b[^.;\n]{0,50}?"
                       r"\b(?:pre-?install|post-?install)\b(?:\s+(?:script|hook|step))?", I)


def detect_lifecycle(line: str) -> list[Hit]:
    m = LIFECYCLE.search(line)
    if m and not negated(line, m.start()):
        return [Hit("RFA032", "medium", f"Instruction adds an install-time script: \"{_short(m.group(0), 70)}\"",
                    m.start())]
    return []


# ---------------------------------------------------------------- RFA051 remote rules
REMOTE_IMPORT = re.compile(r"(?:^|\s)@(https?://\S+)", I)
REMOTE_FETCH = re.compile(
    r"\b(?:fetch|load|download|pull|import|retrieve|curl|wget)\b[^.;\n]{0,60}?"
    r"\b(?:rules?|instructions?|guidelines?|prompts?|system\s+prompts?|directives?|policies|conventions|"
    r"cursorrules|claude\.md|agents\.md)\b[^.;\n]{0,40}?\b(?:from|at)\s+<?(https?://[^\s>)]+)|"
    r"(https?://[^\s>)]+)[^.;\n]{0,40}?\b(?:and|then)\s+(?:follow|obey|apply|execute|do)\s+"
    r"(?:the\s+|its\s+|any\s+|all\s+)?(?:instructions?|rules?|steps?|commands?|what\s+it\s+says)\b", I)
FOLLOW_AT = re.compile(r"\b(?:follow|obey|apply|use|read)\s+(?:the\s+|all\s+|any\s+)?(?:instructions?|rules?|guidelines?)\s+"
                       r"(?:at|from|in|on)\s+<?(https?://[^\s>)]+)", I)


def detect_remote_rules(line: str) -> list[Hit]:
    for pat, sev, what in ((REMOTE_IMPORT, "medium", "imports instructions from"),
                           (REMOTE_FETCH, "medium", "tells the agent to fetch instructions from"),
                           (FOLLOW_AT, "low", "tells the agent to follow rules published at")):
        m = pat.search(line)
        if m and not negated(line, m.start()):
            url = next(g for g in m.groups() if g).rstrip(".,;:")
            if not is_external(url):
                continue
            return [Hit("RFA051", sev, f"Rules file {what} {url}: whoever controls that URL controls the agent.",
                        m.start(), {"url": url})]
    return []


# ---------------------------------------------------------------- entry points
def detect_instruction_line(line: str, in_code: bool) -> list[Hit]:
    """All detectors for one line of an instruction file."""
    line = line.replace("\u2019", "'")          # curly apostrophes (same length, offsets unchanged)
    hits: list[Hit] = []
    hits += detect_remote_code(line, nl=True)
    hits += detect_exfil(line, nl=True)
    hits += detect_secret_read(line, nl=True)
    hits += detect_concealment(line)
    hits += detect_override(line)
    hits += detect_disable_safety(line, in_code)
    hits += detect_registry(line)
    hits += detect_lifecycle(line)
    hits += detect_remote_rules(line)
    return hits


def detect_command(cmd: str, hook: bool = False) -> list[Hit]:
    """Detectors for a shell command found in a config file (hooks, helpers, MCP args)."""
    hits: list[Hit] = []
    hits += detect_remote_code(cmd, nl=False)
    hits += detect_exfil(cmd, nl=False, hook=hook)
    hits += detect_secret_read(cmd, nl=False)
    return hits


INSTRUCTION_LIKE = re.compile(
    r"\b(?:assistant|ai|agent|llm|model|claude|copilot|cursor|gemini|codex|windsurf|cline|aider|chatgpt|"
    r"you\s+(?:must|should|will|are\s+to|need\s+to)|from\s+now\s+on|system\s+prompt|instructions?)\b", I)
