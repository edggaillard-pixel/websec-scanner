"""Central, bilingual catalogue of finding definitions.

Every finding the scanner can emit is declared here once, with its default
severity, scoring weight, OWASP Top 10 (2021) category, CWE reference and
localised (fr/en) title / description / recommendation templates.

Checks never hard-code wording: they call :func:`make_finding` with an id and
the dynamic evidence, and the catalogue takes care of localisation and of the
security knowledge (severity, OWASP, CWE). This keeps the check modules short
and makes the knowledge base auditable in a single file.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Severity

LANGS = ("en", "fr")


@dataclass(frozen=True)
class FindingDef:
    id: str
    severity: Severity
    owasp: str
    cwe: str
    title: dict[str, str]
    description: dict[str, str]
    recommendation: dict[str, str]
    weight: int | None = None


def _d(**kw) -> FindingDef:
    return FindingDef(**kw)


# --- Registry of every known finding ---------------------------------------
CATALOG: dict[str, FindingDef] = {
    # -- Security headers ---------------------------------------------------
    "missing_hsts": _d(
        id="missing_hsts",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-319",
        title={"en": "Missing HSTS header", "fr": "En-tête HSTS absent"},
        description={
            "en": "Strict-Transport-Security is not set, so browsers may fall back "
            "to plaintext HTTP and remain exposed to downgrade/MITM attacks.",
            "fr": "L'en-tête Strict-Transport-Security est absent : le navigateur peut "
            "retomber en HTTP clair et rester exposé aux attaques de rétrogradation (MITM).",
        },
        recommendation={
            "en": "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            "fr": "Envoyez 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
        },
    ),
    "weak_hsts": _d(
        id="weak_hsts",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-319",
        title={"en": "Weak HSTS policy", "fr": "Politique HSTS faible"},
        description={
            "en": "HSTS is present but weak: {reason}.",
            "fr": "HSTS est présent mais faible : {reason}.",
        },
        recommendation={
            "en": "Use a max-age of at least 1 year and add 'includeSubDomains'.",
            "fr": "Utilisez un max-age d'au moins 1 an et ajoutez 'includeSubDomains'.",
        },
    ),
    "missing_x_frame_options": _d(
        id="missing_x_frame_options",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-1021",
        title={"en": "No clickjacking protection", "fr": "Pas de protection anti-clickjacking"},
        description={
            "en": "Neither X-Frame-Options nor a CSP 'frame-ancestors' directive is "
            "present, so the page can be framed by third parties (clickjacking).",
            "fr": "Ni X-Frame-Options ni la directive CSP 'frame-ancestors' ne sont "
            "présentes : la page peut être encadrée par un tiers (clickjacking).",
        },
        recommendation={
            "en": "Set 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
            "fr": "Définissez 'X-Frame-Options: DENY' ou une directive CSP 'frame-ancestors'.",
        },
    ),
    "missing_x_content_type_options": _d(
        id="missing_x_content_type_options",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-693",
        title={"en": "No MIME-sniffing protection", "fr": "Pas de protection anti MIME-sniffing"},
        description={
            "en": "X-Content-Type-Options is not set to 'nosniff', so browsers may "
            "interpret responses as a different content type than declared.",
            "fr": "X-Content-Type-Options n'est pas à 'nosniff' : le navigateur peut "
            "interpréter la réponse avec un type différent de celui déclaré.",
        },
        recommendation={
            "en": "Send 'X-Content-Type-Options: nosniff'.",
            "fr": "Envoyez 'X-Content-Type-Options: nosniff'.",
        },
    ),
    "missing_referrer_policy": _d(
        id="missing_referrer_policy",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "No Referrer-Policy", "fr": "Referrer-Policy absent"},
        description={
            "en": "No Referrer-Policy is set; full URLs may leak to third-party sites.",
            "fr": "Aucune Referrer-Policy : l'URL complète peut fuiter vers des sites tiers.",
        },
        recommendation={
            "en": "Set 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
            "fr": "Définissez 'Referrer-Policy: strict-origin-when-cross-origin' (ou plus strict).",
        },
    ),
    "missing_permissions_policy": _d(
        id="missing_permissions_policy",
        severity=Severity.INFO,
        owasp="A05:2021",
        cwe="CWE-693",
        title={"en": "No Permissions-Policy", "fr": "Permissions-Policy absent"},
        description={
            "en": "No Permissions-Policy header; browser features (camera, geolocation, "
            "etc.) are not explicitly restricted.",
            "fr": "Aucun en-tête Permissions-Policy : les fonctionnalités du navigateur "
            "(caméra, géolocalisation…) ne sont pas explicitement restreintes.",
        },
        recommendation={
            "en": "Declare a Permissions-Policy that disables unused features.",
            "fr": "Déclarez une Permissions-Policy désactivant les fonctionnalités inutilisées.",
        },
    ),
    # -- Content-Security-Policy -------------------------------------------
    "missing_csp": _d(
        id="missing_csp",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-1021",
        title={"en": "No Content-Security-Policy", "fr": "Content-Security-Policy absent"},
        description={
            "en": "No CSP header is present. A CSP is the main defence-in-depth control "
            "against cross-site scripting (XSS) and data injection.",
            "fr": "Aucun en-tête CSP. La CSP est la principale défense en profondeur "
            "contre les failles XSS et l'injection de contenu.",
        },
        recommendation={
            "en": "Deploy a CSP, starting from \"default-src 'self'\" and tightening it.",
            "fr": "Déployez une CSP, en partant de \"default-src 'self'\" puis en la durcissant.",
        },
    ),
    "csp_unsafe_inline": _d(
        id="csp_unsafe_inline",
        severity=Severity.MEDIUM,
        owasp="A03:2021",
        cwe="CWE-79",
        title={"en": "CSP allows 'unsafe-inline'", "fr": "La CSP autorise 'unsafe-inline'"},
        description={
            "en": "The CSP directive '{directive}' allows 'unsafe-inline', which largely "
            "defeats the protection against inline-script XSS.",
            "fr": "La directive CSP '{directive}' autorise 'unsafe-inline', ce qui annule "
            "en grande partie la protection contre le XSS par script en ligne.",
        },
        recommendation={
            "en": "Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
            "fr": "Retirez 'unsafe-inline' et utilisez des nonces ou des hash pour l'inline.",
        },
    ),
    "csp_unsafe_eval": _d(
        id="csp_unsafe_eval",
        severity=Severity.MEDIUM,
        owasp="A03:2021",
        cwe="CWE-95",
        title={"en": "CSP allows 'unsafe-eval'", "fr": "La CSP autorise 'unsafe-eval'"},
        description={
            "en": "The CSP directive '{directive}' allows 'unsafe-eval', enabling "
            "string-to-code execution that attackers can abuse.",
            "fr": "La directive CSP '{directive}' autorise 'unsafe-eval', permettant "
            "l'exécution de code depuis des chaînes, exploitable par un attaquant.",
        },
        recommendation={
            "en": "Remove 'unsafe-eval' and refactor code that relies on eval().",
            "fr": "Retirez 'unsafe-eval' et refactorez le code qui dépend d'eval().",
        },
    ),
    "csp_wildcard_source": _d(
        id="csp_wildcard_source",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-942",
        title={"en": "CSP uses a wildcard source", "fr": "La CSP utilise une source joker"},
        description={
            "en": "The CSP directive '{directive}' allows a wildcard '*' source, which "
            "permits loading from any origin.",
            "fr": "La directive CSP '{directive}' autorise la source joker '*', ce qui "
            "permet de charger depuis n'importe quelle origine.",
        },
        recommendation={
            "en": "Replace '*' with an explicit allow-list of trusted origins.",
            "fr": "Remplacez '*' par une liste explicite d'origines de confiance.",
        },
    ),
    "csp_missing_default_src": _d(
        id="csp_missing_default_src",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-693",
        title={"en": "CSP has no default-src", "fr": "La CSP n'a pas de default-src"},
        description={
            "en": "The CSP defines no 'default-src', so resource types not covered by an "
            "explicit directive are unrestricted.",
            "fr": "La CSP ne définit pas 'default-src' : les types de ressources non "
            "couverts par une directive explicite ne sont pas restreints.",
        },
        recommendation={
            "en": "Add a restrictive 'default-src' (e.g. \"default-src 'self'\").",
            "fr": "Ajoutez un 'default-src' restrictif (ex. \"default-src 'self'\").",
        },
    ),
    "csp_missing_base_uri": _d(
        id="csp_missing_base_uri",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-693",
        title={"en": "CSP has no base-uri", "fr": "La CSP n'a pas de base-uri"},
        description={
            "en": "No 'base-uri' directive is set, allowing injected <base> tags to "
            "redirect relative URLs.",
            "fr": "Aucune directive 'base-uri' : une balise <base> injectée peut "
            "réécrire les URL relatives.",
        },
        recommendation={
            "en": "Add \"base-uri 'self'\" (or \"base-uri 'none'\").",
            "fr": "Ajoutez \"base-uri 'self'\" (ou \"base-uri 'none'\").",
        },
    ),
    # -- Cookies ------------------------------------------------------------
    "cookie_missing_secure": _d(
        id="cookie_missing_secure",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-614",
        title={"en": "Cookie without Secure flag", "fr": "Cookie sans attribut Secure"},
        description={
            "en": "Cookie(s) {names} are set over HTTPS without the 'Secure' flag and may "
            "be transmitted over plaintext HTTP.",
            "fr": "Le(s) cookie(s) {names} sont posés en HTTPS sans l'attribut 'Secure' et "
            "peuvent transiter en HTTP clair.",
        },
        recommendation={
            "en": "Add the 'Secure' attribute to all cookies.",
            "fr": "Ajoutez l'attribut 'Secure' à tous les cookies.",
        },
    ),
    "cookie_missing_httponly": _d(
        id="cookie_missing_httponly",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-1004",
        title={"en": "Cookie without HttpOnly flag", "fr": "Cookie sans attribut HttpOnly"},
        description={
            "en": "Cookie(s) {names} lack the 'HttpOnly' flag and are reachable from "
            "JavaScript, increasing the impact of XSS.",
            "fr": "Le(s) cookie(s) {names} n'ont pas l'attribut 'HttpOnly' et sont "
            "accessibles en JavaScript, ce qui aggrave l'impact d'un XSS.",
        },
        recommendation={
            "en": "Add 'HttpOnly' to cookies that do not need JS access (e.g. session).",
            "fr": "Ajoutez 'HttpOnly' aux cookies n'ayant pas besoin de JS (ex. session).",
        },
    ),
    "cookie_missing_samesite": _d(
        id="cookie_missing_samesite",
        severity=Severity.LOW,
        owasp="A01:2021",
        cwe="CWE-352",
        title={"en": "Cookie without SameSite attribute", "fr": "Cookie sans attribut SameSite"},
        description={
            "en": "Cookie(s) {names} have no explicit 'SameSite' attribute, weakening "
            "CSRF defences.",
            "fr": "Le(s) cookie(s) {names} n'ont pas d'attribut 'SameSite' explicite, ce "
            "qui affaiblit la protection contre le CSRF.",
        },
        recommendation={
            "en": "Set 'SameSite=Lax' (or 'Strict') explicitly on cookies.",
            "fr": "Définissez explicitement 'SameSite=Lax' (ou 'Strict') sur les cookies.",
        },
    ),
    # -- TLS ----------------------------------------------------------------
    "tls_cert_expired": _d(
        id="tls_cert_expired",
        severity=Severity.HIGH,
        owasp="A02:2021",
        cwe="CWE-298",
        title={"en": "TLS certificate expired", "fr": "Certificat TLS expiré"},
        description={
            "en": "The server certificate expired on {not_after}.",
            "fr": "Le certificat du serveur a expiré le {not_after}.",
        },
        recommendation={
            "en": "Renew the certificate and automate renewal (e.g. ACME).",
            "fr": "Renouvelez le certificat et automatisez le renouvellement (ex. ACME).",
        },
    ),
    "tls_cert_expiring_soon": _d(
        id="tls_cert_expiring_soon",
        severity=Severity.LOW,
        owasp="A02:2021",
        cwe="CWE-298",
        title={"en": "TLS certificate expiring soon", "fr": "Certificat TLS bientôt expiré"},
        description={
            "en": "The server certificate expires on {not_after} (in {days} days).",
            "fr": "Le certificat du serveur expire le {not_after} (dans {days} jours).",
        },
        recommendation={
            "en": "Renew before expiry and set up automated renewal.",
            "fr": "Renouvelez avant l'échéance et mettez en place le renouvellement auto.",
        },
    ),
    "tls_cert_self_signed": _d(
        id="tls_cert_self_signed",
        severity=Severity.MEDIUM,
        owasp="A02:2021",
        cwe="CWE-295",
        title={"en": "Self-signed / untrusted certificate", "fr": "Certificat auto-signé / non fiable"},
        description={
            "en": "The server certificate could not be validated against trusted CAs "
            "({reason}); clients cannot verify the server identity.",
            "fr": "Le certificat n'a pas pu être validé via une autorité de confiance "
            "({reason}) ; le client ne peut pas vérifier l'identité du serveur.",
        },
        recommendation={
            "en": "Install a certificate issued by a publicly trusted CA.",
            "fr": "Installez un certificat émis par une autorité publiquement reconnue.",
        },
    ),
    "tls_cert_hostname_mismatch": _d(
        id="tls_cert_hostname_mismatch",
        severity=Severity.MEDIUM,
        owasp="A02:2021",
        cwe="CWE-297",
        title={"en": "Certificate hostname mismatch", "fr": "Nom d'hôte du certificat incohérent"},
        description={
            "en": "The certificate is not valid for host '{host}' (subjects: {names}).",
            "fr": "Le certificat n'est pas valide pour l'hôte '{host}' (sujets : {names}).",
        },
        recommendation={
            "en": "Issue a certificate whose SAN list includes the served hostname.",
            "fr": "Émettez un certificat dont les SAN incluent le nom d'hôte servi.",
        },
    ),
    "tls_obsolete_version": _d(
        id="tls_obsolete_version",
        severity=Severity.MEDIUM,
        owasp="A02:2021",
        cwe="CWE-327",
        title={"en": "Obsolete TLS version accepted", "fr": "Version TLS obsolète acceptée"},
        description={
            "en": "The server accepts {versions}, which are deprecated and insecure.",
            "fr": "Le serveur accepte {versions}, versions dépréciées et non sûres.",
        },
        recommendation={
            "en": "Disable TLS 1.0/1.1 and serve only TLS 1.2+.",
            "fr": "Désactivez TLS 1.0/1.1 et ne servez que TLS 1.2+.",
        },
    ),
    # -- Information disclosure (banners) -----------------------------------
    "banner_version_disclosure": _d(
        id="banner_version_disclosure",
        severity=Severity.LOW,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "Software version disclosed in headers", "fr": "Version logicielle divulguée"},
        description={
            "en": "Header '{header}: {value}' discloses a component and its version, "
            "helping attackers target known vulnerabilities.",
            "fr": "L'en-tête '{header}: {value}' divulgue un composant et sa version, ce "
            "qui aide un attaquant à cibler des vulnérabilités connues.",
        },
        recommendation={
            "en": "Suppress or genericise version banners ({header}).",
            "fr": "Supprimez ou rendez générique la bannière de version ({header}).",
        },
    ),
    "banner_tech_disclosure": _d(
        id="banner_tech_disclosure",
        severity=Severity.INFO,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "Technology disclosed in headers", "fr": "Technologie divulguée dans les en-têtes"},
        description={
            "en": "Header '{header}: {value}' reveals the underlying technology stack.",
            "fr": "L'en-tête '{header}: {value}' révèle la pile technologique employée.",
        },
        recommendation={
            "en": "Remove unnecessary technology-identifying headers ({header}).",
            "fr": "Retirez les en-têtes d'identification technologique inutiles ({header}).",
        },
    ),
    # -- robots.txt ---------------------------------------------------------
    "robots_sensitive_paths": _d(
        id="robots_sensitive_paths",
        severity=Severity.INFO,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "robots.txt reveals sensitive paths", "fr": "robots.txt révèle des chemins sensibles"},
        description={
            "en": "robots.txt disallows paths that hint at sensitive areas: {paths}.",
            "fr": "robots.txt interdit des chemins laissant deviner des zones sensibles : {paths}.",
        },
        recommendation={
            "en": "Do not rely on robots.txt to hide sensitive paths; protect them server-side.",
            "fr": "Ne comptez pas sur robots.txt pour cacher des chemins ; protégez-les côté serveur.",
        },
    ),
    # -- Exposed files / directories (per category) -------------------------
    "exposed_vcs": _d(
        id="exposed_vcs",
        severity=Severity.CRITICAL,
        owasp="A05:2021",
        cwe="CWE-527",
        title={"en": "Version-control directory exposed", "fr": "Répertoire de gestion de versions exposé"},
        description={
            "en": "'{path}' is reachable (HTTP {status}); a VCS directory can leak source "
            "code, history and secrets.",
            "fr": "'{path}' est accessible (HTTP {status}) ; un répertoire VCS peut "
            "divulguer le code source, l'historique et des secrets.",
        },
        recommendation={
            "en": "Block access to VCS directories and never deploy them to production.",
            "fr": "Bloquez l'accès aux répertoires VCS et ne les déployez jamais en production.",
        },
    ),
    "exposed_env": _d(
        id="exposed_env",
        severity=Severity.CRITICAL,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "Environment / secrets file exposed", "fr": "Fichier d'environnement / secrets exposé"},
        description={
            "en": "'{path}' is reachable (HTTP {status}) and may contain credentials, API "
            "keys or other secrets.",
            "fr": "'{path}' est accessible (HTTP {status}) et peut contenir des identifiants, "
            "des clés d'API ou d'autres secrets.",
        },
        recommendation={
            "en": "Remove the file from the web root and rotate any exposed secrets.",
            "fr": "Retirez le fichier de la racine web et faites tourner les secrets exposés.",
        },
    ),
    "exposed_backup": _d(
        id="exposed_backup",
        severity=Severity.HIGH,
        owasp="A05:2021",
        cwe="CWE-530",
        title={"en": "Backup / dump file exposed", "fr": "Fichier de sauvegarde / dump exposé"},
        description={
            "en": "'{path}' is reachable (HTTP {status}); backups and dumps often contain "
            "source code or database contents.",
            "fr": "'{path}' est accessible (HTTP {status}) ; sauvegardes et dumps contiennent "
            "souvent du code source ou des données de base.",
        },
        recommendation={
            "en": "Remove backup/dump artefacts from the web root.",
            "fr": "Retirez les sauvegardes et dumps de la racine web.",
        },
    ),
    "exposed_config": _d(
        id="exposed_config",
        severity=Severity.HIGH,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "Configuration file exposed", "fr": "Fichier de configuration exposé"},
        description={
            "en": "'{path}' is reachable (HTTP {status}); configuration files may reveal "
            "credentials and internal settings.",
            "fr": "'{path}' est accessible (HTTP {status}) ; un fichier de configuration peut "
            "révéler des identifiants et des réglages internes.",
        },
        recommendation={
            "en": "Move configuration outside the web root and deny direct access.",
            "fr": "Déplacez la configuration hors de la racine web et refusez l'accès direct.",
        },
    ),
    "exposed_devfile": _d(
        id="exposed_devfile",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "Development / metadata file exposed", "fr": "Fichier de dev / métadonnées exposé"},
        description={
            "en": "'{path}' is reachable (HTTP {status}) and can leak internal information.",
            "fr": "'{path}' est accessible (HTTP {status}) et peut divulguer des informations internes.",
        },
        recommendation={
            "en": "Remove development and metadata files from production.",
            "fr": "Retirez les fichiers de développement et de métadonnées en production.",
        },
    ),
    "exposed_admin": _d(
        id="exposed_admin",
        severity=Severity.INFO,
        owasp="A05:2021",
        cwe="CWE-200",
        title={"en": "Administration interface reachable", "fr": "Interface d'administration accessible"},
        description={
            "en": "'{path}' is reachable (HTTP {status}); exposed admin interfaces widen "
            "the attack surface.",
            "fr": "'{path}' est accessible (HTTP {status}) ; une interface d'admin exposée "
            "élargit la surface d'attaque.",
        },
        recommendation={
            "en": "Restrict admin interfaces by network/VPN and strong authentication.",
            "fr": "Restreignez les interfaces d'admin (réseau/VPN) et imposez une auth forte.",
        },
    ),
    "exposed_listing": _d(
        id="exposed_listing",
        severity=Severity.MEDIUM,
        owasp="A05:2021",
        cwe="CWE-548",
        title={"en": "Directory listing enabled", "fr": "Listing de répertoire activé"},
        description={
            "en": "'{path}' returns a directory listing (HTTP {status}), exposing the file "
            "tree to anyone.",
            "fr": "'{path}' renvoie un listing de répertoire (HTTP {status}), exposant "
            "l'arborescence à tous.",
        },
        recommendation={
            "en": "Disable automatic directory indexing on the web server.",
            "fr": "Désactivez l'indexation automatique des répertoires sur le serveur web.",
        },
    ),
}


# Default per-occurrence severity overrides are not needed; checks may still
# pass severity= to make_finding when a specific case warrants it.


def localize(text_map: dict[str, str], lang: str) -> str:
    return text_map.get(lang) or text_map.get("en") or next(iter(text_map.values()), "")


def make_finding(
    finding_id: str,
    *,
    check: str,
    lang: str = "en",
    severity: Severity | None = None,
    weight: int | None = None,
    evidence: dict | None = None,
    **params,
) -> Finding:
    """Instantiate a :class:`Finding` from a catalogue entry.

    Args:
        finding_id: Key in :data:`CATALOG`.
        check: Id of the emitting check (recorded on the finding).
        lang: 'en' or 'fr' for the user-facing strings.
        severity: Optional override of the catalogue default severity.
        weight: Optional scoring-weight override.
        evidence: Machine-readable details stored verbatim on the finding.
        **params: Values substituted into the localised templates
            (e.g. ``path=...``, ``header=...``).
    """
    try:
        d = CATALOG[finding_id]
    except KeyError as exc:  # pragma: no cover - programmer error
        raise KeyError(f"Unknown finding id: {finding_id!r}") from exc

    def fmt(tmpl: str) -> str:
        try:
            return tmpl.format(**params)
        except (KeyError, IndexError):
            return tmpl

    return Finding(
        id=d.id,
        check=check,
        title=fmt(localize(d.title, lang)),
        severity=severity or d.severity,
        description=fmt(localize(d.description, lang)),
        recommendation=fmt(localize(d.recommendation, lang)),
        owasp=d.owasp,
        cwe=d.cwe,
        evidence=evidence or {},
        weight=weight if weight is not None else d.weight,
    )

# GROGNON
