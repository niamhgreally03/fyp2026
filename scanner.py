# scanner.py

import requests   #http client (downloads html, sees cookies from headers)
from urllib.parse import urlparse, urljoin   # parse-separates scheeme/host/path (used to force https), join-converts relativr links into absolute ones(privacy policy link detection)
from bs4 import BeautifulSoup    # parses html into a searchable structure (find links/scripts/forms)

from ai_assessor import assess_form_with_openai


# --- Pattern lists ---
TRACKER_PATTERNS = [
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "connect.facebook.net",
    "doubleclick.net",
    "hotjar.com",
    "clarity.ms",
    "linkedin.com/insight",
    "snap.licdn.com",
]

NON_ESSENTIAL_COOKIE_PREFIXES = [
    "_ga", "_gid", "_gat", "_fbp", "fr", "IDE"
]

# Weights (sum to 100) # Weights based on Irish DPC priorities
WEIGHTS = {
    "HTTPS / SSL Enabled": 25,
    "Cookies (Header Check)": 30,
    "Privacy Policy (Validated)": 25,
    "Forms & Consent (Structure)": 15,
    "Tracker Indicators (Advisory)": 5,
}

RECOMMENDATIONS = {
    "HTTPS / SSL Enabled": (
        "Enable HTTPS site-wide and ensure a valid SSL/TLS certificate is installed "
        "(supports GDPR security expectations under Article 32)."
    ),
    "Cookies (Header Check)": (
        "Review cookies set on first page load. Ensure non-essential cookies (analytics/ads) "
        "are not placed until the user gives valid consent (DPC cookie guidance)."
    ),
    "Privacy Policy (Validated)": (
        "Add a clearly labelled Privacy Policy link in the footer/header and ensure the page is reachable "
        "and provides transparency information required under GDPR (Articles 12–13)."
    ),
    "Forms & Consent (Structure)": (
        "Review homepage forms that appear to collect personal data. "
        "Where consent is relied upon, ensure checkboxes are not pre-ticked. "
        "Provide clear privacy/transparency information near the form and link to the Privacy Policy."
    ),
    "Tracker Indicators (Advisory)": (
        "Known tracking-related technologies appear to be referenced in the page source. "
        "Manually review whether they activate before consent and whether cookie/privacy disclosures are accurate."
    ),
}


# cleans input, ensures the url has a scheme (https://), if missing, defaults to HTTPS
#EG most users type example.com not https://example.com
#gdpr relevance - supports a security first assumption: https by default is aligned with secure-by-design thinking (GDPR security expectations) though gdpr doesnt explicitly say default ot gttps it supports article 32 check strategy
def normalize_url(url: str) -> str:
    """Ensure URL has a scheme; default to https:// if missing."""
    url = url.strip()
    if not url:
        raise ValueError("Empty URL")

    parsed = urlparse(url)
    if not parsed.scheme:
        return "https://" + url
    return url

#Downloads the website homepage HTML( or landing page after redirects)
#captures: statis codes, response headers, cookies set by server in Set-Cookie
#limitations- this is a request only approach, it doesnt execute javascript, it may miss cookies or trackers that are loaded after page render
# this limitatation is more important on large enterprises that use tag managers, js frameworks and consent tools
def fetch_response(url: str, timeout: int = 8):
    """Fetch a URL and return (response or None, error_message or None)."""
    try:
        url = normalize_url(url)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            )
        }
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return resp, None
    except Exception as e:
        return None, str(e)


#def extract_forms_snippets(html: str, limit: int = 5) -> list[str]:
#    """Return up to `limit` <form>...</form> snippets for AI review."""
#    soup = BeautifulSoup(html, "html.parser")
#    forms = soup.find_all("form")
#    return [str(f) for f in forms[:limit]]


#def extract_visible_text_excerpt(html: str, limit: int = 3500) -> str:
#    """Extract visible text so AI can see notices near forms/footer."""
#    soup = BeautifulSoup(html, "html.parser")
#    return soup.get_text(separator=" ", strip=True)[:limit]


# -----------------------
# Checks
# -----------------------

#" can i reach this site over https without ssl errors"
#this connects to GDPR article 32:security of processing. requires "appropriate technical and organisational measures" considering risk; it explicitly mentions encryption as an example measure. https/tls is transport encryption
#"HTTPS IS not the whole of gdpr security, but its a baseline control for protecting personal data in transit"
#doesnt prove - doesnt validate hsts or tsl config strength, doesnt verify secure cookie flags, doesnt verify server-side access controls, patching, logging etc

def check_https(url: str, timeout: int = 5):
    """Check whether the site is reachable over HTTPS."""
    url_norm = normalize_url(url)
    parsed = urlparse(url_norm)
    https_url = parsed._replace(scheme="https").geturl()

    try:
        resp = requests.get(https_url, timeout=timeout, allow_redirects=True)
        return {"ok": True, "detail": f"HTTPS reachable (status code {resp.status_code})."}
    except requests.exceptions.SSLError as e:
        return {"ok": False, "detail": f"SSL error: {e}"}
    except requests.exceptions.ConnectionError as e:
        return {"ok": False, "detail": f"Connection error: {e}"}
    except requests.exceptions.Timeout:
        return {"ok": False, "detail": "Connection timed out when trying HTTPS."}
    except Exception as e:
        return {"ok": False, "detail": f"Unexpected error: {e}"}



#this only detects cookies set by server headers on the initial http response. thats usually "Set-Cookies" headers returned immediately
#it doesnt detect cookies that are set later  by javascript(common with GA, FB pixel, etc, depednign on setup)
#why it matters for irish DPC- the dpc is clear that cookies/tracking generally require consent, except for strictly necessary cases. the legal root is ePrivacy tules(transposed into irish law via S.I. 336/2011), commonly referred to as regulation 5(3) in ireland
#gdpr- when consent is used, dpc guidance aligns it with the gdpr consent standard: freely given, specific, informed, unambiguous and a " clear affirmative act"
# i used cookie name prefixes (_ga, _gid, _fbp, IDE) because they are commonly associated with analytics/ads.
#if those appear immediately on first load, thats a red flag that non-essential cookies may be set beofre consent.
#limitations- false negatives: trackers might set cookies later via js, my tool missed it
#- false positives: cookie names can be reused or customised, so prefix matching is heuristic
#-i am not classifying cookies as "strictly necessary" vs "non essential" with certainty, its flagging likel candidates.
# my tool identiifies risk indicators, not legal conclusions
def check_cookie_headers(resp: requests.Response):
    """Detect potentially non-essential cookies set immediately in the first HTTP response."""
    if resp is None:
        return {"ok": False, "detail": "No HTTP response"}

    cookies = resp.cookies
    if not cookies:
        return {"ok": True, "detail": "No cookies detected in initial HTTP response."}

    found = []
    for c in cookies:
        for prefix in NON_ESSENTIAL_COOKIE_PREFIXES:
            if c.name.startswith(prefix):
                found.append(c.name)

    if found:
        return {
            "ok": False,
            "detail": (
                "Potential non-essential cookies set before consent: "
                + ", ".join(sorted(set(found)))
            ),
        }

    return {
        "ok": True,
        "detail": (
            "Cookies set in initial response, but none match common tracking prefixes. "
            f"Count={len(cookies)}"
        ),
    }


# looks lfor anchor lags that likely point to privacy policy pages.
#uses urljoin() to support links like /privacy properly
#deduplicates links

#why matters gpdr, Transparency (“right to be informed”) is a central GDPR obligation: Articles 12–14. The dpc also highlights transparency as part of individuals rights
#the tool is testing  a minimal transparency signal: is there a discoverable policy link?,does it load successfully?does it look like it has meaning content(length threshold)?
#doesnt prove- doesnt validate whether the policy contains required article 13 items(controller identity, purposed, lawful bases, recipients, transfers, retention, rights etc)
#-doesnt check readability or clarity(article 12 requires clarity and accessibility)
#-doesnt confirm the policy matches real processing
#future work - NLP -based privacy policy completeness checks

def find_privacy_policy_links(html: str, base_url: str):
    """Find candidate privacy policy links from homepage HTML."""
    soup = BeautifulSoup(html, "html.parser")
    candidates = []

    for a in soup.find_all("a"):
        text = (a.get_text() or "").strip().lower()
        href = (a.get("href") or "").strip()
        if not href:
            continue

        href_lower = href.lower()
        if "privacy" in href_lower or "data-protection" in href_lower:
            candidates.append(urljoin(base_url, href))
            continue

        if "privacy" in text or "data protection" in text:
            candidates.append(urljoin(base_url, href))

    # Deduplicate while preserving order
    seen = set()
    out = []
    for u in candidates:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def check_privacy_policy_validated(html: str, base_url: str):
    """Validate at least one privacy policy link returns 200 and has meaningful content."""
    if not html:
        return {"ok": False, "detail": "No HTML content to analyse."}

    links = find_privacy_policy_links(html, base_url)
    if not links:
        return {"ok": False, "detail": "No privacy policy links found on homepage."}

    for link in links[:3]:
        resp, err = fetch_response(link)
        if resp and resp.status_code == 200 and len(resp.text.strip()) > 500:
            # include URL so AI can fetch it
            return {"ok": True, "detail": f"Privacy policy reachable: {link}", "url": link}

    return {
        "ok": False,
        "detail": f"Privacy policy link(s) found but not validated: {', '.join(links[:3])}",
    }


#it is detecting known third party tracker "fingerprints" inside <script> tags: google tag manager, google analytics, facebook connect,double click, hotjar
#both script urls and inline js text are scanned
#why matters dpc and gdpr - trackers often involve placing/reading identifiers on devices (ePrivacy consent requirement)
#processing personal data like IP address + online identifiers (GDPR scope)
#potentially sharing with third parties and international transfers (GDPR vendor + transfer compliance)
# the tool doesnt verifiy all those deeper issues but it correctly flags: tracking technologies appear present; investigate consent and disclosures
#limitations- if trackers load dynamically after render it can be missed

def check_tracker_indicators(html: str):
    """
    Detect references to common tracking-related technologies in script tags.
    Advisory only: presence does not prove pre-consent activation or non-compliance.
    """
    if not html:
        return {
            "ok": True,
            "status": "unknown",
            "detail": "No HTML content to analyse for tracker indicators."
        }

    soup = BeautifulSoup(html, "html.parser")
    hits = set()

    for script in soup.find_all("script"):
        src = (script.get("src") or "").lower()
        inline = script.get_text(" ", strip=True).lower()

        for pattern in TRACKER_PATTERNS:
            if pattern in src or pattern in inline:
                hits.add(pattern)

    if hits:
        return {
            "ok": True,
            "status": "review",
            "detected": sorted(hits),
            "detail": (
                "Known tracking-related script references detected: "
                + ", ".join(sorted(hits))
                + ". Presence alone does not confirm pre-consent activation or legal non-compliance."
            ),
        }
    return {
        "ok": True,
        "status": "not_detected",
        "detected": [],
        "detail": "No common tracking-related script references detected in page source.",
    }

#html driven check
#it finds forms, for each input detects "personal data like fields" (email/phone/name), detects checkboxes and whether they are pre checked
#gdpr relevance- forms frequently involve collecting personal data directly from the user -article 13 applies(information at collection)
#important-  not every form requires consetn as lawful basis, some forms are necessary for contract performance or legitimate interests
#but marketing consent must be a real opt-in(no preticked boxes). the dpc strongly treat pre ticked as invalid because it is not an affirmative action
# it doesnt prove - doesnt read label text, so it cant check if consent is specific, it cant check if the checkbox if for terms acceptance vs marketing consent. - it doesnt confirm if a privaxy notice is displayed near the form

def check_forms_structure(html: str):
    """Detect forms, personal-data fields, and consent checkbox patterns."""
    """
    Advisory structural check for homepage forms.

    This check does not determine the lawful basis for processing.
    It looks for visible indicators such as personal-data fields,
    checkbox patterns, pre-ticked boxes, and nearby privacy references.
    """
    if not html:
        return {
            "ok": True,
            "status": "unknown",
            "detail": "No HTML content to analyse."
        }

    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    if not forms:
        return {
            "ok": True,
            "status": "not_applicable",
            "detail": "No forms detected on homepage."
        }

    personal_fields = 0
    checkbox_count = 0
    prechecked = 0
    privacy_signals = 0

    for form in forms:
        form_text = form.get_text(" ", strip=True).lower()

        if any(term in form_text for term in ["privacy", "data protection", "consent", "marketing"]):
            privacy_signals += 1

        for a in form.find_all("a", href=True):
            href = a["href"].lower()
            text = a.get_text(" ", strip=True).lower()
            if (
                "privacy" in href
                or "data-protection" in href
                or "privacy" in text
                or "data protection" in text
            ):
                privacy_signals += 1

        for inp in form.find_all("input"):
            t = (inp.get("type") or "").lower()
            name = (inp.get("name") or "").lower()
            placeholder = (inp.get("placeholder") or "").lower()

            if t == "email" or "email" in name or "email" in placeholder:
                personal_fields += 1
            if "phone" in name or "mobile" in name or "tel" in name or "phone" in placeholder:
                personal_fields += 1
            if "name" in name or "fullname" in name or "name" in placeholder:
                personal_fields += 1

            if t == "checkbox":
                checkbox_count += 1
                if inp.has_attr("checked"):
                    prechecked += 1

        if form.find("textarea"):
            personal_fields += 1

    if personal_fields == 0:
        return {
            "ok": True,
            "status": "not_applicable",
            "detail": f"{len(forms)} form(s) found, but no obvious personal-data fields detected."
        }

    if prechecked > 0:
        return {
            "ok": False,
            "status": "high_risk",
            "detail": (
                f"Form structure review found pre-ticked checkbox(es) ({prechecked}). "
                "This is a high-risk consent pattern and should be manually reviewed."
            )
        }

    if checkbox_count > 0 or privacy_signals > 0:
        return {
            "ok": True,
            "status": "good_indicators",
            "detail": (
                f"Homepage form(s) appear to collect personal data (signals={personal_fields}). "
                f"Supporting structure detected: checkboxes={checkbox_count}, "
                f"privacy/transparency signals={privacy_signals}. "
                "This does not by itself confirm valid GDPR consent or transparency compliance."
            )
        }

    return {
        "ok": True,
        "status": "review",
        "detail": (
            f"Homepage form(s) appear to collect personal data (signals={personal_fields}), "
            "but no obvious checkbox or privacy/transparency signal was detected in the visible form structure. "
            "Manual review recommended."
        )
    }

def extract_form_html(html: str) -> list[str]:
    """Return all form HTML blocks found on the page."""
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    return [str(form) for form in forms]



# score and recommendations
#each check has a weight, each check is pass/fail, score is justed weightes percentage of passed checks
#gdpr and dpc- the score is not a legal metric, it is an internal evaluation metric for my prototype, a way to compare enterprises(small, medium, large) consitently
#"weights reflect relative compliance importance based on cookie consent and transparency emphasis in DPC guidance, and security expectations under Article 32."
#why weights matter- dpc cookie guidance emphasis on consent requirement for tracking technologies, dpc transparency pages emphasising rights to be informed, gdpr article 32 security obligations
def calculate_weighted_score(results: dict) -> float:
    """Weighted score out of 100 based on WEIGHTS."""
    total_weight = sum(WEIGHTS.values())
    if total_weight == 0:
        return 0.0

    earned = 0
    for check_name, weight in WEIGHTS.items():
        result = results.get(check_name, {})

        # Core deterministic checks
        if check_name in [
            "HTTPS / SSL Enabled",
            "Cookies (Header Check)",
            "Privacy Policy (Validated)"
        ]:
            if result.get("ok"):
                earned += weight

        # Forms: partial scoring based on status
        elif check_name == "Forms & Consent (Structure)":
            status = result.get("status", "unknown")

            if status in ["pass", "good_indicators", "not_applicable"]:
                earned += weight
            elif status == "review":
                earned += weight * 0.5
            elif status == "unknown":
                earned += weight * 0.25
            elif status in ["fail", "high_risk"]:
                earned += 0

        # Trackers: advisory only, low influence
        elif check_name == "Tracker Indicators (Advisory)":
            status = result.get("status", "unknown")

            if status == "not_detected":
                earned += weight
            elif status == "review":
                earned += weight * 0.4
            elif status == "unknown":
                earned += weight * 0.2

    return round((earned / total_weight) * 100, 1)


def generate_recommendations(results: dict) -> list[str]:
    """Return recommendation strings for failed checks and advisory review indicators."""
    recs = []

    for check_name, result in results.items():
        if check_name == "Tracker Indicators (Advisory)":
            if result.get("status") == "review":
                recs.append(f"- **{check_name}:** {RECOMMENDATIONS[check_name]}")
            continue

        if check_name == "Forms & Consent (Structure)":
            if result.get("status") in ["fail", "high_risk", "review"]:
                recs.append(f"- **{check_name}:** {RECOMMENDATIONS[check_name]}")
            continue

        if not result.get("ok"):
            rec = RECOMMENDATIONS.get(check_name)
            if rec:
                recs.append(f"- **{check_name}:** {rec}")
            else:
                recs.append(f"- **{check_name}:** Improve this area based on GDPR/DPC guidance.")

    return recs



def run_all_checks(url: str, use_ai: bool = True):
    """Returns (results_dict, weighted_score)."""
    results = {}

    # Always run deterministic checks
    results["HTTPS / SSL Enabled"] = check_https(url)

    url_norm = normalize_url(url)
    resp, err = fetch_response(url_norm)

    if err or not resp:
        fail = {"ok": False, "detail": f"Failed to fetch page: {err}"}
        results["Cookies (Header Check)"] = fail
        results["Privacy Policy (Validated)"] = fail
        results["Forms & Consent (Structure)"] = {
            "ok": False,
            "status": "unknown",
            "detail": f"Form analysis could not be performed because page fetch failed: {err}"
        }
        results["Tracker Indicators (Advisory)"] = {
            "ok": True,
            "status": "unknown",
            "detail": f"Tracker analysis could not be performed because page fetch failed: {err}"
        }

    else:
        html = resp.text

        results["Cookies (Header Check)"] = check_cookie_headers(resp)
        results["Privacy Policy (Validated)"] = check_privacy_policy_validated(html, url_norm)
        results["Tracker Indicators (Advisory)"] = check_tracker_indicators(html)

        form_result = check_forms_structure(html)
        form_html_blocks = extract_form_html(html)

        if use_ai and form_html_blocks:
            try:
                ai_result = assess_form_with_openai(form_html_blocks)

                ai_decision = ai_result.get("decision", "Review")
                ai_reason = ai_result.get("reason", "No explanation returned.")

                original_detail = form_result.get("detail", "")

                if ai_decision == "Pass":
                    form_result = {
                        "ok": True,
                        "status": "pass",
                        "detail": f"{original_detail} AI assessment: Pass. {ai_reason}"
                    }
                elif ai_decision == "Fail":
                    form_result = {
                        "ok": False,
                        "status": "fail",
                        "detail": f"{original_detail} AI assessment: Fail. {ai_reason}"
                    }
                else:
                    form_result = {
                        "ok": True,
                        "status": "review",
                        "detail": f"{original_detail} AI assessment: Review. {ai_reason}"
                    }

            except Exception as e:
                form_result["detail"] += f" AI assessment unavailable: {str(e)}"

        results["Forms & Consent (Structure)"] = form_result

    weighted_score = calculate_weighted_score(results)
    return results, weighted_score