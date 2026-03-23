# app.py

import streamlit as st
import pandas as pd
from scanner import run_all_checks, generate_recommendations

def main():
    st.set_page_config(page_title="GDPR Website Compliance Checker", layout="wide")

    st.title("GDPR Website Compliance Checker for Irish SMEs")

    st.write(
        "This tool performs basic **website-level GDPR checks** such as HTTPS/SSL, "
        "cookie/consent indicators, privacy policy accessibility, trackers, and form consent structure."
    )

    url = st.text_input(
        "Enter website URL",
        value="example.com",
        placeholder="e.g. example.com or https://example.com",
    )

    if st.button("Run Compliance Checks"):

        if not url.strip():
            st.error("Please enter a URL.")
            st.stop()

        with st.spinner("Running checks..."):
            results, score = run_all_checks(url, use_ai=True)

        st.markdown("---")

        # Two-column layout
        left_col, right_col = st.columns([2, 1], gap="large")

      
        with left_col:

            st.subheader(f"Weighted Compliance / Risk Indicator Score: **{score}%**")

            if score >= 85:
                st.success("Overall status: 🟢 Strong overall indicator")
            elif score >= 65:
                st.warning("Overall status: 🟡 Moderate indicator – review recommended")
            else:
                st.error("Overall status: 🔴 Weaker indicator – significant issues or uncertainty detected")

            st.markdown("### Detailed Check Results")

            rows = []

            for check_name, result in results.items():

                if check_name == "Tracker Indicators (Advisory)":
                    tracker_status = result.get("status", "unknown")

                    if tracker_status == "review":
                        status_label = "Manual review recommended"
                    elif tracker_status == "not_detected":
                        status_label = "Not detected"
                    else:
                        status_label = "Unknown"

                elif check_name == "Forms & Consent (Structure)":
                    form_status = result.get("status", "unknown")

                    if form_status == "fail":
                        status_label = "Fail"
                    elif form_status == "pass":
                        status_label = "Pass"
                    elif form_status == "high_risk":
                        status_label = "Fail"
                    elif form_status == "review":
                        status_label = "Manual review recommended"
                    elif form_status == "good_indicators":
                        status_label = "Pass"
                    elif form_status == "not_applicable":
                        status_label = "Not applicable"
                    else:
                        status_label = "Unknown"

                else:
                    status_label = "Pass" if result.get("ok") else "Fail"

                rows.append(
                    {
                        "Check": check_name,
                        "Status": status_label,
                        "Details": result.get("detail", ""),
                    }
                )

            df = pd.DataFrame(rows)

            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Check": st.column_config.Column(width=220),
                    "Status": st.column_config.Column(width=220),
                    "Details": st.column_config.Column(width=3000),
                },
            )

            st.markdown("### Recommendations")

            recs = generate_recommendations(results)

            if recs:
                st.markdown("\n".join(recs))
            else:
                st.success("No recommendations — all checks passed.")

        # What do these checks mean? (GDPR / Irish ePrivacy explanation)
        st.markdown("---")
        st.header("What the checks mean (GDPR / Irish ePrivacy context)")

        st.write(
            "Below is a guide to what each automated check is trying to detect, "
            "why it matters for GDPR compliance, and the key limitations of a *requests-only* scanner."
        )

        st.info(
            "Important: This tool is a **high-level indicator**. Passing a check does *not* guarantee compliance, "
            "and failing a check does *not* prove a legal breach. Many GDPR requirements depend on your real "
            "processing activities (what data you collect, your lawful basis, your vendors, retention, etc.)."
        )

        with st.expander("1) HTTPS / SSL Enabled — why it matters"):
            st.markdown(
                """
**What the tool checks**
- Tries to load the site using https://... and reports whether it succeeds.

**Why it matters for GDPR**
- GDPR **Article 32** expects appropriate security measures.
- HTTPS/TLS supports confidentiality and integrity for data in transit.

**What a 'pass' does NOT prove**
- It doesn’t prove strong TLS configuration (HSTS, ciphers, secure cookies).
- It doesn’t prove internal security controls (patching, access control, incident response).
"""
            )

        with st.expander("2) Cookies (Header Check) — prior consent & non-essential cookies"):
            st.markdown(
                """
**What the tool checks**
- Looks at cookies set in the *first* HTTP response (Set-Cookie headers) and flags common tracking cookies.

**Why it matters**
- Under Irish ePrivacy rules, non-essential cookies generally require **prior consent**.
- GDPR consent must be **freely given, specific, informed and unambiguous**.

**What a 'pass' does NOT prove**
- Cookies may be set later via JavaScript.
- Tracking cookies may use names not covered by the prefix list.
"""
            )

        with st.expander("3) Privacy Policy (Validated) — transparency obligations"):
            st.markdown(
                """
**What the tool checks**
- Searches for “privacy” links on the homepage.
- Tries to open candidate links and checks for reachable, non-trivial content.

**Why it matters for GDPR**
- GDPR transparency requires clear information about processing (Articles 12–14).

**What a 'pass' does NOT prove**
- It does not validate whether the privacy policy is complete or accurate.
- It doesn’t confirm your processing matches what you disclose.
"""
            )

        with st.expander("4) Tracker Indicators (Advisory) — known tracking-related script references"):
            st.markdown(
                """
**What the tool checks**
- Scans script URLs and inline script content in the homepage HTML for known tracking-related patterns.

**Why it matters**
- These technologies can be associated with analytics, advertising, profiling, or third-party data sharing.

**Important limitation**
- Detecting a tracker reference does **not** prove tracking activated before consent.
- Detecting none does **not** prove no tracking exists.
"""
            )

        with st.expander("5) Forms & Consent (Structure) — homepage form indicators"):
            st.markdown(
                """
**What the tool checks**
- Detects homepage forms and looks for personal-data-like fields such as email, name, and phone.

**Why it matters**
- Forms are common collection points for personal data.
- GDPR transparency obligations apply at the point of collection.

**Important limitation**
- A missing checkbox does **not** automatically mean non-compliance.
- This check only reviews visible structure.
"""
            )

        with st.expander("Limitations of this prototype scanner"):
            st.markdown(
                """
**This tool is intentionally lightweight**
- Uses requests to fetch HTML and scans what it can see.
- Does not execute JavaScript.

**AI-assisted analysis**
- AI output is advisory, not legal advice.

**Best use**
Use this tool as a *first-pass indicator* to highlight likely website issues to investigate further.
"""
            )

if __name__ == "__main__":
    main()