import os
import json
import streamlit as st
from openai import OpenAI


def assess_form_with_openai(form_html_list: list[str]) -> dict:
    api_key = os.getenv("OPENAI_API_KEY") or st.secrets.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")

    client = OpenAI(api_key=api_key)

    forms_text = "\n\n--- FORM SPLIT ---\n\n".join(form_html_list[:3])

    prompt = f"""
You are assisting a GDPR website compliance checker.
Review the HTML of website forms and return only one decision:
Pass, Fail, or Review.
Rules:
- Keep the reason short.
Decision rules:
- Pass: reasonable privacy/consent indicators and no obvious high-risk issue.
- Fail: obvious high-risk issue exists, especially pre-ticked consent checkbox(es).
- Review: personal data is collected but the structure is unclear or incomplete.
Return valid JSON only:
{{
  "decision": "Pass",
  "reason": "One short sentence explaining why."
}}

Form HTML:
{forms_text}
"""

    response = client.responses.create(
        model="gpt-4.1-mini",
        input=prompt,
    )

    output_text = response.output_text.strip()

    print("RAW AI OUTPUT:", output_text)  # debug

    try:
        start = output_text.find("{")
        end = output_text.rfind("}") + 1
        json_text = output_text[start:end]
        parsed = json.loads(json_text)

        decision = parsed.get("decision", "Review").strip().title()
        reason = parsed.get("reason", "Manual review recommended.").strip()

        if decision not in ["Pass", "Fail", "Review"]:
            decision = "Review"

        return {
            "decision": decision,
            "reason": reason
        }

    except Exception as e:
        print("JSON PARSE ERROR:", str(e))  # debug
        return {
            "decision": "Review",
            "reason": "AI response could not be parsed, so manual review is recommended."
        }