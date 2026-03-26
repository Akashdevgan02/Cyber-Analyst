"""Provider-agnostic LLM abstraction layer.

Supports OpenAI and Anthropic. Swapping providers requires changing only
the LLM_PROVIDER env var — no application code changes.
"""

import json
from abc import ABC, abstractmethod
from typing import Dict, Any, List

from backend.config import LLM_PROVIDER, OPENAI_API_KEY, ANTHROPIC_API_KEY


SYSTEM_PROMPT = """You are a cybersecurity incident analyst. Given structured incident and timeline data,
produce a JSON response with exactly these fields:
- "summary": a 2-3 sentence plain-language explanation of what happened
- "severity": one of "low", "medium", "high", "critical"
- "suggested_actions": a list of 2-3 specific, actionable response steps

Be concise and specific. Reference actual hosts, users, and techniques from the data."""


def _build_user_prompt(incident_data: Dict[str, Any]) -> str:
    return f"""Analyze this security incident and provide your assessment.

Incident:
- Host: {incident_data.get('host', 'unknown')}
- User: {incident_data.get('user', 'unknown')}
- Severity: {incident_data.get('severity', 'unknown')}
- Event Count: {incident_data.get('event_count', 0)}

Timeline Events:
{json.dumps(incident_data.get('timeline', []), indent=2, default=str)}

Respond with valid JSON only."""


class LLMAdapter(ABC):
    @abstractmethod
    def explain_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate explanation, severity assessment, and suggested actions."""
        pass

    @abstractmethod
    def chat(self, question: str, context: str) -> str:
        """Answer an analyst's question given incident context."""
        pass


class OpenAIAdapter(LLMAdapter):
    def __init__(self):
        from openai import OpenAI
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = "gpt-4o-mini"

    def explain_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(incident_data)},
            ],
            temperature=0.3,
            response_format={"type": "json_object"},
        )
        return json.loads(response.choices[0].message.content)

    def chat(self, question: str, context: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst assistant. Answer questions about security incidents based on the provided context. Be concise and specific."},
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
            ],
            temperature=0.3,
        )
        return response.choices[0].message.content


class AnthropicAdapter(LLMAdapter):
    def __init__(self):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=ANTHROPIC_API_KEY)
        self.model = "claude-3-5-haiku-latest"

    def explain_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": _build_user_prompt(incident_data)},
            ],
        )
        text = response.content[0].text
        return json.loads(text)

    def chat(self, question: str, context: str) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system="You are a cybersecurity analyst assistant. Answer questions about security incidents based on the provided context. Be concise and specific.",
            messages=[
                {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"},
            ],
        )
        return response.content[0].text


class FallbackAdapter(LLMAdapter):
    """Used when no API key is configured. Returns template responses."""

    def explain_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        host = incident_data.get("host", "unknown")
        user = incident_data.get("user", "unknown")
        techniques = set()
        for evt in incident_data.get("timeline", []):
            if evt.get("mitre_technique"):
                techniques.add(evt["mitre_technique"])

        technique_str = ", ".join(techniques) if techniques else "unknown techniques"
        return {
            "summary": f"A multi-stage attack was detected on host {host} involving user {user}. "
                       f"The attack chain includes {technique_str}. "
                       f"Total of {incident_data.get('event_count', 0)} related events were correlated.",
            "severity": incident_data.get("severity", "medium"),
            "suggested_actions": [
                f"Isolate host {host} from the network immediately",
                f"Reset credentials for user {user}",
                f"Review all outbound connections from {host} in the last 24 hours",
            ],
        }

    def chat(self, question: str, context: str) -> str:
        return f"Based on the incident data, here is what I can tell you:\n\n{context[:500]}\n\nFor deeper analysis, configure an LLM API key in the .env file."


def get_llm_adapter() -> LLMAdapter:
    if LLM_PROVIDER == "openai" and OPENAI_API_KEY:
        return OpenAIAdapter()
    elif LLM_PROVIDER == "anthropic" and ANTHROPIC_API_KEY:
        return AnthropicAdapter()
    return FallbackAdapter()
