import os
import requests
import json
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

class LLMEngine:
    def __init__(self):
        # Configuration from environment
        self.provider = os.getenv("LLM_PROVIDER", "local").lower() # 'local' or 'google'
        self.local_model = os.getenv("LOCAL_MODEL", "llama3.2:3b")
        self.local_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/api/generate")
        
        # Google setup (optional fallback)
        self.google_api_key = os.getenv("GEMINI_API_KEY")
        if self.google_api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.google_api_key)
                self.google_model = genai.GenerativeModel("gemini-1.5-flash")
            except ImportError:
                self.google_model = None
        else:
            self.google_model = None

    def query(self, prompt: str) -> Optional[str]:
        if self.provider == "local":
            return self._query_local(prompt)
        elif self.provider == "google":
            return self._query_google(prompt)
        else:
            return f"Error: Unknown LLM provider '{self.provider}'"

    def _query_local(self, prompt: str) -> Optional[str]:
        """Query local LLM via Ollama API."""
        try:
            payload = {
                "model": self.local_model,
                "prompt": prompt,
                "stream": False
            }
            response = requests.post(self.local_url, json=payload, timeout=300)
            response.raise_for_status()
            return response.json().get("response")
        except Exception as e:
            return f"Error querying local LLM (Ollama): {str(e)}"

    def _query_google(self, prompt: str) -> Optional[str]:
        """Query Google Gemini API."""
        if not self.google_model:
            return "Error: Gemini model not initialized. Check GEMINI_API_KEY or install google-generativeai."
        
        try:
            response = self.google_model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Error querying Gemini: {str(e)}"
