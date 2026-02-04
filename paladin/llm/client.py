"""
LLM Client abstraction.

Security rationale:
- Abstracts LLM provider details from security layers
- Enables swapping providers without changing security architecture
- All LLM calls go through this interface for auditing and control
- Provider-specific logic is isolated here
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any
import os


class LLMClient(ABC):
    """
    Abstract base class for LLM clients.
    
    Security rationale:
    - Forces consistent interface across all providers
    - Security layers depend on this interface, not specific implementations
    - Enables provider switching without security regression
    """
    
    @abstractmethod
    def generate(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """
        Generate response from LLM.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            **kwargs: Provider-specific parameters (temperature, max_tokens, etc.)
        
        Returns:
            Generated text response
        
        Security rationale:
        - Takes structured messages, not raw text
        - Ensures context assembly happens before this call
        - Return value is always treated as untrusted
        """
        pass
    
    @abstractmethod
    def validate_connection(self) -> bool:
        """
        Validate that the client can connect to the LLM provider.
        
        Returns:
            True if connection is valid
        """
        pass


class OpenAIClient(LLMClient):
    """
    OpenAI API client implementation.
    
    Security rationale:
    - Uses official OpenAI SDK for reliable API interaction
    - API key is loaded from environment, not hardcoded
    - No provider-specific security logic (security is in PALADIN layers)
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize OpenAI client.
        
        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name to use
        """
        from openai import OpenAI
        
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key must be provided or set in OPENAI_API_KEY env var")
        
        self.model = model
        self.client = OpenAI(api_key=self.api_key)
    
    def generate(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Generate response using OpenAI API."""
        # Security: All messages passed here have already gone through
        # context assembly and trust boundaries
        
        # Set defaults for kwargs
        params = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 1000),
        }
        
        response = self.client.chat.completions.create(**params)
        
        # Security: Return raw response; caller must treat as untrusted
        return response.choices[0].message.content
    
    def validate_connection(self) -> bool:
        """Validate OpenAI API connection."""
        try:
            # Test with minimal API call
            self.client.models.list()
            return True
        except Exception:
            return False


class MockLLMClient(LLMClient):
    """
    Mock LLM client for testing.
    
    Security rationale:
    - Enables testing without API costs or external dependencies
    - Can simulate malicious model outputs for security testing
    - Useful for testing prompt injection scenarios
    """
    
    def __init__(self, responses: Optional[List[str]] = None):
        """
        Initialize mock client.
        
        Args:
            responses: List of pre-defined responses to return in sequence
        """
        self.responses = responses or ["Mock LLM response"]
        self.call_count = 0
        self.call_history: List[Dict[str, Any]] = []
    
    def generate(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Return mock response."""
        # Record call for testing
        self.call_history.append({
            "messages": messages,
            "kwargs": kwargs
        })
        
        # Return response from list (cycle if needed)
        response = self.responses[self.call_count % len(self.responses)]
        self.call_count += 1
        
        return response
    
    def validate_connection(self) -> bool:
        """Mock validation always succeeds."""
        return True
    
    def set_responses(self, responses: List[str]):
        """Update mock responses."""
        self.responses = responses
        self.call_count = 0


class GroqClient(LLMClient):
    """
    Groq API client implementation.
    
    Security rationale:
    - Uses official Groq SDK for reliable API interaction
    - API key is loaded from environment, not hardcoded
    - No provider-specific security logic (security is in PALADIN layers)
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "llama-3.1-70b-versatile"):
        """
        Initialize Groq client.
        
        Args:
            api_key: Groq API key (defaults to GROQ_API_KEY env var)
            model: Model name to use (e.g., llama-3.1-70b-versatile, mixtral-8x7b-32768, gemma-7b-it)
        """
        from groq import Groq
        
        self.api_key = api_key or os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("Groq API key must be provided or set in GROQ_API_KEY env var")
        
        self.model = model
        self.client = Groq(api_key=self.api_key)
    
    def generate(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Generate response using Groq API."""
        # Security: All messages passed here have already gone through
        # context assembly and trust boundaries
        
        # Set defaults for kwargs
        params = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 1000),
        }
        
        response = self.client.chat.completions.create(**params)
        
        # Security: Return raw response; caller must treat as untrusted
        return response.choices[0].message.content
    
    def validate_connection(self) -> bool:
        """Validate Groq API connection."""
        try:
            # Test with minimal API call
            self.client.models.list()
            return True
        except Exception:
            return False


class GeminiClient(LLMClient):
    """
    Google Gemini API client implementation.
    
    Security rationale:
    - Uses official Google Generative AI SDK
    - API key is loaded from environment, not hardcoded
    - No provider-specific security logic (security is in PALADIN layers)
    """
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-pro"):
        """
        Initialize Gemini client.
        
        Args:
            api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            model: Model name to use (e.g., gemini-pro, gemini-pro-vision)
        """
        import google.generativeai as genai
        
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("Google API key must be provided or set in GOOGLE_API_KEY env var")
        
        self.model_name = model
        genai.configure(api_key=self.api_key)
        self.model = genai.GenerativeModel(model)
    
    def generate(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Generate response using Gemini API."""
        # Security: All messages passed here have already gone through
        # context assembly and trust boundaries
        
        # Gemini uses a different message format - convert from OpenAI style
        # For simplicity, concatenate messages into a single prompt
        prompt_parts = []
        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            if role == "system":
                prompt_parts.append(f"System: {content}")
            elif role == "developer":
                prompt_parts.append(f"Instructions: {content}")
            else:
                prompt_parts.append(f"User: {content}")
        
        prompt = "\n\n".join(prompt_parts)
        
        # Generate response
        response = self.model.generate_content(
            prompt,
            generation_config={
                "temperature": kwargs.get("temperature", 0.7),
                "max_output_tokens": kwargs.get("max_tokens", 1000),
            }
        )
        
        # Security: Return raw response; caller must treat as untrusted
        return response.text
    
    def validate_connection(self) -> bool:
        """Validate Gemini API connection."""
        try:
            # Test with minimal API call
            self.model.generate_content("test")
            return True
        except Exception:
            return False


class OllamaClient(LLMClient):
    """
    Ollama local LLM client implementation (for future use).
    
    Security rationale:
    - Local model execution for air-gapped deployments
    - No data leaves local network
    - Same security guarantees as cloud providers
    """
    
    def __init__(self, model: str = "llama2", base_url: str = "http://localhost:11434"):
        """
        Initialize Ollama client.
        
        Args:
            model: Ollama model name
            base_url: Ollama server URL
        """
        self.model = model
        self.base_url = base_url
        
        # Note: Actual implementation would use requests or httpx
        # to call Ollama API. Placeholder for now.
    
    def generate(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Generate response using Ollama API."""
        # Placeholder: Would make HTTP request to Ollama
        raise NotImplementedError("Ollama client not yet implemented")
    
    def validate_connection(self) -> bool:
        """Validate Ollama connection."""
        # Placeholder: Would check if Ollama server is reachable
        return False
