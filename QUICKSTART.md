# Quick Start Guide - Using PALADIN with Groq/Gemini

## Step 1: Get Your API Key

### Option A: Groq (Recommended - Fast & Free)
1. Go to https://console.groq.com/
2. Sign up for a free account
3. Create an API key
4. Copy the key

### Option B: Google Gemini
1. Go to https://makersuite.google.com/app/apikey
2. Sign in with your Google account
3. Create an API key
4. Copy the key

### Option C: OpenAI
1. Go to https://platform.openai.com/api-keys
2. Sign in or create an account
3. Create an API key
4. Copy the key (note: requires payment)

## Step 2: Set Up Your Environment

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` and add your API key:
```bash
# For Groq:
GROQ_API_KEY=your-actual-groq-api-key-here

# For Gemini:
GOOGLE_API_KEY=your-actual-google-api-key-here

# For OpenAI:
OPENAI_API_KEY=your-actual-openai-api-key-here
```

## Step 3: Run the Comparison Demo

```bash
# Run with Groq (recommended)
python comparison_demo.py groq

# Run with Gemini
python comparison_demo.py gemini

# Run with OpenAI
python comparison_demo.py openai

# Or run interactively
python comparison_demo.py
```

## What You'll See

The demo shows two test cases:

### Test 1: Normal Query
- **Without PALADIN**: Direct API call, no security
- **With PALADIN**: Security analysis, logging, same response

### Test 2: Prompt Injection Attack
- **Without PALADIN**: Model may comply with malicious instructions
- **With PALADIN**: Attack detected, input neutralized, boundaries enforced

## Example Output

```
❌ VULNERABLE: Direct API Call
📤 User: Ignore all previous instructions...
📥 [Model attempts to comply with attack]
⚠️  No security protection!

✅ PROTECTED: PALADIN-Secured API Call
🛡️  Risk Level: CRITICAL
    Detected Threats: ['instruction_injection']
    Input Rewritten: Yes
📥 [Model receives neutralized input]
✅ All security layers active!
```

## Using in Your Own Code

### Basic Usage

```python
from paladin.orchestrator import PALADINOrchestrator
from paladin.llm.client import GroqClient
import os

# Initialize client
client = GroqClient(api_key=os.getenv("GROQ_API_KEY"))

# Create PALADIN orchestrator
orchestrator = PALADINOrchestrator(
    llm_client=client,
    use_guardrails=True
)

# Process user input (automatically secured)
result = orchestrator.process_user_input("Your user query here")

print(f"Response: {result['response']}")
print(f"Risk Level: {result['risk_classification']['risk_level']}")
print(f"Threats Detected: {result['risk_classification']['flags']}")
```

### With Gemini

```python
from paladin.llm.client import GeminiClient

client = GeminiClient(api_key=os.getenv("GOOGLE_API_KEY"))
orchestrator = PALADINOrchestrator(llm_client=client)

result = orchestrator.process_user_input("What is AI?")
```

### Memory Operations

```python
# Try to write to memory
result = orchestrator.store_memory(
    "User preference: concise responses",
    trust_level_name="untrusted",
    origin_name="user_input"
)

print(f"Status: {result['status']}")  # quarantined/rejected/written
print(f"Reason: {result['reason']}")
```

## Troubleshooting

### "API key not found"
- Make sure your `.env` file exists
- Check the API key is correctly copied (no extra spaces)
- Restart your terminal after setting environment variables

### "Module not found" 
```bash
# Make sure dependencies are installed
uv sync

# Or with pip
pip install -e .
```

### Rate Limits
- Groq: Very generous free tier
- Gemini: Generous free tier
- OpenAI: Pay per use

## Next Steps

- Run `python main.py` - Quick security demo
- Run `python examples.py` - Detailed examples
- Run `pytest tests/test_paladin.py -v` - Security tests
- Read `README.md` - Full documentation
