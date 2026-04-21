from ..llm_engine import LLMEngine

class SuperAgent:
    """
    Aggregate and interpret outputs from all agents:
    - Log Analysis Agent
    - Authentication Agent
    - Network Monitoring Agent
    - Vulnerability Analysis Agent
    """
    
    PROMPT = """
    You are the Super Agent in a multi-agent cybersecurity system.

    Task:
    Aggregate and interpret outputs from all agents:
    - Log Analysis Agent
    - Authentication Agent
    - Network Monitoring Agent
    - Vulnerability Analysis Agent

    Instructions:
    - Combine all findings
    - Correlate related anomalies across agents
    - Remove duplicates and noise
    - Identify overall threat patterns
    - Assign overall system threat level: LOW | MEDIUM | HIGH | CRITICAL

    Data from other agents:
    {data}

    Generate:
    1. Key Findings (concise)
    2. Threat Summary (attacker perspective)
    3. Risk Level
    4. Actionable Recommendations

    Output Format:
    Clear CLI-friendly structured text (not JSON).

    Constraints:
    - Keep output concise and readable
    - Do NOT include technical overload
    - Do NOT provide real attack steps
    - Focus on defensive insights
    """
    
    def __init__(self, name: str = "Super_Agent"):
        self.name = name
        self.llm = LLMEngine()

    def analyze(self, data_from_agents: str) -> str:
        prompt = self.PROMPT.format(data=data_from_agents)
        return self.llm.query(prompt)
