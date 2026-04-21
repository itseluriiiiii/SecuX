import os
from secux.Authentication_Agent import AuthenticationAgent
from secux.Network_Monitoring_Agent import NetworkMonitoringAgent
from secux.Vulnerability_Analysis_Agent import VulnerabilityAnalysisAgent
from secux.Super_Agent import SuperAgent

def test_agents():
    print("🚀 Starting SecuX Multi-Agent Health Check...\n")

    # 1. Test Authentication Agent
    auth_agent = AuthenticationAgent()
    print("Testing Authentication Agent...")
    auth_data = "User admin failed login 10 times from IP 192.168.1.50"
    auth_result = auth_agent.analyze(auth_data)
    print(f"Auth Result: {auth_result[:200]}...\n")

    # 2. Test Network Agent
    net_agent = NetworkMonitoringAgent()
    print("Testing Network Monitoring Agent...")
    net_data = "High traffic spike: 5GB outbound to unknown IP 45.33.22.11"
    net_result = net_agent.analyze(net_data)
    print(f"Network Result: {net_result[:200]}...\n")

    # 3. Test Vulnerability Agent
    vuln_agent = VulnerabilityAnalysisAgent()
    print("Testing Vulnerability Analysis Agent...")
    vuln_data = "System check: API endpoint /debug/status is public without auth."
    vuln_result = vuln_agent.analyze(vuln_data)
    print(f"Vulnerability Result: {vuln_result[:200]}...\n")

    # 4. Test Super Agent (Aggregation)
    print("Testing Super Agent Orchestration...")
    super_agent = SuperAgent()
    all_context = f"Auth Agent reports: {auth_result}\nNetwork Agent reports: {net_result}\nVulnerability Agent reports: {vuln_result}"
    final_report = super_agent.analyze(all_context)
    
    print("\n--- FINAL SUPER AGENT REPORT ---")
    print(final_report)
    print("---------------------------------")

if __name__ == "__main__":
    test_agents()
