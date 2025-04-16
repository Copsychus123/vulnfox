## VulnFox

VulnFox is designed to help enterprises quickly gain visibility into their assets and vulnerabilities, improve patching efficiency, and enhance cybersecurity risk management. Users can import asset lists (CSV), and the system will automatically compare them against the vulnerability database to generate risk-level reports. For each vulnerability, it provides patch recommendations, impact analysis, and other related information. Additionally, the system integrates the latest CVE vulnerability data and supports various environments such as IT, IoT, OT, and cloud. With the assistance of intelligent agents (LLM Agent), it can generate remediation suggestions and draft patching plans, helping users make more efficient cybersecurity decisions.
<br><br>

## System Advantages

- **Asset-Based Risk Management**  
   The system performs a systematic review of corporate assets, potential threats, and vulnerabilities. It identifies, assesses, and quantifies the risk matrix while documenting detailed vulnerability information. This supports precise remediation and standardized workflows, thereby reducing overall cybersecurity risk.

- **Multi-Factor Vulnerability Algorithm Assessment**  
   In addition to the traditional CVSS scoring mechanism, the system integrates mechanisms such as EPSS and KEV to evaluate the actual exploitation risk of vulnerabilities. This results in more accurate risk prioritization, enabling a focus on the most critical threats.

- **AI Analysis and Vulnerability Ranking**  
   By combining AI analysis with a risk matrix methodology, the system helps managers quickly pinpoint the key vulnerabilities that require immediate attention. This allows for the focused allocation of remediation resources and the planning of specific remediation strategies and schedules, ensuring more precise prioritization and resolution.

- **Patch Progress Tracking and Performance Evaluation**  
   The system not only provides patching recommendations and scheduling but also continuously records and tracks the status of patching. This assists enterprises in evaluating the effectiveness of their remediation efforts and in making timely adjustments to their cybersecurity strategy, ensuring the overall protection efficacy.

- **Enhanced Decision Reliability and Transparency**  
   Through the use of trusted AI mechanisms, the system employs “LLM as a Judge” to conduct vulnerability risk assessments, provide remediation recommendations, and set schedules. This ensures the entire process is highly transparent and traceable.

- **Integrated Vulnerability Management Process**  
   From asset inventory and vulnerability information collection to AI analysis, vulnerability ranking, remediation planning, and progress tracking, the system offers a more comprehensive and systematic vulnerability management solution. This helps enterprises respond more effectively to cybersecurity threats, save remediation resources, and promote team collaboration.

- **Zero Trust Architecture Integration (In the future)**  
   The system will integrate multiple asset discovery mechanisms such as active scanning, passive monitoring, configuration analysis, and manual analysis to provide a comprehensive oversight of cybersecurity vulnerabilities from an asset management perspective, ensuring continuous and complete asset and vulnerability monitoring.
  
![photo](https://github.com/Copsychus123/vulnfox/blob/main/asset%20risk%20management.png)
<br><br>

## Demo Video
[VulnFox](https://www.youtube.com/watch?v=G1Qdwkvx3ns "VulnFox PoC Demo")
<br>

[![VulnFox](https://i.ytimg.com/vi/G1Qdwkvx3ns/hqdefault.jpg?sqp=-oaymwEiCNACELwBSFXyq4qpAxQIARUAAIhCGAFwAcABBrgC1ZjEGA==&rs=AOn4CLCT-BuaGSCUeKCq62m2hBzdZWFjlw)](https://www.youtube.com/watch?v=G1Qdwkvx3ns)
<br><br>

## Quick Start for PoC
Follow these steps to deploy and verify the VulnFox application along with the required MongoDB database environment.

### 1. Create a Docker Network
```bash
docker network create vulnfox-network
```

### 2. Verify Container Connectivity
```bash
docker network inspect vulnfox-network
```

### 3. Run the VulnFox Container
```bash
docker run -d --network vulnfox-network -p 5000:5000 -p 8501:8501 `
  -e OPENAI_API_KEY="openai-key" `
  -e MONGODB_URI="mongodb://mongodb:27017/" `
  -e ASSET_DB="assets" `
  -e NVD_DB="nvd_db" `
  ottotsou/vulnfox:latest
```
### 4. Run the MongoDB Container
```bash
docker run -d --network vulnfox-network --name mongodb -p 27017:27017 -v mongodb-data:/data/db mongodb/mongodb-community-server:latest
```

### 5. Verify and Import MongoDB Data
Download the vulnerability data from [here](https://drive.google.com/drive/folders/1ejLWrUQ9kdWzY8iI8LQ1TGy71XZLn3gy?usp=sharing), then connect and import the data:
```bash
mongo --host 127.0.0.1 --port 27017
mongorestore --host 127.0.0.1 --port 27017 --db nvd_db nvd_db
```
<br>


## Competitor Analysis

| Item |  [AIShield](https://www.aishield.com.tw/) | [Vicarius vRx](https://www.cyberview.com.tw/vicarius/) | [VulnFox](https://github.com/Copsychus123/vulnfox/tree/main) |
| --- | :---: | :---: | :---: |
| no Agent  | ✘ | ✘ | ✘ |
| Asset Inventory  | ✅  | ✘ | ✅ |
| Vulnerability Management  | ✅  | ✅ | ✅ |
| AI Remediation Recommendation  | ✅  | ✅ | ✅ |
| AI Remediation Scheduling  | ✘ | ✅ | ✅ |
| AI Assessment Of Consequences  | ✘ | ✘ | ✅ |
| Risk Matrix   | ✘ | ✘ | ✅ |
| Patch Tracking and Logging  | ✘ | ✘ | ✅ |
| Scripted Automated Patching | ✘  | ✅ | ✘ |
| Sources  | CVSS  | &nbsp;&nbsp;&nbsp;CVSS&nbsp;&nbsp;&nbsp; | CVSS、EPSS、KEV |
| Applicable Scenarios |IT / SOC / MDR | IT | IT / OT |

<br>

## Contact Us  
Primary Contact (First Author)
- Dr. Ching-Huang Lin
- National Taipei University of Technology 
- Cybersecurity Applications Lab

Research & Development Team
- Email: t112c72007@ntut.org.tw
<br><br>

## License
VulnFox is licensed under [GPL v3 License](https://github.com/Copsychus123/vulnfox/blob/main/LICENSE.txt)
