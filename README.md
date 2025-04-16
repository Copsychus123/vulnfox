## VulnFox

VulnFox is designed to help enterprises quickly gain visibility into their assets and vulnerabilities, improve patching efficiency, and enhance cybersecurity risk management. Users can import asset lists (CSV), and the system will automatically compare them against the vulnerability database to generate risk-level reports. For each vulnerability, it provides patch recommendations, impact analysis, and other related information. Additionally, the system integrates the latest CVE vulnerability data and supports various environments such as IT, IoT, OT, and cloud. With the assistance of intelligent agents (LLM Agent), it can generate remediation suggestions and draft patching plans, helping users make more efficient cybersecurity decisions.
<br><br>

## System Advantages

- **基於資產風險管理**  
  本系統進行企業資產、潛在威脅與漏洞的系統性檢查，識別、評估及量化風險矩陣，同時記錄詳盡的弱點資訊，支持精準修補與標準化流程，降低整體資安風險。

- **多因子漏洞演算法評估**  
  除了傳統的 CVSS 評分機制外，系統整合 EPSS 及 KEV 等機制評估漏洞的實際利用風險，使得風險排序更精準，從而聚焦資源於最關鍵的威脅上。
  
- **AI 分析與漏洞排序**  
  結合 AI 分析、風險矩陣方法論，幫助管理者迅速鎖定最需即時處理的關鍵漏洞，聚焦修補資源分配，並規劃具體修補策略與計畫，確保排序更準確，修補更精確。

- **修補進度追蹤與效能評估**  
  系統不僅提供修補建議與排程，還能持續記錄並追蹤修補狀態，協助企業評估修補效能，及時調整資安策略，確保整體防護效果。

- **增強決策的可靠性與透明度**  
  透過可信任AI機制，系統在採用 LLM as a Judge 來進行漏洞風險評估、提供修補建議及制定排程時，能夠確保整個過程具有充分的透明性和可追查性。

- **整合式弱點管理流程**  
  從資產盤點、漏洞資訊收集、AI 分析、漏洞排序，到修補方案制定與進度追蹤，本系統提供一套更完整、系統化的弱點管理解決方案，協助企業更有效應對資安威脅，同時節省修補資源並促進團隊間的協同作業。

- **零信任架構整合 (In the future)**<br>
  系統整合主動掃描、被動監控、配置檔分析與人工分析等多種資產發現機制，從資產管理的角度全面掌握資安隱患，確保實現持續且完整的資產與漏洞監控。
  
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


## 競品比較

| 項目 |  [AIShield](https://www.aishield.com.tw/) | [Vicarius vRx](https://www.cyberview.com.tw/vicarius/) | [VulnFox](https://github.com/Copsychus123/vulnfox/tree/main) |
| --- | :---: | :---: | :---: |
| 是否需要代理(Agent)  | ✘ | ✘ | ✘ |
| 資產盤點  | ✅  | ✘ | ✅ |
| 弱點管理  | ✅  | ✅ | ✅ |
| AI 修補建議  | ✅  | ✅ | ✅ |
| AI 修補排程  | ✘ | ✅ | ✅ |
| AI 後果評鑑  | ✘ | ✘ | ✅ |
| 風險矩陣分析  | ✘ | ✘ | ✅ |
| 修補追蹤與紀錄  | ✘ | ✘ | ✅ |
| 腳本自動化修補 | ✘  | ✅ | ✘ |
| 風險優先級  | CVSS  | &nbsp;&nbsp;&nbsp;CVSS&nbsp;&nbsp;&nbsp; | CVSS、EPSS、KEV |
| 適用情境 |IT / SOC / MDR | IT | IT / OT |

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
