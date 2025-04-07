# VulnFox: Agent-less Vulnerability Management Framework  
VulnFox：無 Agent 式弱點管理架構

### English | 繁體中文 | 简体中文

---

## 1. What is VulnFox?  
### 1. 什麼是 VulnFox？

**English:**

VulnFox is an **Agent-less vulnerability management framework** that focuses on integrating a diverse range of asset inventories and automatically correlating them with known CVE vulnerability information. Instead of installing agents or performing active scans, VulnFox gathers asset data from multiple sources such as active asset discovery, Network Access Control (NAC), passive network analysis, protocol analysis, and descriptor analysis. This multi-source approach not only enhances asset identification accuracy but also ensures that the security posture for IT, IoT, OT, and cloud environments is continuously updated with the latest vulnerability insights.

**繁體中文:**

VulnFox 是一款基於 **Agent-less 架構** 的弱點管理框架，其核心在於通過整合多元化的資產清單，並自動關聯已知的 CVE 弱點資訊，確保 IT、IoT、OT 及雲端環境的資訊安全狀態持續更新。

與傳統依賴 Agent 部署或主動掃描的弱點管理工具不同，VulnFox 無需在終端設備上安裝任何軟體，也不會對網路環境進行主動探測。相反地，該系統透過整合來自以下多個來源的資產清單：
- 網路存取控制（NAC）
- 主動資產探勘
- 被動網路分析
- 網路協議分析
- 描述檔分析

這些多元來源的數據不僅提升了資產識別的準確性，也使 VulnFox 能夠自動匹配並關聯最新的 CVE 弱點資訊，從而在不影響設備效能的前提下，提供一個低成本且高可擴展的多層次弱點管理解決方案。

---

## 2. Core Features  
### 2. 核心功能

#### 2.1 Fully Agent-less Vulnerability Detection  
##### 2.1 完全無 Agent 式弱點檢測
- **No Endpoint Installation Required**: VulnFox eliminates the need for endpoint agents and active scanning tools.  
- **Passive Network Monitoring**: Utilizes network traffic analysis and metadata extraction to detect vulnerabilities.  
- **Real-Time Asset Identification**: Leverages NAC to continuously update asset inventories.

- **無需端點安裝**：VulnFox 無需安裝 Agent，也不依賴主動掃描工具。  
- **被動式網路監控**：透過網路流量分析與元數據提取來識別弱點。  
- **即時資產識別**：利用 NAC 持續更新資產清單，確保安全可視化。

---

#### 2.2 NAC-Driven Asset & Vulnerability Management  
##### 2.2 NAC 驅動的資產與弱點管理
- **Network-Based Asset Inventory**: Retrieves up-to-date asset information using NAC authentication logs and network metadata.  
- **Automated CVE Correlation**: Automatically maps known vulnerabilities to discovered network assets for precise risk assessment.  
- **Zero Performance Impact**: Operates without interfering with device performance or network operations.

- **基於網路的資產清單管理**：透過 NAC 認證日誌與網路元數據獲取最新資產資訊。  
- **自動化 CVE 關聯**：自動匹配已知弱點與發現的資產，提供精確的風險評估。  
- **零效能影響**：不影響設備效能或網路運作。

---

#### 2.3 Multi-Layered Vulnerability Management Strategy  
##### 2.3 多層次弱點管理策略
- **Supports Integration with External Vulnerability Reports**: Enables security teams to correlate VulnFox asset intelligence with external vulnerability reports for a unified security assessment.  
- **Low-Cost, Scalable Deployment**: Eliminates the overhead of agent licensing, endpoint maintenance, and active scanning.  
- **Threat Intelligence Integration**: Seamlessly syncs with sources like NVD, MITRE ATT&CK, and other industry threat intelligence platforms.

- **支持整合外部弱點報告**：允許資安團隊將 VulnFox 資產情報與外部弱點報告關聯分析，實現統一的資訊安全評估。  
- **低成本、高可擴展性佈署**：無需額外的 Agent 授權、端點維護與主動掃描負擔。  
- **資安情報整合**：支援與 NVD、MITRE ATT&CK 及其他資安情報平台無縫對接，提升檢測準確度。

---

## 3. Technical Architecture  
### 3. 技術架構

VulnFox 整合了三大核心組件：

1. **VulnFox NAC Engine**：透過 NAC 認證日誌與網路元數據即時收集資產資訊。  
2. **VulnFox Intelligence Engine**：運用 AI 驅動的風險評估與 CVE 弱點關聯分析。  
3. **VulnFox Dashboard**：提供一個集中式資安管理介面。

---

## 4. Quick Start & Demo  
### 4. 快速開始與 Demo

1. **Deploy VulnFox NAC Engine**  
2. **Enable VulnFox Intelligence Engine**  
3. **Access VulnFox Dashboard**  
4. **Request a Live Demo**: Contact us for a proof-of-concept demonstration.

---

## 5. Contact Us  
### 5. 聯繫我們

#### Primary Contact (First Author)
- **Dr. Ching-Huang Lin (林敬皇)**  
- **Affiliation**: National Taipei University of Technology (NTUT)  
- **Email**: [gbox@ntut.edu.tw]  
- **Laboratory**: Cybersecurity Applications Lab (資通安全應用實驗室)

#### Research & Development Team
- **GitHub**: [VulnFox Repository](https://github.com/VulnFox) (範例待修正)
- **Website**: [www.vulnfox.com](https://www.vulnfox.com) (範例待修正)
- **Email**: t112c72007@ntut.org.tw

---
