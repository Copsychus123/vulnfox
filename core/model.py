#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : ${DATE} ${TIME}
# @Author  : Copsychus123
# @email   : t112c72007@ntut.org.tw

# Copyright (C) 2025 Copsychus123
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import requests, json, datetime, time, copy, os, logging
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter
import streamlit as st

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

API_BASE_URL = "http://localhost:5000"
DATA_CACHE_TTL = 300

class DataModel:
    """數據模型類，處理API請求和數據轉換"""
    
    @staticmethod
    def api_request(endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[Dict]:
        """發送API請求"""
        url = f"{API_BASE_URL}/{endpoint}"
        logger.info(f"發送API請求: {method} {url}")
        try:
            resp = requests.get(url, timeout=120) if method.upper() == "GET" else requests.post(url, json=data, timeout=120)
            if resp.status_code == 200:
                result = resp.json()
                logger.info(f"API返回成功: {endpoint}")
                return result
            logger.error(f"API請求失敗: {resp.status_code}")
            st.error(f"API請求失敗: {resp.status_code}")
        except Exception as e:
            logger.error(f"請求出錯: {e}")
            st.error(f"請求出錯: {e}")
        return None

    @staticmethod
    def fetch_data(endpoint: str, force_refresh: bool = False) -> Optional[Dict]:
        """獲取數據並緩存"""
        cache_key = f"data_{endpoint}"
        now = time.time()
        
        # 初始化緩存
        if 'data_cache' not in st.session_state:
            st.session_state.data_cache = {}
        cache = st.session_state.data_cache
        
        # 檢查是否需要刷新緩存
        if force_refresh or cache_key not in cache or now - cache.get(f"{cache_key}_time", 0) > DATA_CACHE_TTL:
            with st.spinner(f"獲取 {endpoint} 數據..."):
                result = DataModel.api_request(endpoint)
                if result and result.get("status") == "success":
                    data = result.get("data", {})
                    
                    # 確保歷史數據格式正確
                    if endpoint == "history":
                        if isinstance(data, list):
                            data = {"assets": data}
                        elif not isinstance(data, dict):
                            data = {"assets": []}
                        elif "assets" not in data or not isinstance(data["assets"], list):
                            data["assets"] = []
                        
                        # 添加摘要信息
                        if "summary" not in data:
                            assets = data.get("assets", [])
                            total_assets = len(assets)
                            assets_with_vulns = sum(1 for asset in assets if asset.get("vulnerabilities"))
                            unpatched_vulns = sum(len([v for v in asset.get("vulnerabilities", []) if not v.get("patched", False)]) for asset in assets)
                            critical_vulns = sum(len([v for v in asset.get("vulnerabilities", []) if v.get("base_score", 0) >= 9.0 and not v.get("patched", False)]) for asset in assets)
                            high_vulns = sum(len([v for v in asset.get("vulnerabilities", []) if 7.0 <= v.get("base_score", 0) < 9.0 and not v.get("patched", False)]) for asset in assets)
                            
                            data["summary"] = {
                                "total_assets": total_assets,
                                "assets_with_vulns": assets_with_vulns,
                                "unpatched_vulns": unpatched_vulns,
                                "critical_vulns": critical_vulns,
                                "high_vulns": high_vulns
                            }
                    
                    # 更新緩存
                    cache[cache_key] = data
                    cache[f"{cache_key}_time"] = now
                    return data
                    
                # 若無法獲取漏洞數據，嘗試從歷史數據中提取
                if endpoint == "vuln":
                    st.warning(f"無法獲取 {endpoint} 數據，嘗試歷史數據...")
                    hist = DataModel.fetch_data("history")
                    if hist:
                        hist = DataModel.preprocess_history_data(hist)
                        return {"vulnerabilities": DataModel.collect_all_vulnerabilities(hist.get("assets", []))}
        
        return cache.get(cache_key)
        
    @staticmethod
    def clear_cache() -> None:
        """清除緩存"""
        if 'data_cache' in st.session_state:
            st.session_state.data_cache = {}

    @staticmethod
    def get_severity(cvss: float) -> str:
        """根據CVSS分數獲取嚴重性等級"""
        if cvss >= 9.0: return "關鍵 (Critical)"
        if cvss >= 7.0: return "高風險 (High)"
        if cvss >= 4.0: return "中風險 (Medium)"
        if cvss > 0: return "低風險 (Low)"
        return "無 (None)"

    @staticmethod
    def truncate_text(text: str, limit: int = 100) -> str:
        """截斷文本"""
        return f"{text[:limit]}..." if text and len(text) > limit else (text or "")

    @staticmethod
    def calculate_priority_score(vuln: Dict) -> float:
        """計算漏洞優先級分數"""
        try:
            base = float(vuln.get("base_score", 0))
        except Exception:
            base = 0.0
        try:
            epss = float(vuln.get("epss_score", 0))
        except Exception:
            epss = 0.0
        try:
            percentile = float(vuln.get("percentile", 0))
        except Exception:
            percentile = 0.0

        in_kev = vuln.get("in_kev", False)
        kev = 2 if in_kev else 0

        # 漏洞時間權重
        age = 0
        if vuln.get("published"):
            try:
                pub = vuln["published"]
                if isinstance(pub, str):
                    pub_dt = datetime.datetime.fromisoformat(pub.replace("Z", "+00:00"))
                else:
                    pub_dt = pub
                # 如果發佈時間沒有時區資訊，則視為 UTC
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=datetime.timezone.utc)
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                days = (now_dt - pub_dt).days
                # 根據漏洞年齡設定權重：新漏洞權重較高
                age = 1.5 if days < 30 else (1.0 if days < 90 else 0.5)
            except Exception as e:
                logger.warning(f"計算時間權重失敗: {e}")
        
        # 結合各項權重計算最終分數
        score = (base * 0.5) + (epss * 3) + (percentile * 2) + kev + age
        return min(max(score, 0), 10)



    @staticmethod
    def validate_vulnerability_data(vulns: List[Dict]) -> List[Dict]:
        """驗證和標準化漏洞數據"""
        valid = []
        for vuln in vulns:
            # 跳過無效數據
            if not isinstance(vuln, dict) or not vuln.get("cve_id"):
                continue
                
            # 複製並標準化數據
            v = vuln.copy()
            v["description"] = v.get("description") or f"漏洞 {v.get('cve_id', 'N/A')}"
            
            # 標準化數值
            try:
                v["base_score"] = float(v.get("base_score", 0))
            except Exception:
                v["base_score"] = 0.0
                
            try:
                v["epss_score"] = float(v.get("epss_score", 0))
            except Exception:
                v["epss_score"] = 0.0
                
            # 設置其他字段
            v["patched"] = v.get("patched", False)
            v["published"] = v.get("published") or datetime.datetime.now(datetime.timezone.utc).isoformat()
            v["severity"] = v.get("severity") or DataModel.get_severity(v["base_score"])
            v["priority_score"] = v.get("priority_score") or DataModel.calculate_priority_score(v)
            
            valid.append(v)
        return valid

    @staticmethod
    def preprocess_history_data(history: Dict) -> Dict:
        """預處理歷史數據"""
        if not history or not isinstance(history, dict):
            return {}
            
        data = copy.deepcopy(history)
        
        # 處理每個資產的漏洞信息
        for asset in data.get("assets", []):
            for key in ["vulnerabilities", "raw_vulnerabilities"]:
                for vuln in asset.get(key, []):
                    # 確保嚴重性和優先級分數存在
                    vuln["severity"] = vuln.get("severity") or DataModel.get_severity(vuln.get("base_score", 0))
                    vuln["priority_score"] = vuln.get("priority_score") or DataModel.calculate_priority_score(vuln)
                    
        return data

    @staticmethod
    def collect_all_vulnerabilities(assets: List[Dict]) -> List[Dict]:
        """收集所有漏洞信息"""
        if not isinstance(assets, list):
            return []
            
        # 獲取已通過過濾的漏洞ID
        passed = {v.get("cve_id") for asset in assets 
                 for v in asset.get("vulnerabilities", []) 
                 if v.get("cve_id")}
                 
        all_vulns = []
        
        # 處理每個資產的漏洞信息
        for asset in assets:
            info = asset.get("asset_info", {})
            
            for vuln in asset.get("raw_vulnerabilities", []):
                v = vuln.copy()
                
                # 添加資產信息
                v["host_name"] = info.get("Host Name", "N/A")
                v["ip_address"] = info.get("IP Address", "N/A")
                v["asset_info"] = info
                
                # 添加漏洞狀態信息
                v["severity"] = v.get("severity") or DataModel.get_severity(v.get("base_score", 0))
                v["priority_score"] = v.get("priority_score") or DataModel.calculate_priority_score(v)
                v["passed_filter"] = v.get("cve_id") in passed
                v["patched"] = v.get("patched", False)
                
                all_vulns.append(v)
                
        return all_vulns

    @staticmethod
    def enhance_vulnerability_data(vulns: List[Dict]) -> List[Dict]:
        """增強漏洞數據以供前端顯示"""
        now = datetime.datetime.now(datetime.timezone.utc)
        enhanced = []
        
        for vuln in vulns:
            # logger.info(f"讀取到 vuln: {vuln}")
            # 計算漏洞發佈天數
            days = None
            if vuln.get("published"):
                try:
                    pub = vuln.get("published")
                    if isinstance(pub, str):
                        pub_dt = datetime.datetime.fromisoformat(pub.replace('Z', '+00:00'))
                    else:
                        pub_dt = pub
                    days = (now - pub_dt).days
                except Exception:
                    days = None
            
            # 處理 EPSS 分數與百分比
            epss = vuln.get("epss_score")
            epss_per = vuln.get("percentile")
            logger.info(f"讀取到 epss_score: {epss}, percentile: {epss_per}")
            
            # 根據漏洞天數與是否修補確定 SLA 狀態
            sla = "超時" if (days is not None and days > 30 and not vuln.get("patched", False)) else "正常"
            
            # 獲取產品/IP資訊
            info = vuln.get("asset_info", {})
            prod = info.get("Host Name") or info.get("hostname") or "N/A"
            ip = info.get("IP Address") or info.get("ip_address") or vuln.get("ip_address", "N/A")
            
            # 獲取 CWE 資訊
            cwe = vuln.get("cwe_id") or (vuln.get("cwes", [])[0] if vuln.get("cwes") else "N/A")
            
            # 新增：計算或使用已有的優先分數
            priority_score = vuln.get("priority_score", DataModel.calculate_priority_score(vuln))
            
            enhanced.append({
                "弱點嚴重度": vuln.get("severity", "N/A"),
                "CVE ID": vuln.get("cve_id", "N/A"),
                "描述": vuln.get("description", ""),
                "CWE": cwe,
                "CVSS": vuln.get("base_score", ""),
                "EPSS 分數/百分比": f"{epss} / {(epss_per * 100):.2f}%" if epss_per != 0 else f"{epss} / N/A",
                "發布日期": vuln.get("published", "N/A"),
                "SLA": sla,
                "狀態": "已修補" if vuln.get("patched", False) else "未修補",
                "產品": prod,
                "IP地址": ip,
                "產品/IP": f"{prod} / {ip}" if prod != "N/A" or ip != "N/A" else "N/A",
                "服務": info.get("Service", "N/A"),
                "修復計畫": "已修補" if vuln.get("patched", False) else vuln.get("remediation_date", "未排程"),
                "人員": vuln.get("reporter", ""),
                "主管": vuln.get("reviewers", "N/A"),
                "天數": f"{days} 天" if days is not None else "N/A",
                "KEV": "是" if vuln.get("in_kev", False) else "否",
                "優先分數": f"{priority_score:.2f}",
                "_original_data": vuln
            })
            
        return enhanced


    @staticmethod
    def update_vulnerability_status(cve_id: str, patched: bool) -> Tuple[bool, str]:
        """更新漏洞修補狀態"""
        try:
            result = DataModel.api_request("update_vuln", "POST", {"cve_id": cve_id, "patched": patched})
            
            if result and result.get("status") == "success":
                DataModel.clear_cache()
                return True, "成功更新漏洞狀態"
                
            return False, f"更新失敗: {result.get('message', '未知錯誤') if result else '伺服器無回應'}"
        except Exception as e:
            return False, f"更新失敗: {e}"