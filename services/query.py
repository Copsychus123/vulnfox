import os
import json
import logging
import asyncio
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from services.db import DatabaseManager, get_instance, get_assets_with_vulnerabilities

# 設定日誌
logger = logging.getLogger(__name__)

# 預設設定
DEFAULT_SETTINGS = {
    "min_cvss": 7.0,
    "epss_min": 0.0,
    "include_kev": False,
    "strategy": "ColBERT"
}

class QueryService:
    """
    查詢服務：提供各種數據查詢功能
    """
    _instance = None
    
    def __init__(self):
        """初始化查詢服務"""
        self.db_manager = get_instance()
        self.settings = self._load_settings()
        logger.info("查詢服務初始化完成")
        
    @classmethod
    def get_instance(cls):
        """獲取查詢服務單例"""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
        
    def _load_settings(self) -> Dict[str, Any]:
        """載入預設設置，不從資料庫讀取"""
        return DEFAULT_SETTINGS.copy()
 
    async def update_settings(self, new_settings: Dict[str, Any]) -> Dict[str, Any]:
        """更新設置，只在記憶體中儲存"""
        self.settings = {**self.settings, **new_settings}
        logger.info(f"設置已更新: {json.dumps(self.settings)}")
        return self.settings
            
    async def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """獲取漏洞信息"""
        try:
            return await self.db_manager.get_vulnerability(cve_id)
        except Exception as e:
            logger.error(f"獲取漏洞信息失敗: {e}")
            return None
            

    @classmethod
    async def get_asset_history(cls, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """獲取資產歷史數據"""
        try:
            # 確保獲取資產數據
            assets_with_vulns = await get_assets_with_vulnerabilities(
                min_score=filters.get("min_cvss", 0.0) if filters else 0.0,
                additional_filters=filters
            )
            
            logger.info(f"從資產庫獲取到 {len(assets_with_vulns)} 個資產")
            
            return {
                "assets": assets_with_vulns,
                "summary": {
                    "total_assets": len(assets_with_vulns),
                    "assets_with_vulns": sum(1 for a in assets_with_vulns if a.get("vulnerabilities")),
                    "unpatched_vulns": sum(len([v for v in a.get("vulnerabilities", []) if not v.get("patched", False)]) for a in assets_with_vulns),
                    "critical_vulns": sum(len([v for v in a.get("vulnerabilities", []) if v.get("base_score", 0) >= 9.0]) for a in assets_with_vulns),
                    "high_vulns": sum(len([v for v in a.get("vulnerabilities", []) if 7.0 <= v.get("base_score", 0) < 9.0]) for a in assets_with_vulns),
                },
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logger.error(f"獲取資產歷史數據失敗: {e}")
            return {"assets": [], "summary": {}, "timestamp": datetime.now(timezone.utc).isoformat()}
            
    async def generate_report(self, history_data: Dict[str, Any]) -> str:
        """生成綜合報告"""
        try:
            # 使用 LLM 生成報告
            try:
                from langchain_openai import ChatOpenAI
                
                # 初始化 LLM
                llm = ChatOpenAI(
                    temperature=0.1,
                    model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    request_timeout=60,
                    max_retries=2
                )
                
                # 準備提示內容
                assets = history_data.get("assets", [])
                assets_count = len(assets)
                
                # 生成資產漏洞摘要
                assets_summary = []
                for i, asset in enumerate(assets[:10]):  # 限制處理的資產數量
                    asset_info = asset.get("asset_info", {})
                    vuln_info = asset.get("弱點管理", {})
                    vuln_count = vuln_info.get("漏洞總數", 0)
                    
                    hostname = asset_info.get("Host Name", "未知主機")
                    ip = asset_info.get("IP Address", "未知IP")
                    
                    assets_summary.append(f"{i+1}. {hostname} ({ip}): {vuln_count} 個漏洞")
                
                # 構建提示
                prompt = f"""
                請根據以下資訊生成一份企業漏洞風險管理報告：
                
                總資產數量：{assets_count}
                
                資產漏洞摘要：
                {chr(10).join(assets_summary)}
                
                報告應包含：
                1. 風險評估總覽
                2. 關鍵漏洞分析
                3. 改善建議
                4. 後續行動計劃
                
                請使用繁體中文，以專業且結構化的方式撰寫報告。
                """
                
                # 調用 LLM 生成報告
                response = await llm.ainvoke([
                    {"role": "system", "content": "你是一位資安專家，專門提供漏洞風險管理報告。"},
                    {"role": "user", "content": prompt}
                ])
                
                return response.content.strip()
                
            except Exception as e:
                logger.error(f"生成報告失敗（LLM）: {e}")
                return "無法使用 LLM 生成報告。請確保已設置正確的 API 密鑰。"
                
        except Exception as e:
            logger.error(f"生成報告失敗: {e}")
            return "報告生成失敗。"

# 導出 generate_vulnerability_report 函數以支援 main.py 中的用法
async def generate_vulnerability_report(data: Dict[str, Any]) -> str:
    """生成漏洞報告"""
    query_service = QueryService.get_instance()
    return await query_service.generate_report(data)