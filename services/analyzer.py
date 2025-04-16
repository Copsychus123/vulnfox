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

import asyncio, logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzer:
    """漏洞分析與風險評估"""

    def __init__(self, db_manager: Any, knowledge_base: Any) -> None:
        self.db = db_manager
        self.kb = knowledge_base
        self.client = ChatOpenAI(
            temperature=0.1,
            model="gpt-4o-mini",
            request_timeout=60,
            max_retries=2
        )

    async def analyze_vulnerability(self, vuln_data: Dict) -> Dict[str, Any]:
        """完整分析漏洞，並行拉取各項資料以提高性能"""
        try:
            # 並行取得各來源數據
            cve_id = vuln_data.get("cve_id")
            nvd_future = self.kb.get_nvd_data(cve_id)
            kev_future = self.kb.get_kev_data(cve_id)
            epss_future = self.kb.get_epss_data(cve_id)
            rss_future = self.kb.get_rss_data(cve_id)
            nvd_data, kev_data, epss_data, rss_data = await asyncio.gather(
                nvd_future, kev_future, epss_future, rss_future
            )
            analysis = {
                "cve_id": cve_id,
                "nvd": nvd_data,
                "kev": kev_data,
                "epss": epss_data,
                "rss": rss_data,
                "timestamp": datetime.utcnow().isoformat()
            }
            # 並行獲取修補建議
            patch_tasks = [
                self.kb.get_nvd_patch(cve_id),
                self.kb.get_kev_patch(cve_id)
            ]
            nvd_patch, kev_patch = await asyncio.gather(*patch_tasks)
            patches = []
            if nvd_patch:
                patches.append({"source": "NVD", "recommendation": nvd_patch})
            if kev_patch:
                patches.append({"source": "KEV", "recommendation": kev_patch})
            # LLM 生成補充修補建議（獨立處理）
            ai_patch = await self._generate_ai_patch_recommendation(vuln_data)
            if ai_patch:
                patches.append({"source": "AI", "recommendation": ai_patch})
            analysis["patches"] = patches

            # 風險評估與未來風險預測可同時進行
            risk_future = self._evaluate_risk(vuln_data)
            prediction_future = self._predict_future_risk(vuln_data)
            risk, prediction = await asyncio.gather(risk_future, prediction_future)
            analysis["risk_assessment"] = risk
            analysis["risk_prediction"] = prediction

            return analysis

        except Exception as e:
            logger.error(f"分析漏洞失敗: {str(e)}")
            return {
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

    async def _evaluate_risk(self, vuln_data: Dict) -> Dict[str, Any]:
        """評估漏洞風險，核心計算保持不變"""
        try:
            base_score = float(vuln_data.get("cvss_score", 0))
            is_kev = vuln_data.get("in_kev", False)
            epss_score = float(vuln_data.get("epss_score", 0))
            risk_score = base_score * 0.4 + (1.0 if is_kev else 0.0) * 0.3 + epss_score * 0.3
            if risk_score >= 8.0:
                risk_level = "高風險"
            elif risk_score >= 5.0:
                risk_level = "中風險"
            else:
                risk_level = "低風險"
            return {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "factors": {
                    "cvss": base_score,
                    "is_kev": is_kev,
                    "epss": epss_score
                }
            }
        except Exception as e:
            logger.error(f"評估風險失敗: {str(e)}")
            return {}

    async def _predict_future_risk(self, vuln_data: Dict) -> str:
        """使用 LLM 預測未來風險，同步並行調用歷史資料接口"""
        try:
            prediction = await self._generate_risk_prediction(vuln_data)
            patch_history = await self.kb.get_patch_history(vuln_data["cve_id"])
            patch_difficulty = self._evaluate_patch_difficulty(patch_history)
            return {
                "risk_trend": prediction,
                "patch_difficulty": patch_difficulty,
                "confidence": 0.8,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"預測風險失敗: {str(e)}")
            return ""

    async def _generate_ai_patch_recommendation(self, vuln_data: Dict) -> str:
        """使用 LLM 生成修補建議"""
        try:
            prompt = f"""
請根據以下漏洞資訊生成詳細的修補建議:

CVE ID: {vuln_data.get('cve_id')}
描述: {vuln_data.get('description')}
CVSS: {vuln_data.get('cvss_score')}

請提供:
1. 漏洞風險評估
2. 詳細修補步驟
3. 相關補充建議
"""
            response = await self.client.ainvoke([
                {"role": "system", "content": "你是一個專業的資安分析師，負責提供漏洞修補建議。"},
                {"role": "user", "content": prompt}
            ])
            return response.content
        except Exception as e:
            logger.error(f"生成 AI 修補建議失敗: {str(e)}")
            return ""

    async def _generate_risk_prediction(self, vuln_data: Dict) -> str:
        """使用 LLM 預測風險趨勢，並同時調用外部數據"""
        try:
            epss_trend_future = self.kb.get_epss_trend(vuln_data["cve_id"])
            kev_info_future = self.kb.get_kev_data(vuln_data["cve_id"])
            epss_trend, kev_info = await asyncio.gather(epss_trend_future, kev_info_future)
            prompt = f"""
請根據以下資訊預測此漏洞的未來風險趨勢:

CVE ID: {vuln_data.get('cve_id')}
描述: {vuln_data.get('description')}
CVSS: {vuln_data.get('cvss_score')}
EPSS 趨勢: {epss_trend}
KEV 狀態: {'已知被利用' if kev_info else '未被利用'}

請分析:
1. 風險趨勢走向
2. 可能的利用情境
3. 建議的預防措施
"""
            response = await self.client.ainvoke([
                {"role": "system", "content": "你是一個專業的資安分析師，負責預測漏洞風險趨勢。"},
                {"role": "user", "content": prompt}
            ])
            return response.content
        except Exception as e:
            logger.error(f"生成風險預測失敗: {str(e)}")
            return ""

    def _evaluate_patch_difficulty(self, patch_history: List[Dict]) -> str:
        try:
            if not patch_history:
                return "未知"
            total_patches = len(patch_history)
            successful_patches = sum(1 for p in patch_history if p.get("status") == "success")
            avg_time = sum(p.get("patch_time", 0) for p in patch_history) / total_patches
            success_rate = successful_patches / total_patches
            if success_rate >= 0.8 and avg_time <= 24:
                return "容易"
            elif success_rate >= 0.5 and avg_time <= 72:
                return "中等"
            else:
                return "困難"
        except Exception as e:
            logger.error(f"評估修補難度失敗: {str(e)}")
            return "未知"
