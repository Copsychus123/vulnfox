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

import asyncio
import numpy as np
import streamlit as st
import pandas as pd
import time
from collections import Counter
from typing import Dict, List, Optional, Any
import datetime
import logging
from core.model import DataModel
from core.view import UIView

# 設定日誌
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class AppController:
    """控制器類，負責處理用戶交互和頁面狀態管理"""
    
    def __init__(self):
        """初始化控制器"""
        self.init_session_state()
        
    def init_session_state(self):
        """初始化會話狀態變數"""
        if 'data_cache' not in st.session_state:
            st.session_state.data_cache = {}
        if 'current_tab' not in st.session_state:
            st.session_state.current_tab = 0  # 預設顯示概覽
        if 'selected_cve' not in st.session_state:
            st.session_state.selected_cve = None
        if 'show_unfiltered' not in st.session_state:
            st.session_state.show_unfiltered = True
        if 'remediation_plan' not in st.session_state:
            st.session_state.remediation_plan = None
        if 'remediation_filter_hash' not in st.session_state:
            st.session_state.remediation_filter_hash = None
        if 'recommendation_history' not in st.session_state:
            st.session_state.recommendation_history = {}
    
    def handle_tab_click(self):
        """處理卡片點擊切換標籤頁事件"""
        if 'clicked_card' in st.session_state:
            st.session_state.current_tab = st.session_state.clicked_card
            del st.session_state.clicked_card
    
    def render_sidebar(self):
        """設定側邊欄内容"""
        st.sidebar.title("系統設定")
        st.sidebar.markdown("### 查詢過濾參數")
        min_cvss = st.sidebar.number_input("最低 CVSS", value=7.0, step=0.5)
        epss_min = st.sidebar.number_input("最低 EPSS", value=0.0, step=0.05)
        include_kev = st.sidebar.checkbox("包含 KEV", value=False)
        strategy = st.sidebar.selectbox("檢索策略", ["ColBERT", "RankGPT", "naive"], index=0)
        self._handle_settings_update(min_cvss, epss_min, include_kev, strategy)
        st.sidebar.markdown("### 顯示設定")
        show_unfiltered = st.sidebar.checkbox("顯示未通過過濾的漏洞", value=st.session_state.show_unfiltered)
        if show_unfiltered != st.session_state.show_unfiltered:
            st.session_state.show_unfiltered = show_unfiltered
        self._display_current_settings()
        self._display_system_status()
        st.sidebar.markdown("---")
        if st.sidebar.button("清除緩存", use_container_width=True):
            self._clear_cache()
    
    def _handle_settings_update(self, min_cvss, epss_min, include_kev, strategy):
        """處理設定更新"""
        update_btn = st.sidebar.button("更新設定", use_container_width=True)
        if update_btn:
            with st.sidebar.spinner("更新設定中..."):
                try:
                    payload = {
                        "min_cvss": min_cvss,
                        "epss_min": epss_min,
                        "include_kev": include_kev,
                        "strategy": strategy
                    }
                    result = DataModel.api_request("settings", "POST", payload)
                    if result and result.get("status") == "success":
                        st.sidebar.success("設定已更新")
                        DataModel.clear_cache()
                        time.sleep(0.5)
                        st.experimental_rerun()
                    else:
                        st.sidebar.error(f"設定更新失敗: {result.get('message', '未知錯誤') if result else '伺服器無回應'}")
                except Exception as e:
                    st.sidebar.error(f"設定更新錯誤: {str(e)}")
    
    def _display_current_settings(self):
        """顯示當前設定"""
        with st.sidebar.expander("目前系統設定", expanded=False):
            try:
                settings_result = DataModel.api_request("settings")
                if settings_result:
                    current_settings = settings_result.get("settings", {})
                    st.json(current_settings)
                else:
                    st.error("無法獲取當前設定")
            except Exception as e:
                st.error(f"獲取設定錯誤: {str(e)}")
    
    def _display_system_status(self):
        """顯示系統狀態"""
        st.sidebar.markdown("### 系統狀態")
        cache_info = []
        for key in st.session_state.data_cache:
            if not key.endswith("_time"):
                last_update = st.session_state.data_cache.get(f"{key}_time", 0)
                elapsed = time.time() - last_update
                cache_info.append({
                    "數據": key.replace("data_", ""),
                    "上次更新": f"{int(elapsed)} 秒前" if elapsed > 0 else "剛剛"
                })
        if cache_info:
            st.sidebar.dataframe(pd.DataFrame(cache_info), use_container_width=True, hide_index=True)
        else:
            st.sidebar.info("尚無緩存數據")
    
    def _clear_cache(self):
        """清除緩存"""
        DataModel.clear_cache()
        if 'remediation_plan' in st.session_state:
            del st.session_state.remediation_plan
        if 'remediation_filter_hash' in st.session_state:
            del st.session_state.remediation_filter_hash
        st.sidebar.success("已清除所有緩存")
        time.sleep(0.5)
        st.experimental_rerun()
    
    def show_overview(self):
        """顯示系統概覽頁面"""
        st.write("本系統提供資產管理、弱點管理、風險降低及風險接受等功能，幫助企業全面掌控安全狀態。")
        history_data = self._get_history_data()
        if not history_data:
            return
        metrics = self._calculate_overview_metrics(history_data)
        UIView.display_metric_cards(metrics)
        self._display_vulnerability_distribution(history_data)
    
    def _get_history_data(self):
        """獲取歷史數據"""
        history_data = DataModel.fetch_data("history")
        if not history_data:
            st.error("無法載入系統數據，請稍後重試")
            if st.button("重新載入", key="reload_data"):
                st.experimental_rerun()
            return None
        return DataModel.preprocess_history_data(history_data)
    
    def _calculate_overview_metrics(self, history_data):
        """計算概覽頁指標"""
        assets = history_data.get("assets", [])
        summary = history_data.get("summary", {})
        
        # 使用新的摘要數據
        total_assets = summary.get("total_assets", len(assets))
        assets_with_vulns = sum(1 for asset in assets if asset.get("vulnerabilities"))
        unpatched_vulns = summary.get("unpatched_vulns", 0)
        critical_vulns = summary.get("critical_vulns", 0)
        high_vulns = summary.get("high_vulns", 0)
        
        # 計算風險百分比
        risk_percent = (assets_with_vulns / total_assets * 100) if total_assets > 0 else 0
        
        # 收集風險處理狀態
        all_vulnerabilities = DataModel.collect_all_vulnerabilities(assets)
        risk_counter = Counter(v.get('risk_status', 'None') for v in all_vulnerabilities)
        risk_changes = {
            'reduce': risk_counter.get('Reduce', 0),
            'transfer': risk_counter.get('Transfer', 0),
            'avoid': risk_counter.get('Avoid', 0),
            'retain': risk_counter.get('Retain', 0)
        }
        
        total_reduce = sum(risk_changes[k] for k in ['reduce', 'transfer', 'avoid'])
        
        metrics = [
            {
                "title": "資產管理",
                "value": total_assets,
                "content": f"""
                <p>資產總數</p>
                <p>有漏洞資產: {assets_with_vulns}</p>
                <p>風險比例: {risk_percent:.1f}%</p>
                """,
                "footer": '點擊查看資產詳情 →',
                "tab_index": 1
            },
            {
                "title": "弱點管理",
                "value": unpatched_vulns,
                "content": f"""
                <p>未修補漏洞</p>
                <p><span class="critical-text">關鍵: {critical_vulns}</span></p>
                <p><span class="high-text">高風險: {high_vulns}</span></p>
                """,
                "footer": '點擊查看漏洞詳情 →',
                "tab_index": 2
            },
            {
                "title": "風險降低",
                "value": total_reduce,
                "content": f"""
                <p>風險降低策略</p>
                <p>降低: {risk_changes['reduce']}</p>
                <p>轉移: {risk_changes['transfer']}</p>
                """,
                "footer": '點擊查看策略詳情 →',
                "tab_index": 3
            },
            {
                "title": "風險接受",
                "value": risk_changes['retain'],
                "content": f"""
                <p>已接受風險</p>
                <p>需定期追蹤</p>
                <p>持續監控</p>
                """,
                "footer": '點擊查看接受詳情 →',
                "tab_index": 4
            }
        ]
        return metrics

    def _display_vulnerability_distribution(self, history_data):
        """顯示漏洞風險分佈"""
        summary = history_data.get("summary", {})
        assets = history_data.get("assets", [])
        
        # 使用摘要數據
        critical_vulns = summary.get("critical_vulns", 0)
        high_vulns = summary.get("high_vulns", 0)
        unpatched_vulns = summary.get("unpatched_vulns", 0)
        
        # 如果找不到摘要數據，則計算
        if unpatched_vulns == 0:
            all_vulnerabilities = DataModel.collect_all_vulnerabilities(assets)
            unpatched_vulns = [v for v in all_vulnerabilities if not v.get("patched", False)]
            severity_counter = Counter(
                "關鍵風險" if "Critical" in v.get("severity", "") else
                "高風險" if "High" in v.get("severity", "") else
                "中風險" if "Medium" in v.get("severity", "") else
                "低風險"
                for v in unpatched_vulns
            )
        else:
            # 使用摘要數據構建分佈
            medium_high = max(0, unpatched_vulns - critical_vulns - high_vulns)
            severity_counter = {
                "關鍵風險": critical_vulns,
                "高風險": high_vulns,
                "中風險": int(medium_high * 0.7),  # 假設中風險約佔70%
                "低風險": int(medium_high * 0.3)   # 假設低風險約佔30%
            }
        
        if unpatched_vulns:
            risk_data = pd.DataFrame({
                "風險等級": list(severity_counter.keys()),
                "數量": list(severity_counter.values())
            })
            domain_order = ["關鍵風險", "高風險", "中風險", "低風險"]
            color_range = ["#d62728", "#ff7f0e", "#ffbb78", "#98df8a"]
            pie_chart = UIView.create_pie_chart(
                data=risk_data,
                theta_field="數量",
                color_field="風險等級",
                title="未修補漏洞風險分布",
                domain=domain_order,
                color_range=color_range
            )
            st.altair_chart(pie_chart, use_container_width=True)
        else:
            st.success("恭喜！目前沒有未修補的漏洞。")

    def show_asset(self):
        """顯示資產管理頁面"""
        st.write("以下顯示系統中管理的資產資訊：")
        history_data = self._get_history_data()
        if not history_data:
            return
        assets = history_data.get("assets", [])
        st.write(f"資產總數：{len(assets)}")
        filtered_assets = self._filter_assets(assets)
        self._display_asset_list(filtered_assets)
    
    def _filter_assets(self, assets):
        """過濾資產"""
        search_col1, search_col2 = st.columns([3, 1])
        with search_col1:
            search_term = st.text_input("搜尋資產 (主機名稱、IP、廠商)", placeholder="輸入關鍵字...")
        with search_col2:
            sort_by = st.selectbox("排序方式", ["風險 (高→低)", "風險 (低→高)", "主機名稱", "IP位址"])
        if search_term:
            search_term_lower = search_term.lower()
            filtered_assets = [
                a for a in assets 
                if any(search_term_lower in str(a.get("asset_info", {}).get(field, "")).lower() 
                      for field in ["Host Name", "IP Address", "Vendor"])
            ]
            st.info(f"找到 {len(filtered_assets)} 筆符合條件的資產")
        else:
            filtered_assets = assets
        sort_funcs = {
            "風險 (高→低)": lambda a: -sum(
                100 if v.get("base_score", 0) >= 9.0 else
                50 if v.get("base_score", 0) >= 7.0 else
                10 if v.get("base_score", 0) >= 4.0 else 1
                for v in a.get("vulnerabilities", [])
            ),
            "風險 (低→高)": lambda a: sum(
                100 if v.get("base_score", 0) >= 9.0 else
                50 if v.get("base_score", 0) >= 7.0 else
                10 if v.get("base_score", 0) >= 4.0 else 1
                for v in a.get("vulnerabilities", [])
            ),
            "主機名稱": lambda a: str(a.get("asset_info", {}).get("Host Name", "")).lower(),
            "IP位址": lambda a: str(a.get("asset_info", {}).get("IP Address", "")).lower()
        }
        sort_func = sort_funcs.get(sort_by)
        sorted_assets = sorted(filtered_assets, key=sort_func) if sort_func else filtered_assets
        return sorted_assets
    
    def _display_asset_list(self, assets):
        """顯示資產列表"""
        if assets:
            asset_list = [{
                "主機名稱": a.get("asset_info", {}).get("Host Name", "N/A"),
                "IP 位址": a.get("asset_info", {}).get("IP Address", "N/A"),
                "廠商": a.get("asset_info", {}).get("Vendor", "N/A"),
                "部門/管理人": a.get("asset_info", {}).get("Department", "N/A"),
                "漏洞數": len(a.get("vulnerabilities", []))
            } for a in assets]
            df = pd.DataFrame(asset_list)
            st.dataframe(df, use_container_width=True)
            if st.checkbox("顯示詳細資訊"):
                self._display_asset_details(assets)
        else:
            st.warning("沒有找到符合條件的資產")
    
    def _display_asset_details(self, assets):
        """顯示資產詳細資訊"""
        host_names = [a.get("asset_info", {}).get("Host Name", "N/A") for a in assets]
        selected_host = st.selectbox("選擇資產", host_names)
        selected_asset = next((a for a in assets if a.get("asset_info", {}).get("Host Name") == selected_host), None)
        if selected_asset:
            st.markdown("#### 資產基本資訊")
            info = selected_asset.get("asset_info", {})
            info_cols = st.columns(2)
            with info_cols[0]:
                st.write(f"**維護等級**: {info.get('Maintenance Level', 'N/A')}")
                st.write(f"**購買成本**: ${info.get('Purchase Cost', 'N/A')}")
                st.write(f"**年度維護成本**: ${info.get('Maintenance Cost (per year)', 'N/A')}")
            with info_cols[1]:
                st.write(f"**保固開始日期**: {info.get('Warranty Start Date', 'N/A')}")
                st.write(f"**保固結束日期**: {info.get('Warranty End Date', 'N/A')}")
            st.markdown("#### 發現的弱點")
            vulnerabilities = selected_asset.get("vulnerabilities", [])
            if vulnerabilities:
                vuln_list = [{
                    "CVE ID": v.get("cve_id", "N/A"),
                    "描述": DataModel.truncate_text(v.get("description", ""), 50),
                    "風險等級": v.get("severity", "N/A"),
                    "CVSS": v.get("base_score", "N/A"),
                    "狀態": "已修補" if v.get("patched", False) else "未修補"
                } for v in vulnerabilities]
                df_vuln = pd.DataFrame(vuln_list)
                st.dataframe(df_vuln, use_container_width=True)
            else:
                st.success("此資產未發現漏洞")
    
    def render_recommendation(self, vuln_id: str) -> Dict[str, Any]:
        """為特定漏洞生成或獲取推薦方案"""
        cache_key = f"recommendation_{vuln_id}"
        regenerate = st.session_state.get("regenerate_recommendation", False)
        if cache_key in st.session_state and not regenerate:
            return st.session_state[cache_key]
        
        with st.spinner("正在生成修補建議..."):
            try:
                api_result = DataModel.api_request("recommendation", "POST", {"cve_id": vuln_id})
                
                if api_result and api_result.get("status") == "success":
                    # 取得API返回的數據
                    result = api_result.get("data", {})
                    ragas_eval = api_result.get("ragas_evaluation", {})
                    contexts = api_result.get("contexts", [])
                    
                    # 輸出日志查看ragas_evaluation內容
                    logger.info(f"Recommendation API result: {api_result}")
                    logger.info(f"RAGAS Evaluation: {ragas_eval}")
                    
                    # 確保結果包含必要字段
                    if "recommendation" not in result and "recommendation" in api_result.get("data", {}):
                        result["recommendation"] = api_result["data"]["recommendation"]
                    
                    # 創建ragas_scores結構並添加日志
                    result["ragas_scores"] = {
                        "faithfulness": ragas_eval.get("faithfulness", 0.0),
                        "answer_relevancy": ragas_eval.get("answer_relevancy", 0.0)
                    }
                    logger.info(f"Created ragas_scores: {result['ragas_scores']}")
                    
                    # 直接設置評分到頂層
                    result["faithfulness"] = result["ragas_scores"]["faithfulness"]
                    result["answer_relevancy"] = result["ragas_scores"]["answer_relevancy"]
                    
                    # 添加時間戳
                    if "generated_at" not in result:
                        result["generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    
                    # 默認性能指標
                    if "performance_metrics" not in result:
                        result["performance_metrics"] = {
                            "響應時間(秒)": ragas_eval.get("execution_time", 0.0),
                            "上下文數量": len(contexts),
                            "生成字元數": len(result.get("recommendation", ""))
                        }
                        logger.info(f"Created performance_metrics: {result['performance_metrics']}")
                            
                    # 添加資源使用信息
                    if "resource_usage" not in result:
                        result["resource_usage"] = {
                            "記憶體使用": "低",
                            "處理時間": "普通",
                            "API調用次數": 1,
                            "RAG策略": ragas_eval.get("rag_strategy", "未知")
                        }
                        logger.info(f"Created resource_usage: {result['resource_usage']}")
                else:
                    result = self._get_empty_recommendation()
                    if api_result:
                        st.error(f"API請求失敗: {api_result.get('message', '未知錯誤')}")
                        logger.error(f"API請求失敗: {api_result}")
                    else:
                        st.error("伺服器無回應")
                        logger.error("伺服器無回應")
            except Exception as e:
                st.warning(f"生成建議失敗: {e}")
                logger.error(f"生成建議失敗: {e}", exc_info=True)
                result = self._get_empty_recommendation()
        
        # 記錄最終結果
        logger.info(f"Final recommendation result for {vuln_id}: {result}")
        
        st.session_state[cache_key] = result
        self._update_recommendation_history(vuln_id, result)
        if regenerate:
            st.session_state.regenerate_recommendation = False
        return result

    def _get_vulnerability_data(self, vuln_id):
        """獲取漏洞資訊"""
        vuln_data = None
        if "selected_vuln_details" in st.session_state:
            vuln_data = st.session_state.selected_vuln_details.get("_original_data", {})
        if not vuln_data:
            vuln_data = next(
                (v.get("_original_data", {}) for v in st.session_state.get("enhanced_vulnerabilities", [])
                 if v.get("弱點ID") == vuln_id),
                None
            )
        return vuln_data
    
    def _get_empty_recommendation(self):
        """返回空的推薦結果"""
        return {
            "recommendation": "無法獲取漏洞資料",
            "evaluation_scores": {},
            "resource_usage": {},
            "performance_metrics": {}
        }
    
    def _update_recommendation_history(self, vuln_id, result):
        """更新推薦歷史記錄"""
        if "recommendation_history" not in st.session_state:
            st.session_state.recommendation_history = {}
        if vuln_id not in st.session_state.recommendation_history:
            st.session_state.recommendation_history[vuln_id] = []
        history_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "recommendation": result.get("recommendation", ""),
            "evaluation_scores": result.get("evaluation_scores", {})
        }
        st.session_state.recommendation_history[vuln_id].append(history_entry)
        if len(st.session_state.recommendation_history[vuln_id]) > 5:
            st.session_state.recommendation_history[vuln_id] = st.session_state.recommendation_history[vuln_id][-5:]
    
    def show_vuln(self):
        """顯示弱點管理頁面"""
        if st.session_state.selected_cve:
            self._show_vulnerability_details()
            return
            
        st.write("以下顯示系統中偵測到的漏洞資訊，支持多種互動功能。")
        
        # 直接從歷史數據獲取漏洞信息
        history_data = DataModel.fetch_data("history")
        if not history_data:
            st.error("無法載入系統數據，請稍後重試")
            if st.button("重新載入", key="reload_vuln"):
                st.experimental_rerun()
            return
            
        # 預處理數據
        history_data = DataModel.preprocess_history_data(history_data)
        
        # 從歷史數據中提取所有漏洞信息
        vulnerabilities = DataModel.collect_all_vulnerabilities(history_data.get("assets", []))
        
        # 增強漏洞數據以供前端顯示
        enhanced_vulnerabilities = DataModel.enhance_vulnerability_data(vulnerabilities)
        st.session_state.enhanced_vulnerabilities = enhanced_vulnerabilities
        
        # 根據過濾條件篩選漏洞
        filtered_vulns = self._filter_vulnerabilities(enhanced_vulnerabilities)
        
        # 顯示漏洞數量統計
        st.info(f"顯示 {len(filtered_vulns)} 個漏洞，共 {len(enhanced_vulnerabilities)} 個")
        
        # 提供下載選項
        UIView.download_buttons(filtered_vulns, "vulnerability")
        
        # 選擇顯示的列
        display_columns = self._select_display_columns()
        
        # 顯示漏洞表格
        UIView.display_vuln_table(filtered_vulns, display_columns)
        
        # 處理選定CVE的重新加載
        if st.session_state.selected_cve:
            st.experimental_rerun()
            
        # 處理修復計劃
        self._handle_remediation_plan(filtered_vulns)

    def _handle_remediation_plan(self, filtered_vulns):
        """處理生成漏洞修補建議並顯示評估結果"""
        if filtered_vulns:
            st.markdown("### 漏洞修補建議")
            if 'remediation_plan' in st.session_state and st.session_state.remediation_plan:
                # 顯示已存在的修補建議和評估結果
                UIView.display_remediation_plan(st.session_state.remediation_plan.get("recommendation", ""))
                ragas_scores = st.session_state.remediation_plan.get("ragas_scores", {})
                if ragas_scores:
                    UIView.display_evaluation_results(ragas_scores)
            elif st.button("生成漏洞修補建議", key="generate_remediation"):
                selected_vulns = self._select_top_vulnerabilities(filtered_vulns)
                if not selected_vulns:
                    st.error("無法獲取有效的漏洞數據以生成修補建議")
                    return
                    
                with st.spinner("正在生成修補建議..."):
                    vuln_data = selected_vulns[0].get("_original_data", {})
                    
                    # 只使用API獲取建議和評估結果
                    api_payload = {
                        "cve_id": vuln_data.get("cve_id"),
                        "vuln_data": vuln_data
                    }
                    
                    logger.info(f"發送修補建議請求: {vuln_data.get('cve_id')}")
                    api_result = DataModel.api_request("recommendation", "POST", api_payload)
                    
                    if api_result and api_result.get("status") == "success":
                        logger.info(f"API返回: {api_result}")
                        self._process_successful_api_result(api_result)
                    else:
                        error_msg = api_result.get("message", "未知錯誤") if api_result else "伺服器無回應"
                        st.error(f"無法獲取修補建議: {error_msg}")
                        logger.error(f"API請求失敗: {error_msg}")

    def _process_successful_api_result(self, api_result):
        """處理成功的API回應"""
        # 提取數據
        recommendation_data = api_result.get("data", {})
        recommendation = recommendation_data.get("recommendation", "")
        ragas_eval = api_result.get("ragas_evaluation", {})
        
        # 顯示修補建議
        UIView.display_remediation_plan(recommendation, key_prefix="initial")
        
        # 創建評估結構
        ragas_scores = {
            "faithfulness": ragas_eval.get("faithfulness", 0.0),
            "answer_relevancy": ragas_eval.get("answer_relevancy", 0.0)
        }
        
        # 顯示評估結果
        UIView.display_evaluation_results(ragas_scores)
        
        # 儲存結果
        st.session_state.remediation_plan = {
            "recommendation": recommendation,
            "ragas_scores": ragas_scores,
            "generated_at": datetime.datetime.now().isoformat()
        }

    def _show_vulnerability_details(self):
        """顯示單個漏洞詳細資訊"""
        vuln_data = DataModel.fetch_data("vuln")
        logger.info(f"讀取到 vuln_data: {vuln_data}")
        if not vuln_data:
            st.error("無法載入漏洞數據，請稍後重試")
            if st.button("重新載入"):
                st.experimental_rerun()
            return
        vulnerabilities = DataModel.validate_vulnerability_data(vuln_data.get("vulnerabilities", []))
        enhanced_vulnerabilities = DataModel.enhance_vulnerability_data(vulnerabilities)
        st.session_state.enhanced_vulnerabilities = enhanced_vulnerabilities
        UIView.display_vulnerability_details(
            st.session_state.selected_cve, 
            enhanced_vulnerabilities,
            DataModel.update_vulnerability_status,
            self.render_recommendation
        )
    
    def _filter_vulnerabilities(self, vulnerabilities):
        """篩選漏洞"""
        filter_cols = st.columns([1, 2, 1])
        with filter_cols[0]:
            severity_filter = st.multiselect(
                "風險等級篩選",
                ["關鍵 (Critical)", "高風險 (High)", "中風險 (Medium)", "低風險 (Low)"],
                default=["關鍵 (Critical)", "高風險 (High)"]
            )
        with filter_cols[1]:
            search_query = st.text_input("搜尋漏洞", placeholder="輸入 CVE ID、描述或產品關鍵字")
        with filter_cols[2]:
            status_filter = st.radio(
                "修補狀態",
                ["全部", "未修補", "已修補"],
                horizontal=True,
                index=1
            )
        with st.expander("高級篩選選項"):
            adv_cols = st.columns(3)
            with adv_cols[0]:
                epss_min = st.slider("最低 EPSS 分數", 0.0, 1.0, 0.0, 0.01)
            with adv_cols[1]:
                kev_only = st.checkbox("僅顯示 KEV 漏洞", False)
            with adv_cols[2]:
                age_max = st.slider("最大漏洞(天數)", 0, 365, 365)
        filter_functions = []
        if severity_filter:
            severity_set = set(severity_filter)
            filter_functions.append(lambda v: v["弱點嚴重度"] in severity_set)
        if status_filter == "未修補":
            filter_functions.append(lambda v: v["狀態"] == "未修補")
        elif status_filter == "已修補":
            filter_functions.append(lambda v: v["狀態"] == "已修補")
        if search_query:
            search_lower = search_query.lower()
            filter_functions.append(lambda v: any(
                search_lower in str(v.get(field, "")).lower() 
                for field in ["弱點ID", "描述", "產品"]
            ))
        if epss_min > 0:
            filter_functions.append(lambda v: 
                v["EPSS 分數"] != "N/A" and 
                float(v["EPSS 分數"]) >= epss_min
            )
        if kev_only:
            filter_functions.append(lambda v: v.get("_original_data", {}).get("in_kev", False))
        if age_max < 365:
            filter_functions.append(lambda v: 
                v["天數"] != "N/A" and 
                int(v["天數"].split(" ")[0]) <= age_max
            )
        current_filter_hash = hash((tuple(severity_filter), search_query, status_filter, epss_min, kev_only, age_max))
        if st.session_state.remediation_filter_hash and current_filter_hash != st.session_state.remediation_filter_hash:
            if 'remediation_plan' in st.session_state:
                del st.session_state.remediation_plan
        st.session_state.remediation_filter_hash = current_filter_hash
        if filter_functions:
            filtered_vulns = [v for v in vulnerabilities if all(f(v) for f in filter_functions)]
        else:
            filtered_vulns = vulnerabilities
        return filtered_vulns
 
    def _select_display_columns(self):
        """選擇顯示的列"""
        with st.expander("顯示設定"):
            available_columns = [
                "產品/IP",
                "弱點嚴重度",
                "CVE ID",
                "描述",
                "CVSS",
                "EPSS 分數/百分比",
                "KEV",
                "SLA",
                "狀態",
                "修復計畫"
            ]
            display_columns = st.multiselect(
                "選擇顯示的列",
                options=available_columns,
                default=available_columns
            )
        return display_columns
    

    def _select_top_vulnerabilities(self, vulnerabilities, limit=20):
        """選擇最高風險的漏洞"""
        if len(vulnerabilities) > limit:
            st.info(f"為了更高效的分析，從 {len(vulnerabilities)} 個漏洞中選取最高風險的前{limit}個進行修補建議生成")
            def get_vuln_priority(v):
                original_data = v.get("_original_data", {})
                # 使用更新後的風險優先級公式結果
                if "priority_score" in original_data:
                    return original_data.get("priority_score", 0)
                    
                # 如果沒有計算好的優先級分數，使用原數據計算
                return DataModel.calculate_priority_score(original_data)
                
            selected_vulns = sorted(vulnerabilities, key=get_vuln_priority, reverse=True)[:limit]
        else:
            selected_vulns = vulnerabilities
        return selected_vulns

    def show_risk_reduction(self):
        """顯示風險降低頁面"""
        st.write("以下顯示近期風險降低策略的統計數據：")
        history_data = self._get_history_data()
        if not history_data:
            return
        risk_chart_data = self._calculate_risk_reduction_stats(history_data)
        domain = ["降低 (Reduce)", "轉移 (Transfer)", "規避 (Avoid)"]
        color_range = ["#4f88ff", "#ffbb78", "#98df8a"]
        chart = UIView.create_risk_chart(
            risk_data=risk_chart_data,
            chart_title="風險降低策略統計",
            domain=domain,
            color_range=color_range
        )
        st.altair_chart(chart, use_container_width=True)
        st.subheader("風險降低計畫")
        self._display_risk_reduction_plans()
    
    def _calculate_risk_reduction_stats(self, history_data):
        """計算風險降低統計"""
        assets = history_data.get("assets", [])
        all_vulnerabilities = DataModel.collect_all_vulnerabilities(assets)
        risk_counter = Counter(v.get('risk_status', 'None') for v in all_vulnerabilities)
        risk_changes = {
            'reduce': risk_counter.get('Reduce', 0),
            'transfer': risk_counter.get('Transfer', 0),
            'avoid': risk_counter.get('Avoid', 0)
        }
        if sum(risk_changes.values()) == 0:
            risk_changes = {'reduce': 5, 'transfer': 2, 'avoid': 3}
        risk_data = pd.DataFrame({
            "策略": ["降低 (Reduce)", "轉移 (Transfer)", "規避 (Avoid)"],
            "數量": [risk_changes["reduce"], risk_changes["transfer"], risk_changes["avoid"]]
        })
        return risk_data
    
    def _display_risk_reduction_plans(self):
        """顯示風險降低計畫"""
        reduction_plans = [
            {"CVE ID": "CVE-2023-1234", "風險等級": "關鍵 (Critical)", "降低策略": "升級系統", "負責人": "資安部門", "預計完成日期": "2025-04-15"},
            {"CVE ID": "CVE-2023-5678", "風險等級": "高風險 (High)", "降低策略": "啟用防火牆規則", "負責人": "網路團隊", "預計完成日期": "2025-03-20"},
            {"CVE ID": "CVE-2024-3456", "風險等級": "中風險 (Medium)", "降低策略": "安裝修補程式", "負責人": "IT 部門", "預計完成日期": "2025-03-15"}
        ]
        df = pd.DataFrame(reduction_plans)
        st.dataframe(df, use_container_width=True)
    
    def show_risk_acceptance(self):
        """顯示風險接受頁面"""
        st.write("以下顯示已接受風險的項目清單：")
        history_data = self._get_history_data()
        if not history_data:
            return
        accepted_risks, reason_counts = self._process_risk_acceptance_data(history_data)
        df = pd.DataFrame(accepted_risks)
        st.dataframe(df, use_container_width=True)
        reason_data = pd.DataFrame({
            "原因": list(reason_counts.keys()),
            "數量": list(reason_counts.values())
        })
        chart = UIView.create_risk_chart(
            risk_data=reason_data,
            chart_title="風險接受原因分布",
            domain=list(reason_counts.keys()),
            color_range=["#4f88ff", "#ff7f0e", "#ffbb78", "#98df8a"][:len(reason_counts)]
        )
        st.altair_chart(chart, use_container_width=True)
    
    def _process_risk_acceptance_data(self, history_data):
        """處理風險接受數據"""
        assets = history_data.get("assets", [])
        all_vulnerabilities = DataModel.collect_all_vulnerabilities(assets)
        retained_vulns = [v for v in all_vulnerabilities if v.get('risk_status') == 'Retain']
        if not retained_vulns:
            mock_data = [
                {
                    "CVE ID": "CVE-2022-9999",
                    "描述": "模擬漏洞1：業務考量下接受",
                    "風險等級": "中風險 (Medium)",
                    "原因": "業務考量",
                    "接受人": "資訊長",
                    "接受日期": "2025-03-01",
                    "重新評估日期": "2025-06-01"
                },
                {
                    "CVE ID": "CVE-2022-8888",
                    "描述": "模擬漏洞2：技術限制下接受",
                    "風險等級": "高風險 (High)",
                    "原因": "技術限制",
                    "接受人": "IT 主管",
                    "接受日期": "2025-04-15",
                    "重新評估日期": "2025-07-15"
                }
            ]
            reason_counts = {"業務考量": 1, "技術限制": 1, "成本考量": 0, "其他": 0}
        else:
            reason_counter = Counter(v.get('risk_reason', '其他') for v in retained_vulns)
            reason_counts = dict(reason_counter)
            mock_data = [{
                "CVE ID": v.get("cve_id", "N/A"),
                "描述": DataModel.truncate_text(v.get("description", ""), 50),
                "風險等級": v.get("severity", "N/A"),
                "原因": v.get('risk_reason', '其他'),
                "接受人": v.get("approver", "N/A"),
                "接受日期": v.get("acceptance_date", "N/A"),
                "重新評估日期": v.get("reassessment_date", "N/A")
            } for v in retained_vulns]
        return mock_data, reason_counts
    
    def render_tab_navigation(self, current_tab: int):
        """渲染標籤頁切換的 JavaScript 代碼"""
        if current_tab > 0:
            js = f"""
            <script>
                requestAnimationFrame(function() {{
                    const tabs = window.parent.document.querySelectorAll("[data-baseweb='tab']");
                    if (tabs && tabs.length > {current_tab}) {{
                        tabs[{current_tab}].click();
                    }}
                    setTimeout(function() {{
                        window.parent.postMessage({{
                            type: 'streamlit:setComponentValue',
                            value: 0,
                            dataType: 'number',
                            key: 'current_tab'
                        }}, '*');
                    }}, 100);
                }});
            </script>
            """
            st.markdown(js, unsafe_allow_html=True)