import requests
import json
import datetime
import time
import copy
import os
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter
import streamlit as st
import numpy as np

# 嘗試匯入 ragas 相關庫
try:
    from datasets import Dataset, Features, Value, Sequence
    from ragas.metrics import faithfulness, answer_relevancy, context_utilization
    from ragas import evaluate
    HAS_RAGAS = True
except ImportError:
    HAS_RAGAS = False
    RAGAS_WARNING_MSG = "未找到 Ragas 套件，將使用替代方法進行評估。"

# 嘗試匯入資源監控類
try:
    from services.eval import QueryResourceMonitor, MetricsCalculator
    HAS_RESOURCE_MONITOR = True
except ImportError:
    HAS_RESOURCE_MONITOR = False
    # 簡易版資源監控
    class SimpleResourceMonitor:
        def __init__(self):
            self.reset()
            
        def reset(self):
            self._start_time = None
            self._end_time = None
            
        def start_monitoring(self):
            self.reset()
            self._start_time = time.time()
            
        def stop_monitoring(self):
            self._end_time = time.time()
            
        def get_usage(self) -> Dict:
            if not self._start_time:
                return {"Total Time (s)": 0.0}
            total_time = (self._end_time or time.time()) - self._start_time
            return {"Total Time (s)": round(total_time, 3)}

    class SimpleMetricsCalculator:
        @staticmethod
        def calculate_metrics(raw_metrics: Dict, resource_usage: Dict) -> Dict[str, float]:
            total_duration = resource_usage.get("Total Time (s)", 0.0)
            return {
                "total_duration_s": total_duration,
                "efficiency_score": round(1.0 / (1.0 + total_duration), 4)
            }
            
    QueryResourceMonitor = SimpleResourceMonitor
    MetricsCalculator = SimpleMetricsCalculator

# API 基礎URL與緩存時間
API_BASE_URL = "http://localhost:5000"
DATA_CACHE_TTL = 300

class DataModel:
    """處理數據獲取、處理和緩存的模型類"""
    
    @staticmethod
    def api_request(endpoint: str, method: str = "GET", data: Optional[Dict] = None) -> Optional[Dict]:
        """統一處理 API 請求"""
        url = f"{API_BASE_URL}/{endpoint}"
        try:
            if method.upper() == "GET":
                response = requests.get(url, timeout=10)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, timeout=10)
            else:
                st.error(f"不支援的 HTTP 方法: {method}")
                return None
            if response.status_code == 200:
                return response.json()
            st.error(f"API 請求失敗: {response.status_code}")
            return None
        except requests.exceptions.RequestException as e:
            st.error(f"連接錯誤: {e}")
            return None
        except json.JSONDecodeError:
            st.error("無效的 JSON 響應")
            return None
        except Exception as e:
            st.error(f"請求出錯: {e}")
            return None

    @staticmethod
    def fetch_data(endpoint: str, force_refresh: bool = False) -> Optional[Dict]:
        """獲取並緩存 API 數據"""
        cache_key = f"data_{endpoint}"
        now = time.time()
        if 'data_cache' not in st.session_state:
            st.session_state.data_cache = {}
        cache = st.session_state.data_cache
        needs_update = (
            force_refresh or 
            cache_key not in cache or 
            now - cache.get(f"{cache_key}_time", 0) > DATA_CACHE_TTL
        )
        if needs_update:
            with st.spinner(f"正在獲取{endpoint}數據..."):
                result = DataModel.api_request(endpoint)
                if result and result.get("status") == "success":
                    cache[cache_key] = result.get("data", {})
                    cache[f"{cache_key}_time"] = now
                    return cache[cache_key]
                if endpoint == "vuln":
                    st.warning(f"無法獲取 {endpoint} 數據，嘗試使用歷史數據...")
                    history_data = DataModel.fetch_data("history")
                    if history_data:
                        history_data = DataModel.preprocess_history_data(history_data)
                        return {"vulnerabilities": DataModel.collect_all_vulnerabilities(history_data.get("assets", []))}
                return None
        return cache.get(cache_key)

    @staticmethod
    def clear_cache() -> None:
        """清除所有數據緩存"""
        if 'data_cache' in st.session_state:
            st.session_state.data_cache = {}

    @staticmethod
    def get_severity(cvss_score: float) -> str:
        if cvss_score >= 9.0:
            return "關鍵 (Critical)"
        elif cvss_score >= 7.0:
            return "高風險 (High)"
        elif cvss_score >= 4.0:
            return "中風險 (Medium)"
        elif cvss_score > 0:
            return "低風險 (Low)"
        else:
            return "無 (None)"

    @staticmethod
    def truncate_text(text: str, limit: int = 100) -> str:
        if not text:
            return ""
        return f"{text[:limit]}..." if len(text) > limit else text

    @staticmethod
    def calculate_priority_score(vuln: Dict) -> float:
        base_score = vuln.get('base_score', 0)
        epss_score = vuln.get('epss_score', 0) * 3
        kev_weight = 2 if vuln.get('in_kev', False) else 0
        age_weight = 0
        if 'published' in vuln:
            try:
                published_date = vuln['published']
                if isinstance(published_date, str):
                    published_date = datetime.datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                days_old = (datetime.datetime.now(datetime.timezone.utc) - published_date).days
                if days_old < 30:
                    age_weight = 1
                elif days_old < 90:
                    age_weight = 0.5
            except Exception:
                pass
        total_score = base_score * 0.5 + epss_score + kev_weight + age_weight
        return min(max(total_score, 0), 10)

    @staticmethod
    def validate_vulnerability_data(vulnerabilities: List[Dict]) -> List[Dict]:
        validated_vulns = []
        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue
            if 'cve_id' not in vuln or not vuln['cve_id']:
                continue
            valid_vuln = vuln.copy()
            if 'description' not in valid_vuln or not valid_vuln['description']:
                valid_vuln['description'] = f"漏洞 {valid_vuln.get('cve_id', 'N/A')}"
            if 'base_score' not in valid_vuln:
                valid_vuln['base_score'] = 0.0
            elif isinstance(valid_vuln['base_score'], str):
                try:
                    valid_vuln['base_score'] = float(valid_vuln['base_score'])
                except ValueError:
                    valid_vuln['base_score'] = 0.0
            if 'epss_score' not in valid_vuln:
                valid_vuln['epss_score'] = 0.0
            elif isinstance(valid_vuln['epss_score'], str):
                try:
                    valid_vuln['epss_score'] = float(valid_vuln['epss_score'])
                except ValueError:
                    valid_vuln['epss_score'] = 0.0
            if 'patched' not in valid_vuln:
                valid_vuln['patched'] = False
            if 'published' not in valid_vuln:
                valid_vuln['published'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            if 'severity' not in valid_vuln:
                valid_vuln['severity'] = DataModel.get_severity(valid_vuln['base_score'])
            if 'priority_score' not in valid_vuln:
                valid_vuln['priority_score'] = DataModel.calculate_priority_score(valid_vuln)
            validated_vulns.append(valid_vuln)
        return validated_vulns

    @staticmethod
    def preprocess_history_data(history_data: Dict) -> Dict:
        if not history_data:
            return {}
        processed_data = copy.deepcopy(history_data)
        for asset in processed_data.get("assets", []):
            for vuln_list_key in ["vulnerabilities", "raw_vulnerabilities"]:
                for vuln in asset.get(vuln_list_key, []):
                    if "severity" not in vuln:
                        vuln["severity"] = DataModel.get_severity(vuln.get("base_score", 0))
                    if "priority_score" not in vuln:
                        vuln["priority_score"] = DataModel.calculate_priority_score(vuln)
        return processed_data

    @staticmethod
    def collect_all_vulnerabilities(assets: List[Dict]) -> List[Dict]:
        passed_filter_ids = {
            vuln.get("cve_id") 
            for asset in assets 
            for vuln in asset.get("vulnerabilities", [])
            if vuln.get("cve_id")
        }
        all_vulnerabilities = []
        for asset in assets:
            info = asset.get("asset_info", {})
            for vuln in asset.get("raw_vulnerabilities", []):
                v = vuln.copy()
                v["host_name"] = info.get("Host Name", "N/A")
                v["ip_address"] = info.get("IP Address", "N/A")
                v["asset_info"] = info
                if "severity" not in v:
                    v["severity"] = DataModel.get_severity(v.get("base_score", 0))
                if "priority_score" not in v:
                    v["priority_score"] = DataModel.calculate_priority_score(v)
                v["passed_filter"] = v.get("cve_id") in passed_filter_ids
                if "patched" not in v:
                    v["patched"] = False
                all_vulnerabilities.append(v)
        return all_vulnerabilities

    @staticmethod
    def enhance_vulnerability_data(vulnerabilities: List[Dict]) -> List[Dict]:
        now = datetime.datetime.now(datetime.timezone.utc)
        enhanced_vulnerabilities = []
        for vuln in vulnerabilities:
            days_old = None
            epss_percentile = "N/A"
            if "published" in vuln:
                try:
                    published_date = vuln.get("published")
                    if isinstance(published_date, str):
                        published_date = datetime.datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    days_old = (now - published_date).days
                except Exception:
                    pass
            sla_status = "超時" if (days_old and days_old > 30 and not vuln.get("patched", False)) else "正常"
            if "epss_score" in vuln:
                try:
                    epss_score = vuln.get("epss_score", 0)
                    if epss_score > 0:
                        epss_percentile = f"{epss_score * 100:.2f}%"
                except Exception:
                    pass
            asset_info = vuln.get("asset_info", {})
            product_name = asset_info.get("Host Name") or asset_info.get("hostname") or "N/A"
            ip_address = asset_info.get("IP Address") or asset_info.get("ip_address") or vuln.get("ip_address", "N/A")
            cwe_list = vuln.get("cwes", [])
            cwe_id = vuln.get("cwe_id") or (cwe_list[0] if cwe_list else "N/A")
            enhanced_vuln = {
                "弱點嚴重度": vuln.get("severity", "N/A"),
                "弱點ID": vuln.get("cve_id", "N/A"),
                "描述": vuln.get("description", ""),
                "CWE": cwe_id,
                "CVE 分數": vuln.get("base_score", ""),
                "EPSS 分數": f"{vuln.get('epss_score', 0):.4f}" if 'epss_score' in vuln else "N/A",
                "EPSS 百分位數": epss_percentile,
                "發布日期": vuln.get("published", "N/A"),
                "SLA": sla_status,
                "狀態": "已修補" if vuln.get("patched", False) else "未修補",
                "產品": product_name,
                "IP地址": ip_address,
                "產品/IP": f"{product_name} / {ip_address}" if product_name != "N/A" or ip_address != "N/A" else "N/A",
                "服務": asset_info.get("Service", "N/A"),
                "修復計畫": "已修補" if vuln.get("patched", False) else vuln.get("remediation_date", "未排程"),
                "人員": vuln.get("reporter", ""),
                "主管": vuln.get("reviewers", "N/A"),
                "天數": f"{days_old} 天" if days_old is not None else "N/A",
                "KEV": "是" if vuln.get("in_kev", False) else "否",
                "_original_data": vuln
            }
            enhanced_vulnerabilities.append(enhanced_vuln)
        return enhanced_vulnerabilities

    @staticmethod
    def update_vulnerability_status(cve_id: str, patched: bool) -> Tuple[bool, str]:
        try:
            result = DataModel.api_request("update_vuln", "POST", {"cve_id": cve_id, "patched": patched})
            if result and result.get("status") == "success":
                DataModel.clear_cache()
                return True, "成功更新漏洞狀態"
            else:
                return False, f"更新失敗: {result.get('message', '未知錯誤') if result else '伺服器無回應'}"
        except Exception as e:
            return False, f"更新失敗: {str(e)}"
    
    @staticmethod
    def generate_recommendation(vuln_data: Dict) -> str:
        if not vuln_data:
            return "無漏洞資訊可用，無法生成修補建議。"
        vuln_list = [vuln_data] if not isinstance(vuln_data, list) else vuln_data
        try:
            return DataModel.generate_remediation_plan(vuln_list)
        except Exception as e:
            st.warning(f"生成修補建議時出錯: {str(e)}。使用替代方法。")
            return "無法生成修補建議。請稍後重試。"
    
    @staticmethod
    def evaluate_report_with_ragas(report: str, vuln_data: Dict) -> Dict[str, float]:
        resource_monitor = QueryResourceMonitor()
        resource_monitor.start_monitoring()
        query = f"如何修補 {vuln_data.get('cve_id', 'N/A')} 漏洞？"
        contexts = []
        if vuln_data.get('description'):
            contexts.append(f"漏洞描述: {vuln_data.get('description')}")
        if vuln_data.get('base_score'):
            contexts.append(f"CVSS基礎分數: {vuln_data.get('base_score')}")
        references = vuln_data.get('references', [])
        if references:
            contexts.append(f"參考資料: {', '.join(references[:5])}")
        if vuln_data.get('product'):
            contexts.append(f"受影響產品: {vuln_data.get('product')}")
        ragas_scores = DataModel._evaluate_with_ragas(query, report, contexts)
        resource_monitor.stop_monitoring()
        resource_usage = resource_monitor.get_usage()
        raw_metrics = {
            "prompt": query,
            "response_text": report,
            "contexts": contexts
        }
        performance_metrics = MetricsCalculator.calculate_metrics(raw_metrics, resource_usage)
        return ragas_scores

    @staticmethod
    def _evaluate_with_ragas(query: str, answer: str, contexts: List[str]) -> Dict[str, float]:
        """使用 Ragas 評估答案質量"""
        # 如果未安裝 ragas 套件，直接返回預設分數
        if not HAS_RAGAS:
            return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
        if not query or not answer or not contexts:
            return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
        try:
            # 將上下文列表轉換為單一字串（使用換行符連接）
            contexts_str = "\n".join(contexts)
            dataset = Dataset.from_dict({
                "question": [query],
                "answer": [answer],
                "contexts": [contexts_str]
            }, features=Features({
                'question': Value('string'),
                'answer': Value('string'),
                'contexts': Value('string'),
            }))
            results = evaluate(
                dataset=dataset,
                metrics=[faithfulness, answer_relevancy, context_utilization]
            )
            scores = {}
            for name, score in results.items():
                if isinstance(score, (list, np.ndarray)):
                    scores[name] = round(float(score[0]), 4)
                else:
                    scores[name] = round(float(score), 4)
            return scores
        except Exception as e:
            st.error(f"Ragas 評估錯誤: {str(e)}")
            return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}

    @staticmethod
    def generate_remediation_plan(vulnerabilities: List[Dict]) -> str:
        if not vulnerabilities:
            return "無漏洞資訊可用，無法生成修補建議。"
        try:
            history_data = {
                'assets': [
                    {
                        'asset_info': {'Host Name': 'All Vulnerabilities', 'IP Address': 'Multiple'},
                        'vulnerabilities': vulnerabilities
                    }
                ]
            }
            try:
                import sys, os
                current_dir = os.path.dirname(os.path.abspath(__file__))
                sys.path.append(os.path.join(current_dir, '..'))
                from services.query import generate_vulnerability_report
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                report = loop.run_until_complete(generate_vulnerability_report(history_data))
                loop.close()
                if report:
                    return report
                else:
                    return "無法從API生成修補建議。"
            except (ImportError, ModuleNotFoundError) as e:
                st.warning(f"無法導入 generate_vulnerability_report 函數: {e}。使用替代方法。")
        except Exception as e:
            st.warning(f"無法使用原始報告生成函數: {str(e)}。使用替代方法。")
        try:
            from langchain_openai import ChatOpenAI
            api_key = os.environ.get("OPENAI_API_KEY")
            if not api_key:
                return "無法生成修補計劃：未找到OpenAI API密鑰。請設置OPENAI_API_KEY環境變數。"
            llm_agent = ChatOpenAI(
                temperature=0.1,
                model="gpt-4o-mini",
                api_key=api_key,
                request_timeout=60,
                max_retries=2
            )
            vuln_entries = []
            for vuln in vulnerabilities:
                cve_id = vuln.get('cve_id', 'N/A')
                severity = vuln.get('severity', 'Unknown')
                description = vuln.get('description', '')
                impact = vuln.get('impact', '')
                entry = f"CVE: {cve_id} | 嚴重性: {severity}\n描述: {description}"
                if impact:
                    entry += f"\n影響: {impact}"
                vuln_entries.append(entry)
            combined_vuln_str = "\n\n".join(vuln_entries)
            prompt = f"""tell me about {combined_vuln_str}, what can i fix it? """
            response = llm_agent.invoke([
                {"role": "system", "content": "你是一位資安專家，專門提供漏洞修補建議，你的建議應該簡潔明瞭、可操作且有條理。請使用專業但易於理解的口吻，以結構化的Markdown格式生成報告。"},
                {"role": "user", "content": prompt}
            ])
            return response.content if response.content else "無法從LLM生成有效的修補建議。"
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            st.error(f"生成修補計劃時出錯: {e}")
            return f"""
    ## 無法生成完整修補計劃

    很抱歉，在處理您的請求時遇到了問題：

    ```{error_details}```
    請稍後重試，或手動制定修補方案。
    """

    @staticmethod
    def generate_recommendation_with_evaluation(vuln_data: Dict) -> Dict[str, Any]:
        recommendation = DataModel.generate_recommendation(vuln_data)
        ragas_scores = DataModel.evaluate_report_with_ragas(recommendation, vuln_data)
        overall_score = np.mean([
            ragas_scores.get("faithfulness", 0.0),
            ragas_scores.get("answer_relevancy", 0.0),
            ragas_scores.get("context_utilization", 0.0)
        ])
        return {
            "recommendation": recommendation,
            "ragas_scores": ragas_scores,
            "overall_score": float(overall_score),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
    
    @staticmethod
    def generate_recommendation_with_ragas(vuln_data: Dict) -> Dict[str, Any]:
        try:
            from services.recom import RecommendationService
            if 'recommendation_service' not in st.session_state:
                service = RecommendationService()
                st.session_state.recommendation_service = service
            else:
                service = st.session_state.recommendation_service
            try:
                # 若當前有正在運行的事件迴圈，使用 run_coroutine_threadsafe
                loop = asyncio.get_running_loop()
                result = asyncio.run_coroutine_threadsafe(
                    service.generate_recommendation_with_ragas(vuln_data),
                    loop
                ).result()
            except RuntimeError:
                # 如果沒有正在運行的事件迴圈，使用 asyncio.run
                result = asyncio.run(service.generate_recommendation_with_ragas(vuln_data))
            return result
        except Exception as e:
            st.warning(f"使用增強型推薦服務失敗: {e}，使用替代方法")
            return DataModel.generate_recommendation_with_evaluation(vuln_data)
