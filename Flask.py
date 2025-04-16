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

import os, sys, json, datetime, asyncio, logging
from typing import Dict, Any, List, Optional
from bson import ObjectId
from quart import Quart, request, jsonify, Blueprint
from quart_cors import cors
from services.db import DatabaseManager
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def load_config():
    # 完全依賴環境變數，由Dockerfile設定
    return {
        "MONGODB_URI": os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
        "ASSET_DB": os.getenv("ASSET_DB", "assets"),
        "NVD_DB": os.getenv("NVD_DB", "nvd_db"), 
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", "ollama"),
        "MODEL": os.getenv("MODEL", "openai:gpt-4o-mini"),
        "OPENAI_BASE_URL": os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    }

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

api_bp = Blueprint("api", __name__)

class DataService:
    @staticmethod
    async def get_asset_history(filters: Optional[Dict] = None) -> Dict:
        from services.query import QueryService
        return await QueryService.get_instance().get_asset_history(filters or {})
    
    @staticmethod
    async def get_vulnerabilities(filters: Optional[Dict] = None, sort_field: str = "base_score", 
                                  sort_order: int = -1, limit: int = 100, skip: int = 0) -> List[Dict]:
        from services.db import DatabaseManager
        query = DataService._build_vulnerability_query(filters or {})
        sort_condition = [(sort_field, sort_order)]
        return await DatabaseManager.get_instance().vuln_repo.search_vulnerabilities(
            query, sort=sort_condition, limit=limit, skip=skip
        )
    
    @staticmethod
    async def count_vulnerabilities(filters: Optional[Dict] = None) -> int:
        from services.db import DatabaseManager
        query = DataService._build_vulnerability_query(filters or {})
        return await DatabaseManager.get_instance().vuln_repo.count(query)

    @staticmethod
    def _build_vulnerability_query(filters: Dict) -> Dict:
        query = {}
        if "min_cvss" in filters:
            query["base_score"] = {"$gte": float(filters["min_cvss"])}
        if "max_cvss" in filters:
            if "base_score" not in query:
                query["base_score"] = {}
            query["base_score"]["$lte"] = float(filters["max_cvss"])
        if "epss_min" in filters:
            query["epss_score"] = {"$gte": float(filters["epss_min"])}
        if "include_kev" in filters and filters["include_kev"]:
            query["in_kev"] = True
        if "keyword" in filters and filters["keyword"]:
            query["$or"] = [
                {"cve_id": filters["keyword"]},
                {"description": filters["keyword"]},
                {"product": filters["keyword"]}
            ]
        return query
    
    @staticmethod
    def enhance_vulnerability(vuln: Dict) -> Dict:
        if not isinstance(vuln, dict) or "cve_id" not in vuln:
            return {}
        enhanced_vuln = {
            "cve_id": vuln["cve_id"],
            "description": vuln.get("description", "無描述"),
            "base_score": vuln.get("base_score", 0),
            "published": vuln.get("published", ""),
            "patched": vuln.get("patched", False)
        }
        if "published" in vuln and vuln["published"]:
            try:
                if isinstance(vuln["published"], str):
                    published_date = datetime.datetime.fromisoformat(vuln["published"].replace('Z', '+00:00'))
                else:
                    published_date = vuln["published"]
                enhanced_vuln["days_ago"] = (datetime.datetime.now(datetime.timezone.utc) - published_date).days
            except Exception:
                enhanced_vuln["days_ago"] = None
        if not vuln.get("severity") and "base_score" in vuln:
            score = float(vuln["base_score"])
            if score >= 9.0: enhanced_vuln["severity"] = "關鍵 (Critical)"
            elif score >= 7.0: enhanced_vuln["severity"] = "高風險 (High)"
            elif score >= 4.0: enhanced_vuln["severity"] = "中風險 (Medium)"
            else: enhanced_vuln["severity"] = "低風險 (Low)"
        else:
            enhanced_vuln["severity"] = vuln.get("severity", "")
        if "epss_score" in vuln:
            enhanced_vuln["epss_score"] = vuln["epss_score"]
            enhanced_vuln["epss_percentile"] = f"{vuln['epss_score']*100:.2f}%"
        enhanced_vuln["in_kev"] = vuln.get("in_kev", False)
        if "product" in vuln: enhanced_vuln["product"] = vuln["product"]
        if "references" in vuln and isinstance(vuln["references"], list):
            enhanced_vuln["references"] = vuln["references"]
        return enhanced_vuln

@api_bp.route("/health", methods=["GET"])
async def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.datetime.now().isoformat()})

@api_bp.route("/settings", methods=["GET", "POST"])
async def settings():
    """管理應用程式設定"""
    try:
        # 初始化默認設定 - 從環境變數中獲取
        if not hasattr(settings, 'current_settings'):
            config = load_config()
            settings.current_settings = {
                "min_cvss": 7.0, 
                "epss_min": 0.0,
                "include_kev": False, 
                "strategy": os.getenv("RAG_STRATEGY", "colbert"),  # 與rag.py中的默認策略對齊
                "model": config["MODEL"]  # 從環境變數獲取
            }

        if request.method == "GET":
            logger.info(f"Current settings: {settings.current_settings}")
            return jsonify({"status": "success", "settings": settings.current_settings})

        # POST 更新設定
        payload = await request.get_json() or {}
        
        # 驗證strategy參數
        if "strategy" in payload:
            valid_strategies = ["colbert", "rankgpt", "naive", "llm_rerank", "multi_query"]
            if payload["strategy"].lower() not in valid_strategies:
                return jsonify({"status": "error", "message": "無效的策略選項"}), 400
            # 轉換為小寫以與rag.py保持一致
            payload["strategy"] = payload["strategy"].lower()
        
        # 更新設定
        settings.current_settings.update(payload)
        logger.info(f"Updated settings: {settings.current_settings}")
        return jsonify({"status": "success", "settings": settings.current_settings})

    except Exception as e:
        logger.error(f"設定管理失敗: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@api_bp.route("/history", methods=["GET"])
async def get_history():
    try:
        from services.query import QueryService
        from services.db import DatabaseManager
        
        query_service = QueryService.get_instance()
        user_settings = getattr(settings, 'current_settings', {})
        logger.info(f"使用當前設定: {user_settings}")
        
        min_score = float(request.args.get("min_score", user_settings.get("min_score", 0)))
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 100))
        sort_field = request.args.get("sort_field", "updated_at")
        sort_order = -1 if request.args.get("sort_order", "desc").lower() == "desc" else 1
        
        additional_filters = {}
        if "vuln_filters" in user_settings:
            additional_filters["vuln_filters"] = user_settings.get("vuln_filters", {})
        if "asset_filters" in user_settings:
            additional_filters["asset_filters"] = user_settings.get("asset_filters", {})
            
        cve_id = request.args.get("cve_id", "")
        if cve_id:
            logger.info(f"處理特定CVE查詢: {cve_id}")
            if "vuln_filters" not in additional_filters:
                additional_filters["vuln_filters"] = {}
            additional_filters["vuln_filters"]["cve_id"] = cve_id
        
        cpe = request.args.get("cpe", "")
        if cpe:
            logger.info(f"處理特定CPE查詢: {cpe}")
            from services.db import DatabaseManager
            vuln_results = await DatabaseManager.get_instance().vuln_repo.search_by_cpe(cpe, min_score=min_score)
            if vuln_results:
                logger.info(f"直接從漏洞資料庫找到 {len(vuln_results)} 個符合CPE的漏洞")
                result = [{
                    "asset_info": {"CPE": cpe},
                    "vulnerabilities": vuln_results,
                    "弱點管理": {
                        "漏洞總數": len(vuln_results),
                        "未修補漏洞": sum(1 for v in vuln_results if not v.get("patched", False)),
                        "關鍵漏洞": sum(1 for v in vuln_results if v.get("base_score", 0) >= 9.0),
                        "高風險漏洞": sum(1 for v in vuln_results if 7.0 <= v.get("base_score", 0) < 9.0),
                        "中風險漏洞": sum(1 for v in vuln_results if 4.0 <= v.get("base_score", 0) < 7.0),
                        "低風險漏洞": sum(1 for v in vuln_results if v.get("base_score", 0) < 4.0),
                        "KEV漏洞": sum(1 for v in vuln_results if v.get("in_kev", False))
                    }
                }]
                pagination = {
                    "page": 1,
                    "limit": len(vuln_results),
                    "total": len(vuln_results),
                    "pages": 1,
                    "has_next": False,
                    "has_prev": False
                }
                return jsonify({
                    "status": "success",
                    "data": result,
                    "pagination": pagination
                })
            else:
                logger.info(f"未直接從漏洞資料庫找到符合CPE的漏洞，嘗試通過資產查詢")
                if "asset_filters" not in additional_filters:
                    additional_filters["asset_filters"] = {}
                additional_filters["asset_filters"]["cpe"] = cpe
        
        keyword = request.args.get("keyword", "")
        if keyword:
            logger.info(f"處理關鍵字查詢: {keyword}")
            if "vuln_filters" not in additional_filters:
                additional_filters["vuln_filters"] = {}
            if "$or" not in additional_filters["vuln_filters"]:
                additional_filters["vuln_filters"]["$or"] = []
            additional_filters["vuln_filters"]["$or"].extend([
                {"cve_id": {"$regex": keyword, "$options": "i"}},
                {"description": {"$regex": keyword, "$options": "i"}},
                {"product": {"$regex": keyword, "$options": "i"}}
            ])
        
        logger.info(f"查詢參數: min_score={min_score}, page={page}, limit={limit}, 附加過濾條件: {additional_filters}")
        data = await DataService.get_asset_history(additional_filters)
        if isinstance(data, dict):
            data = data.get("assets", [])
        
        data.sort(key=lambda x: x.get("弱點管理", {}).get("未修補漏洞", 0), reverse=(sort_order == -1))
        total_assets = len(data)
        start = (page - 1) * limit
        end = start + limit
        paginated_data = data[start:end] if data else []
        pagination = {
            "page": page,
            "limit": limit,
            "total": total_assets,
            "pages": (total_assets + limit - 1) // limit if limit > 0 else 1,
            "has_next": page * limit < total_assets,
            "has_prev": page > 1
        }
        
        logger.info(f"歷史資料獲取完成：總資產數量: {total_assets}，返回第 {page} 頁")
        return jsonify({
            "status": "success",
            "data": paginated_data,
            "pagination": pagination
        })
    except Exception as e:
        logger.error(f"歷史資料獲取失敗: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500


@api_bp.route("/upload_assets", methods=["POST"])
async def upload_assets():
    try:
        payload = await request.get_json()
        assets = payload.get('assets', [])
        if not assets:
            return jsonify({"status": "error", "message": "未提供資產資料"}), 400
        
        # 使用現有的 DatabaseManager 實例
        from services.db import DatabaseManager, AssetVulnerabilityService
        db_manager = DatabaseManager.get_instance()
        
        # 不要創建新的 AssetRepository，直接使用 db_manager 中的 asset_repo
        successful_uploads = 0
        base_vuln_query = {"base_score": {"$gte": 0}}
        
        for asset in assets:
            vulnerabilities = await AssetVulnerabilityService.query_vulnerabilities_for_asset(db_manager, asset, base_vuln_query)
            merged_asset = AssetVulnerabilityService.merge_asset_data(asset, vulnerabilities)
            if await db_manager.asset_repo.save_asset(merged_asset):
                successful_uploads += 1
                
        return jsonify({"status": "success", "message": f"成功上傳 {successful_uploads} 個資產"})
    except Exception as e:
        logger.error(f"上傳資產失敗: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
    

@api_bp.route("/generate_report", methods=["POST"])
async def generate_report():
    try:
        from services.query import QueryService
        query_service = QueryService.get_instance()
        payload = await request.get_json() or {}
        if "data" in payload and isinstance(payload["data"], dict):
            history_data = payload["data"]
        else:
            filters = payload.get('filters', {})
            history_data = await DataService.get_asset_history(filters)
        report = await query_service.generate_report(history_data)
        history_data["comprehensive_report"] = report
        return jsonify({
            "status": "success", 
            "report": report, 
            "data": json.loads(json.dumps(history_data, cls=CustomJSONEncoder))
        })
    except Exception as e:
        logger.error(f"報告生成失敗: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@api_bp.route("/update_vuln", methods=["POST"])
async def update_vulnerability():
    try:
        payload = await request.get_json() or {}
        cve_id = payload.get("cve_id")
        patched = payload.get("patched", False)
        if not cve_id:
            return jsonify({"status": "error", "message": "缺少CVE ID"}), 400
        from services.db import DatabaseManager
        db_manager = DatabaseManager.get_instance()
        vuln = await db_manager.vuln_repo.get_vulnerability(cve_id)
        if vuln:
            vuln["patched"] = patched
            vuln["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            success = await db_manager.vuln_repo.save_vulnerability(vuln)
            if success:
                return jsonify({"status": "success", "message": f"已將 {cve_id} 狀態更新為 {'已修補' if patched else '未修補'}"})
            else:
                return jsonify({"status": "error", "message": "更新漏洞狀態失敗"}), 500
        else:
            return jsonify({"status": "error", "message": f"找不到漏洞: {cve_id}"}), 404
    except Exception as e:
        logger.error(f"更新漏洞狀態失敗: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@api_bp.route("/recommendation", methods=["POST"])
async def recommendation():
    """生成漏洞修補建議並提取RAGAS評估分數"""
    try:
        from services.rag import generate_vulnerability_remediation
        
        # 準備漏洞數據
        payload = await request.get_json() or {}
        cve_id = payload.get("cve_id")
        vuln_data = payload.get("vuln_data")
        
        if not vuln_data and cve_id:
            try:
                from services.db import DatabaseManager
                vuln_data = await DatabaseManager.get_instance().vuln_repo.get_vulnerability(cve_id)
            except Exception as e:
                logger.warning(f"從資料庫獲取漏洞資料失敗: {e}")
                vuln_data = {"cve_id": cve_id, "description": f"Vulnerability {cve_id}"}
        
        if not cve_id and not vuln_data:
            return jsonify({"status": "error", "message": "缺少CVE ID或漏洞數據"}), 400
        
        # 獲取當前設定的模型
        config = load_config()
        user_settings = getattr(settings, 'current_settings', {})
        model = user_settings.get("model", config["MODEL"])
        
        # 設置API密鑰
        api_key = config["OPENAI_API_KEY"]
        
        logger.info(f"使用模型: {model}")
        
        # 生成建議
        start_time = datetime.datetime.now()
        result = await asyncio.wait_for(
            generate_vulnerability_remediation(
                vuln_data=vuln_data,
                api_key=api_key,  # 傳遞API密鑰
                model=model,      # 傳遞模型名稱
                temperature=0.0,  # 固定溫度
                max_tokens=4000   # 固定最大令牌數
            ), 
            timeout=200.0
        )
        execution_time = (datetime.datetime.now() - start_time).total_seconds()
        
        # 打印原始結果，幫助調試
        logger.info(f"RAG處理完成，原始結果包含以下鍵: {list(result.keys()) if isinstance(result, dict) else '非字典結果'}")
        
        # 提取評估分數 - 嘗試多種可能的數據結構
        try:
            # 1. 直接從result的頂層獲取
            faithfulness = float(result.get("faithfulness", 0.0))
            answer_relevancy = float(result.get("answer_relevancy", 0.0))
            context_utilization = float(result.get("context_utilization", 0.0))
            overall_score = float(result.get("overall_score", 0.0))
            
            # 2. 如果頂層為零，嘗試從evaluation字典獲取
            if faithfulness == 0.0 or answer_relevancy == 0.0:
                evaluation = result.get("evaluation", {})
                if evaluation:
                    logger.info(f"評估數據類型: {type(evaluation).__name__}")
                    if isinstance(evaluation, dict):
                        faithfulness = float(evaluation.get("faithfulness", faithfulness))
                        answer_relevancy = float(evaluation.get("answer_relevancy", answer_relevancy))
                        context_utilization = float(evaluation.get("context_utilization", context_utilization))
                    elif hasattr(evaluation, '__dict__'):
                        eval_dict = evaluation.__dict__
                        faithfulness = float(getattr(evaluation, "faithfulness", eval_dict.get("faithfulness", faithfulness)))
                        answer_relevancy = float(getattr(evaluation, "answer_relevancy", eval_dict.get("answer_relevancy", answer_relevancy)))
                        context_utilization = float(getattr(evaluation, "context_utilization", eval_dict.get("context_utilization", context_utilization)))
            
            # 3. 計算整體評分（如果未提供）
            if overall_score == 0.0:
                metrics = [v for v in [faithfulness, answer_relevancy, context_utilization] if v > 0]
                overall_score = sum(metrics) / len(metrics) if metrics else 0.0
                overall_score = round(overall_score, 4)
                
            # 確保結果是有效的浮點數
            if not isinstance(faithfulness, (int, float)) or faithfulness < 0 or faithfulness > 1:
                faithfulness = 0.0
            if not isinstance(answer_relevancy, (int, float)) or answer_relevancy < 0 or answer_relevancy > 1:
                answer_relevancy = 0.0
            if not isinstance(context_utilization, (int, float)) or context_utilization < 0 or context_utilization > 1:
                context_utilization = 0.0
            if not isinstance(overall_score, (int, float)) or overall_score < 0 or overall_score > 1:
                overall_score = 0.0
                
            logger.info(f"最終獲取的評估分數: 忠實度={faithfulness}, 回答相關性={answer_relevancy}, 上下文利用率={context_utilization}, 整體評分={overall_score}")
            
        except Exception as e:
            logger.exception(f"提取評估分數時發生錯誤: {e}")
            faithfulness = answer_relevancy = context_utilization = overall_score = 0.0
        
        # 準備響應數據
        response_data = {
            "status": "success", 
            "data": {
                "recommendation": result.get("recommendation", ""),
                "query": result.get("query", ""),
                "contexts": result.get("contexts", []),
                "rag_strategy": result.get("rag_strategy", "未知"),
                "model_used": model,
                "time_used": execution_time,
                "faithfulness": faithfulness,
                "answer_relevancy": answer_relevancy,
                "context_utilization": context_utilization,
                "overall_score": overall_score
            },
            "ragas_evaluation": {
                "faithfulness": faithfulness,
                "answer_relevancy": answer_relevancy,
                "context_utilization": context_utilization,
                "overall_score": overall_score,
                "rag_strategy": result.get("rag_strategy", "未知"),
                "model_used": model,
                "execution_time": execution_time
            },
            "contexts": result.get("contexts", [])
        }
        
        return jsonify(response_data)

    except asyncio.TimeoutError:
        logger.error("生成建議超時")
        return jsonify({"status": "error", "message": "生成建議超時，請稍後再試"}), 408
    except Exception as e:
        logger.exception(f"建議生成失敗: {e}")
        return jsonify({"status": "error", "message": f"建議生成失敗: {e}"}), 500
        
def create_app(config=None):
    app = Quart(__name__)
    app = cors(app)
    app.json_encoder = CustomJSONEncoder
    app.config.update(config or load_config())
    app.register_blueprint(api_bp)
    
    @app.before_request
    async def ignore_favicon():
        if request.path == '/favicon.ico':
            return jsonify({}), 204
            
    return app

class AppManager:
    _instance = None
    _app = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AppManager, cls).__new__(cls)
            cls._instance._app = create_app()
        return cls._instance
    
    @classmethod
    def get_app(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance._app

def get_app():
    return AppManager.get_app()

async def main():
    import hypercorn.asyncio, hypercorn.config
    config = hypercorn.config.Config()
    config.bind = ["0.0.0.0:5000"]
    config.workers = 1
    app = get_app()
    logger.info("應用啟動中...")
    await hypercorn.asyncio.serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())