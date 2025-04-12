import datetime
import json, asyncio, logging
from bson import ObjectId
from quart import Quart, request, jsonify
from quart_cors import cors

from services.query import (
    get_asset_vulnerability_history,
    generate_vulnerability_report,
    update_query_settings,
    DEFAULT_SETTINGS
)
from core.model import DataModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)

app = Quart(__name__)
app = cors(app)
app.json_encoder = CustomJSONEncoder
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

@app.before_request
async def before_request():
    if request.path == '/favicon.ico':
        return jsonify({}), 204

# 抽象化資料抓取函式，根據參數決定是否僅回傳漏洞資料
async def _fetch_history_data(filters: dict = None, vuln_only: bool = False) -> dict:
    if filters is None:
        filters = {}
    logger.info(f"Fetching history data with filters: {filters}")
    history_data = await get_asset_vulnerability_history(settings=filters)
    if not history_data:
        return {}
    
    if vuln_only:
        all_vulnerabilities = []
        for asset in history_data.get("assets", []):
            vulns = asset.get("raw_vulnerabilities", [])
            # 過濾出未修補的漏洞
            unpatched = [v for v in vulns if not v.get("patched", False)]
            all_vulnerabilities.extend(unpatched)
        return {"vulnerabilities": all_vulnerabilities}
    else:
        # 移除不必要的報告欄位
        history_data.pop("comprehensive_report", None)
        return history_data

# /history 路由，回傳完整歷史資料
@app.route("/history", methods=["GET"])
async def get_history():
    try:
        filters_str = request.args.get('filters', '{}')
        try:
            filters = json.loads(filters_str)
        except json.JSONDecodeError:
            filters = {}
        data = await _fetch_history_data(filters=filters, vuln_only=False)
        total_assets = len(data.get("assets", []))
        total_raw_vulns = data.get("total_raw_vuln_count", 0)
        total_filtered_vulns = data.get("total_vuln_count", 0)
        logger.info(f"History fetched: assets: {total_assets}, raw vulns: {total_raw_vulns}, filtered vulns: {total_filtered_vulns}")
        sanitized_data = json.loads(json.dumps(data, cls=CustomJSONEncoder))
        return jsonify({"status": "success", "data": sanitized_data})
    except Exception as e:
        logger.error(f"Failed to fetch history: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

# /vuln 路由，僅回傳漏洞資料
@app.route("/vuln", methods=["GET"])
async def vulnerability_management():
    try:
        data = await _fetch_history_data(filters={}, vuln_only=True)
        sanitized_data = json.loads(json.dumps(data, cls=CustomJSONEncoder))
        return jsonify({"status": "success", "data": sanitized_data})
    except Exception as e:
        logger.error(f"Failed to fetch vulnerability data: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/generate_report", methods=["POST"])
async def generate_report():
    try:
        data = await request.get_json() or {}
        if "data" in data and isinstance(data["data"], dict):
            history_data = data["data"]
            logger.info("Using provided history data for report generation")
        else:
            filters = data.get('filters', {})
            logger.info(f"No history data provided, fetching with filters: {filters}")
            history_data = await get_asset_vulnerability_history(settings=filters)
        logger.info("Generating vulnerability report...")
        report = await generate_vulnerability_report(history_data)
        history_data["comprehensive_report"] = report
        logger.info("Report generation complete")
        sanitized_data = json.loads(json.dumps(history_data, cls=CustomJSONEncoder))
        return jsonify({"status": "success", "report": report, "data": sanitized_data})
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/settings", methods=["GET", "POST"])
async def manage_settings():
    try:
        if request.method == "GET":
            return jsonify({"status": "success", "settings": DEFAULT_SETTINGS})
        elif request.method == "POST":
            data = await request.get_json()
            logger.info(f"Updating settings: {json.dumps(data)}")
            updated_settings = await update_query_settings(data)
            return jsonify({"status": "success", "settings": updated_settings})
    except Exception as e:
        logger.error(f"Settings management failed: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/recommendation", methods=["POST"])
async def recommendation():
    try:
        data = await request.get_json() or {}
        cve_id = data.get("cve_id")
        if not cve_id:
            return jsonify({"status": "error", "message": "Missing CVE ID"}), 400
        try:
            from services.recom import RecommendationService
            from services.knowledge import KnowledgeBase
            from services.db import get_instance
            kb = KnowledgeBase()
            db = get_instance()
            service = RecommendationService(kb, db)
            vuln_data = await db.get_vulnerability(cve_id)
            if not vuln_data:
                return jsonify({"status": "error", "message": "Vulnerability not found"}), 404
            recommendation_result = await service.generate_recommendation_with_ragas(vuln_data)
            return jsonify({"status": "success", "data": recommendation_result})
        except ImportError:
            from core.model import DataModel
            recommendation_result = DataModel.generate_recommendation_with_ragas(cve_id)
            return jsonify({"status": "success", "data": recommendation_result})
    except Exception as e:
        logger.error(f"Recommendation generation failed: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

async def main():
    import hypercorn.asyncio, hypercorn.config
    config = hypercorn.config.Config()
    config.bind = ["0.0.0.0:5000"]
    config.workers = 1
    await hypercorn.asyncio.serve(app, config)

if __name__ == "__main__":
    asyncio.run(main())
