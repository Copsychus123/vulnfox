import os, asyncio, logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pymongo import MongoClient, IndexModel, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError, ConnectionFailure
from bson.objectid import ObjectId
from dotenv import load_dotenv

# 載入環境變數
load_dotenv()
logger = logging.getLogger(__name__)

class DatabaseManager:
    """MongoDB 資料庫管理"""

    def __init__(self, connection_string: Optional[str] = None, db_name: Optional[str] = None):
        """初始化資料庫管理器"""
        try:
            # 設定連接參數
            self.mongo_uri = connection_string or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
            self.db_name = db_name or os.getenv("DATABASE_NAME", "nvd_db")
            
            # 設定集合名稱
            self.collections = {
                "vulnerabilities": "vulnerabilities",  # 漏洞資訊
                "assets": "assets",                    # 資產資訊
                "incidents": "incidents",              # 事件紀錄
                "patches": "patches",                  # 修補紀錄
                "reports": "reports"                   # 報告資料
            }
            
            # 初始化連接
            self.client = MongoClient(
                self.mongo_uri,
                serverSelectionTimeoutMS=5000,
                maxPoolSize=50,
                minPoolSize=10,
                retryWrites=True
            )
            
            # 獲取資料庫實例
            self.db = self.client[self.db_name]
            
            # 建立索引
            self._ensure_indexes()
            
            logger.info(f"已連接到資料庫: {self.db_name}")
            
        except ConnectionFailure as e:
            logger.error(f"資料庫連接失敗: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"初始化資料庫管理器失敗: {str(e)}")
            raise

    def _ensure_indexes(self) -> None:
        """確保必要的索引存在"""
        try:
            # 漏洞集合索引
            self.db[self.collections["vulnerabilities"]].create_indexes([
                IndexModel([("cve_id", ASCENDING)], unique=True, name="cve_id_index"),
                IndexModel([("cvss_score", DESCENDING)], name="cvss_index"),
                IndexModel([("published_date", DESCENDING)], name="published_index"),
                IndexModel([("description", "text"), ("cve_id", "text")], name="text_index")
            ])
            
            # 資產集合索引
            self.db[self.collections["assets"]].create_indexes([
                IndexModel([("asset_id", ASCENDING)], unique=True, name="asset_id_index"),
                IndexModel([("ip_address", ASCENDING)], name="ip_index"),
                IndexModel([("os_type", ASCENDING)], name="os_index")
            ])
            
            # 事件集合索引
            self.db[self.collections["incidents"]].create_indexes([
                IndexModel([("incident_id", ASCENDING)], unique=True, name="incident_id_index"),
                IndexModel([("status", ASCENDING)], name="status_index"),
                IndexModel([("priority", DESCENDING)], name="priority_index")
            ])
            
            logger.info("已建立所有必要索引")
            
        except PyMongoError as e:
            logger.error(f"建立索引失敗: {str(e)}")
            raise

    def close(self) -> None:
        """關閉資料庫連接"""
        try:
            if hasattr(self, "client"):
                self.client.close()
                logger.info("資料庫連接已關閉")
        except Exception as e:
            logger.error(f"關閉資料庫連接失敗: {str(e)}")

    def _sanitize_document(self, document: Dict[str, Any]) -> Dict[str, Any]:
        """清理文檔數據"""
        try:
            # 處理 ObjectId
            if "_id" in document and isinstance(document["_id"], ObjectId):
                document["_id"] = str(document["_id"])
            
            # 處理日期時間
            for key, value in document.items():
                if isinstance(value, datetime):
                    document[key] = value.isoformat()
                elif isinstance(value, dict):
                    document[key] = self._sanitize_document(value)
                elif isinstance(value, list):
                    document[key] = [
                        self._sanitize_document(item) if isinstance(item, dict) else item
                        for item in value
                    ]
            
            return document
            
        except Exception as e:
            logger.error(f"清理文檔數據失敗: {str(e)}")
            return document

    # ---------- 漏洞管理 ----------
    async def save_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """儲存漏洞資訊"""
        try:
            cve_id = vulnerability.get("cve_id")
            if not cve_id:
                logger.error("缺少 CVE ID")
                return False
            
            # 更新時間戳
            vulnerability["updated_at"] = datetime.now(timezone.utc)
            
            # 使用 upsert 更新或插入
            result = self.db[self.collections["vulnerabilities"]].update_one(
                {"cve_id": cve_id},
                {"$set": vulnerability},
                upsert=True
            )
            
            return result.acknowledged
            
        except PyMongoError as e:
            logger.error(f"儲存漏洞資訊失敗: {str(e)}")
            return False

    async def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """獲取漏洞資訊"""
        try:
            result = self.db[self.collections["vulnerabilities"]].find_one(
                {"cve_id": cve_id}
            )
            
            if result:
                return self._sanitize_document(result)
            return None
            
        except PyMongoError as e:
            logger.error(f"獲取漏洞資訊失敗: {str(e)}")
            return None

    async def search_vulnerabilities(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """搜尋漏洞"""
        try:
            cursor = self.db[self.collections["vulnerabilities"]].find(query)
            # 將同步的 Cursor 轉換為列表
            docs = await asyncio.to_thread(list, cursor)
            results = [self._sanitize_document(doc) for doc in docs]
            return results
        except PyMongoError as e:
            logger.error(f"搜尋漏洞失敗: {str(e)}")
            return []

    async def delete_vulnerability(self, cve_id: str) -> bool:
        """刪除漏洞資訊"""
        try:
            result = self.db[self.collections["vulnerabilities"]].delete_one(
                {"cve_id": cve_id}
            )
            
            return result.deleted_count > 0
            
        except PyMongoError as e:
            logger.error(f"刪除漏洞資訊失敗: {str(e)}")
            return False

    # 新增：同步方式獲取多筆漏洞資訊
    def get_vulnerabilities(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """同步方式獲取多筆漏洞資訊"""
        try:
            cursor = self.db[self.collections["vulnerabilities"]].find(query)
            results = [self._sanitize_document(doc) for doc in cursor]
            return results
        except Exception as e:
            logger.error(f"獲取漏洞資訊失敗: {str(e)}")
            return []

    # ---------- 資產管理 ----------
    async def save_asset(self, asset: Dict[str, Any]) -> bool:
        """儲存資產資訊"""
        try:
            asset_id = asset.get("asset_id")
            if not asset_id:
                logger.error("缺少資產 ID")
                return False
            
            # 更新時間戳
            asset["updated_at"] = datetime.now(timezone.utc)
            
            # 使用 upsert 更新或插入
            result = self.db[self.collections["assets"]].update_one(
                {"asset_id": asset_id},
                {"$set": asset},
                upsert=True
            )
            
            return result.acknowledged
            
        except PyMongoError as e:
            logger.error(f"儲存資產資訊失敗: {str(e)}")
            return False

    async def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """獲取資產資訊"""
        try:
            result = self.db[self.collections["assets"]].find_one(
                {"asset_id": asset_id}
            )
            
            if result:
                return self._sanitize_document(result)
            return None
            
        except PyMongoError as e:
            logger.error(f"獲取資產資訊失敗: {str(e)}")
            return None

    async def search_assets(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """搜尋資產"""
        try:
            cursor = self.db[self.collections["assets"]].find(query)
            
            results = []
            async for doc in cursor:
                results.append(self._sanitize_document(doc))
            
            return results
            
        except PyMongoError as e:
            logger.error(f"搜尋資產失敗: {str(e)}")
            return []

    async def delete_asset(self, asset_id: str) -> bool:
        """刪除資產資訊"""
        try:
            result = self.db[self.collections["assets"]].delete_one(
                {"asset_id": asset_id}
            )
            
            return result.deleted_count > 0
            
        except PyMongoError as e:
            logger.error(f"刪除資產資訊失敗: {str(e)}")
            return False

    # ---------- 事件管理 ----------
    async def save_incident(self, incident: Dict[str, Any]) -> bool:
        """儲存事件資訊"""
        try:
            incident_id = incident.get("incident_id")
            if not incident_id:
                logger.error("缺少事件 ID")
                return False
            
            # 更新時間戳
            incident["updated_at"] = datetime.now(timezone.utc)
            
            # 使用 upsert 更新或插入
            result = self.db[self.collections["incidents"]].update_one(
                {"incident_id": incident_id},
                {"$set": incident},
                upsert=True
            )
            
            return result.acknowledged
            
        except PyMongoError as e:
            logger.error(f"儲存事件資訊失敗: {str(e)}")
            return False

    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """獲取事件資訊"""
        try:
            result = self.db[self.collections["incidents"]].find_one(
                {"incident_id": incident_id}
            )
            
            if result:
                return self._sanitize_document(result)
            return None
            
        except PyMongoError as e:
            logger.error(f"獲取事件資訊失敗: {str(e)}")
            return None

    async def search_incidents(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """搜尋事件"""
        try:
            cursor = self.db[self.collections["incidents"]].find(query)
            
            results = []
            async for doc in cursor:
                results.append(self._sanitize_document(doc))
            
            return results
            
        except PyMongoError as e:
            logger.error(f"搜尋事件失敗: {str(e)}")
            return []

    async def update_incident_status(self, incident_id: str, status: str, details: Optional[str] = None) -> bool:
        """更新事件狀態"""
        try:
            update = {
                "$set": {
                    "status": status,
                    "updated_at": datetime.now(timezone.utc)
                },
                "$push": {
                    "timeline": {
                        "status": status,
                        "details": details,
                        "timestamp": datetime.now(timezone.utc)
                    }
                }
            }
            
            result = self.db[self.collections["incidents"]].update_one(
                {"incident_id": incident_id},
                update
            )
            
            return result.modified_count > 0
            
        except PyMongoError as e:
            logger.error(f"更新事件狀態失敗: {str(e)}")
            return False

    # ---------- 報告管理 ----------
    async def save_report(self, report: Dict[str, Any]) -> bool:
        """儲存報告"""
        try:
            report_id = report.get("report_id")
            if not report_id:
                logger.error("缺少報告 ID")
                return False
            
            # 更新時間戳
            report["updated_at"] = datetime.now(timezone.utc)
            
            # 使用 upsert 更新或插入
            result = self.db[self.collections["reports"]].update_one(
                {"report_id": report_id},
                {"$set": report},
                upsert=True
            )
            
            return result.acknowledged
            
        except PyMongoError as e:
            logger.error(f"儲存報告失敗: {str(e)}")
            return False

    async def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """獲取報告"""
        try:
            result = self.db[self.collections["reports"]].find_one(
                {"report_id": report_id}
            )
            
            if result:
                return self._sanitize_document(result)
            return None
            
        except PyMongoError as e:
            logger.error(f"獲取報告失敗: {str(e)}")
            return None

    async def search_reports(self, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """搜尋報告"""
        try:
            cursor = self.db[self.collections["reports"]].find(query)
            
            results = []
            async for doc in cursor:
                results.append(self._sanitize_document(doc))
            
            return results
            
        except PyMongoError as e:
            logger.error(f"搜尋報告失敗: {str(e)}")
            return []

    # ---------- 統計分析 ----------
    async def get_vulnerability_stats(self) -> Dict[str, Any]:
        """獲取漏洞統計資訊"""
        try:
            # 取得總漏洞數
            total_count = await self.db[self.collections["vulnerabilities"]].count_documents({})
            
            # 依據 CVSS 分數分類
            severity_stats = await self.db[self.collections["vulnerabilities"]].aggregate([
                {
                    "$group": {
                        "_id": {
                            "$switch": {
                                "branches": [
                                    {"case": {"$gte": ["$cvss_score", 9.0]}, "then": "Critical"},
                                    {"case": {"$gte": ["$cvss_score", 7.0]}, "then": "High"},
                                    {"case": {"$gte": ["$cvss_score", 4.0]}, "then": "Medium"},
                                    {"case": {"$gte": ["$cvss_score", 0.1]}, "then": "Low"}
                                ],
                                "default": "None"
                            }
                        },
                        "count": {"$sum": 1}
                    }
                }
            ]).to_list(None)
            
            # 時間趨勢分析
            time_trend = await self.db[self.collections["vulnerabilities"]].aggregate([
                {
                    "$group": {
                        "_id": {
                            "$dateToString": {
                                "format": "%Y-%m",
                                "date": "$published_date"
                            }
                        },
                        "count": {"$sum": 1}
                    }
                },
                {"$sort": {"_id": 1}}
            ]).to_list(None)
            
            return {
                "total_vulnerabilities": total_count,
                "severity_distribution": {
                    item["_id"]: item["count"] 
                    for item in severity_stats
                },
                "time_trend": {
                    item["_id"]: item["count"]
                    for item in time_trend
                },
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except PyMongoError as e:
            logger.error(f"獲取漏洞統計失敗: {str(e)}")
            return {}

    async def get_incident_stats(self) -> Dict[str, Any]:
        """獲取事件統計資訊"""
        try:
            # 取得總事件數
            total_count = await self.db[self.collections["incidents"]].count_documents({})
            
            # 依據狀態分類
            status_stats = await self.db[self.collections["incidents"]].aggregate([
                {
                    "$group": {
                        "_id": "$status",
                        "count": {"$sum": 1}
                    }
                }
            ]).to_list(None)
            
            # 依據優先級分類
            priority_stats = await self.db[self.collections["incidents"]].aggregate([
                {
                    "$group": {
                        "_id": "$priority",
                        "count": {"$sum": 1}
                    }
                }
            ]).to_list(None)
            
            # 處理時間分析
            resolution_times = await self.db[self.collections["incidents"]].aggregate([
                {
                    "$match": {
                        "status": "resolved",
                        "created_at": {"$exists": True},
                        "resolved_at": {"$exists": True}
                    }
                },
                {
                    "$project": {
                        "resolution_time": {
                            "$divide": [
                                {"$subtract": ["$resolved_at", "$created_at"]},
                                3600000
                            ]
                        }
                    }
                },
                {
                    "$group": {
                        "_id": None,
                        "avg_resolution_time": {"$avg": "$resolution_time"},
                        "min_resolution_time": {"$min": "$resolution_time"},
                        "max_resolution_time": {"$max": "$resolution_time"}
                    }
                }
            ]).to_list(None)
            
            return {
                "total_incidents": total_count,
                "status_distribution": {
                    item["_id"]: item["count"]
                    for item in status_stats
                },
                "priority_distribution": {
                    item["_id"]: item["count"]
                    for item in priority_stats
                },
                "resolution_times": resolution_times[0] if resolution_times else {},
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except PyMongoError as e:
            logger.error(f"獲取事件統計失敗: {str(e)}")
            return {}

    async def get_asset_vulnerability_stats(self, asset_id: Optional[str] = None) -> Dict[str, Any]:
        """獲取資產漏洞統計"""
        try:
            # 構建查詢條件
            match_stage = {}
            if asset_id:
                match_stage["asset_id"] = asset_id
            
            # 執行聚合查詢
            pipeline = [
                {"$match": match_stage} if match_stage else {"$match": {}},
                {
                    "$lookup": {
                        "from": self.collections["vulnerabilities"],
                        "localField": "vulnerabilities",
                        "foreignField": "cve_id",
                        "as": "vuln_details"
                    }
                },
                {
                    "$project": {
                        "asset_id": 1,
                        "hostname": 1,
                        "ip_address": 1,
                        "os_type": 1,
                        "vulnerability_count": {"$size": "$vuln_details"},
                        "critical_count": {
                            "$size": {
                                "$filter": {
                                    "input": "$vuln_details",
                                    "as": "vuln",
                                    "cond": {"$gte": ["$vuln.cvss_score", 9.0]}
                                }
                            }
                        },
                        "high_count": {
                            "$size": {
                                "$filter": {
                                    "input": "$vuln_details",
                                    "as": "vuln",
                                    "cond": {
                                        "$and": [
                                            {"$gte": ["$vuln.cvss_score", 7.0]},
                                            {"$lt": ["$vuln.cvss_score", 9.0]}
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            ]
            
            results = await self.db[self.collections["assets"]].aggregate(pipeline).to_list(None)
            
            return {
                "asset_vulnerability_stats": [
                    self._sanitize_document(result)
                    for result in results
                ],
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except PyMongoError as e:
            logger.error(f"獲取資產漏洞統計失敗: {str(e)}")
            return {}

# 單例模式
_instance = None

def get_instance() -> DatabaseManager:
    """取得資料庫管理器單例"""
    global _instance
    if _instance is None:
        _instance = DatabaseManager()
    return _instance