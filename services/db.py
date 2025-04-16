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

import math
import os
import logging
import pymongo
import asyncio
from bson import ObjectId
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class DatabaseManager:
    _instance = None
    
    def __new__(cls, connection_string=None):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
        
    def __init__(self, connection_string=None, db_name=None):
        if self._initialized:
            return
        self.mongo_uri = connection_string or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        self.nvd_db = os.getenv("NVD_DB", "nvd_db")
        self.asset_db = os.getenv("ASSET_DB", "assets")
        
        self.collections = {
            "all": (self.nvd_db, "all"),
            "assets": (self.asset_db, "assets")
        }
        
        try:
            self.client = pymongo.MongoClient(self.mongo_uri, serverSelectionTimeoutMS=5000)
            self.db = {
                self.nvd_db: self.client[self.nvd_db],
                self.asset_db: self.client[self.asset_db]
            }
            self.client.admin.command('ping')
            self._ensure_indexes()
            self.vuln_repo = VulnerabilityRepository(self.client, self.collections)
            self.asset_repo = AssetRepository(self.client, self.collections)
            self._initialized = True
            logger.info(f"成功連接到 MongoDB: {self.nvd_db}和{self.asset_db}")
        except Exception as e:
            logger.error(f"資料庫連接錯誤: {str(e)}")
            raise

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ensure_indexes(self):
        nvd_indexes = {
            "vulnerabilities": [
                ("cve_id_index", [("cve_id", pymongo.ASCENDING)], True),
                ("published_index", [("published", pymongo.DESCENDING)], False),
                ("base_score_index", [("base_score", pymongo.DESCENDING)], False)
            ],
            "kev": [("kev_cve_id_index", [("cveID", pymongo.ASCENDING)], False)],
            "epss": [("epss_cve_id_index", [("cve_id", pymongo.ASCENDING)], False)],
            "cpe": [("cpe_index", [("cpe", pymongo.ASCENDING)], True)]
        }
        
        asset_indexes = {
            "assets": [
                ("asset_id_index", [("asset_id", pymongo.ASCENDING)], True),
                ("ip_index", [("asset_info.IP Address", pymongo.ASCENDING)], False),
                ("hostname_index", [("asset_info.Host Name", pymongo.ASCENDING)], False),
                ("cpe_os_index", [("cpe_info.cpe_os", pymongo.ASCENDING)], False),
                ("cpe_firmware_index", [("cpe_info.cpe_firmware", pymongo.ASCENDING)], False),
                ("cpe_software_index", [("cpe_info.cpe_software", pymongo.ASCENDING)], False)
            ]
        }
        
        # 處理索引
        for db_name, indexes_dict in [
            (self.nvd_db, nvd_indexes), 
            (self.asset_db, asset_indexes)
        ]:
            for collection_name, indexes in indexes_dict.items():
                self._create_indexes(db_name, collection_name, indexes)
                
        logger.info("索引檢查完成")

    def _create_indexes(self, db_name, collection_name, indexes):
        existing_indexes = self.db[db_name][collection_name].index_information()
        for idx_name, idx_fields, unique in indexes:
            if idx_name not in existing_indexes:
                self.db[db_name][collection_name].create_index(
                    idx_fields,
                    unique=unique,
                    background=True,
                    name=idx_name,
                    sparse=True
                )
                logger.info(f"創建索引: {idx_name} 在 {db_name}.{collection_name}")

    def _sanitize_document(self, doc):
        if not doc:
            return {}
            
        def convert_value(value):
            if isinstance(value, ObjectId):
                return str(value)
            elif isinstance(value, datetime):
                return value.isoformat()
            elif isinstance(value, dict):
                return {k: convert_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [convert_value(item) for item in value]
            return value
            
        return {k: convert_value(v) for k, v in doc.items()}

    def close(self):
        if hasattr(self, 'client'):
            self.client.close()

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): 
        self.close()
        return not exc_type

class BaseRepository:
    def __init__(self, client, collections_map):
        self.client = client
        self.collections_map = collections_map
    
    def _get_collection_info(self, key):
        return self.collections_map.get(key, (None, key))
        
    def _get_collection(self, key):
        db_name, coll_name = self._get_collection_info(key)
        if db_name is None:
            return None
        return self.client[db_name][coll_name]

class AssetRepository(BaseRepository):
    async def save_asset(self, asset: Dict[str, Any]) -> bool:
        try:
            asset_id = asset.get("asset_id")
            if not asset_id:
                logger.error("缺少 asset_id")
                return False
            
            asset["updated_at"] = datetime.now(timezone.utc)
            collection = self._get_collection("assets")
            if collection is None:
                logger.error("找不到資產集合")
                return False
                
            result = collection.update_one(
                {"asset_id": asset_id},
                {"$set": asset},
                upsert=True
            )
            return result.acknowledged
        except Exception as e:
            logger.error(f"儲存資產資訊失敗: {str(e)}")
            return False
    
    async def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        try:
            collection = self._get_collection("assets")
            if collection is None:
                return None
                
            result = collection.find_one({"asset_id": asset_id})
            return DatabaseManager.get_instance()._sanitize_document(result) if result else None
        except Exception as e:
            logger.error(f"獲取資產資訊失敗: {str(e)}")
            return None
    
    async def get_assets(self, query=None) -> List[Dict[str, Any]]:
        try:
            collection = self._get_collection("assets")
            if collection is None:
                return []
                
            cursor = collection.find(query or {})
            results = list(cursor)
            return [DatabaseManager.get_instance()._sanitize_document(doc) for doc in results]
        except Exception as e:
            logger.error(f"獲取資產列表失敗: {str(e)}")
            return []

class VulnerabilityRepository(BaseRepository):
    async def get_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        try:
            collection = self._get_collection("vulnerabilities")
            if collection is None:
                return None
                
            result = collection.find_one({"cve_id": cve_id})
            if not result and cve_id:
                result = collection.find_one(
                    {"cve_id": {"$regex": f"^{cve_id}$", "$options": "i"}}
                )
            return DatabaseManager.get_instance()._sanitize_document(result) if result else None
        except Exception as e:
            logger.error(f"獲取漏洞資訊失敗: {str(e)}")
            return None
            
    async def save_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        try:
            cve_id = vulnerability.get("cve_id")
            if not cve_id:
                logger.error("缺少 CVE ID")
                return False
                
            vulnerability["updated_at"] = datetime.now(timezone.utc)
            collection = self._get_collection("vulnerabilities")
            if collection is None:
                return False
                
            result = collection.update_one(
                {"cve_id": cve_id},
                {"$set": vulnerability},
                upsert=True
            )
            return result.acknowledged
        except Exception as e:
            logger.error(f"保存漏洞資訊失敗: {str(e)}")
            return False
    
    async def search_vulnerabilities(self, query, sort=None, limit=100, skip=0) -> List[Dict]:
        try:
            collection = self._get_collection("vulnerabilities")
            if collection is None:
                return []
                
            logger.info(f"執行漏洞搜尋: {query}")
            sort = sort or [("base_score", -1)]
            cursor = collection.find(query).sort(sort).skip(skip).limit(limit)
            results = list(cursor)
            logger.info(f"查詢結果: 找到 {len(results)} 個漏洞")
            return [DatabaseManager.get_instance()._sanitize_document(doc) for doc in results]
        except Exception as e:
            logger.error(f"搜尋漏洞失敗: {str(e)}")
            return []
    
    async def count(self, query=None) -> int:
        try:
            collection = self._get_collection("vulnerabilities")
            if collection is None:
                return 0
            return collection.count_documents(query or {})
        except Exception as e:
            logger.error(f"計算漏洞數量失敗: {str(e)}")
            return 0
            
    async def search_by_cpe(self, cpe: str, min_score: float = 0.0) -> List[Dict]:
        try:
            collection = self._get_collection("all")
            if collection is None:
                return []
            
            # 創建基本查詢 - 首先嘗試精確匹配
            query = {"affected_systems.cpe23Uri": cpe}
            
            # 如果有最低分數要求，添加到查詢中
            if min_score > 0:
                query["base_score"] = {"$gte": min_score}

            
            # 執行查詢
            cursor = collection.find(query).sort([("base_score", -1)]).limit(20)
            results = list(cursor)
            logger.info(f"CPE查詢結果: 找到 {len(results)} 個相關漏洞")
            return [DatabaseManager.get_instance()._sanitize_document(doc) for doc in results]
        except Exception as e:
            logger.error(f"依據 CPE 搜尋漏洞失敗: {str(e)}")
            return []
        
class AssetVulnerabilityService:
    @staticmethod
    def extract_cpe_fields(asset: Dict[str, Any]) -> Dict[str, List[str]]:
        fields = {"cpe_os": [], "cpe_firmware": [], "cpe_software": []}
        
        # 從cpe_info取值
        cpe_info = asset.get("cpe_info", {}) or {}
        for key in fields.keys():
            if key in cpe_info and cpe_info[key]:
                if isinstance(cpe_info[key], list):
                    fields[key].extend([v for v in cpe_info[key] if v])
                else:
                    fields[key].append(cpe_info[key])
        
        # 直接從資產取值
        for key in fields.keys():
            if key in asset and asset[key]:
                if isinstance(asset[key], list):
                    fields[key].extend([v for v in asset[key] if v])
                else:
                    fields[key].append(asset[key])
        
        # 去除重複並將空值移除
        for key in fields:
            fields[key] = list(set([v for v in fields[key] if v]))
            
        logger.info(f"從資產提取的CPE欄位: {fields}")
        return fields

    @staticmethod
    async def query_vulnerabilities_for_asset(
        db_manager: DatabaseManager, 
        asset: Dict[str, Any],
        base_vuln_query: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        vulnerabilities = []
        asset_id = asset.get("asset_id", "unknown")
        cpe_fields = AssetVulnerabilityService.extract_cpe_fields(asset)
        
        logger.info(f"開始為資產 {asset_id} 查詢漏洞，CPE欄位數量: {sum(len(v) for v in cpe_fields.values())}")
        
        # 從各個CPE字段查詢漏洞
        for field, cpe_list in cpe_fields.items():
            for cpe in cpe_list:
                if not cpe or len(cpe) < 4:  # 跳過空值或太短的CPE
                    continue
                
                # 直接使用search_by_cpe方法
                vuln_results = await db_manager.vuln_repo.search_by_cpe(cpe)
                
                if vuln_results:
                    logger.info(f"CPE {cpe} 找到 {len(vuln_results)} 個漏洞")
                    for vuln in vuln_results:
                        # 標記來源和資產資訊
                        vuln["source"] = field
                        vuln["host_name"] = asset.get("asset_info", {}).get("Host Name", "N/A")
                        vuln["ip_address"] = asset.get("asset_info", {}).get("IP Address", "N/A")
                        vuln["asset_info"] = asset.get("asset_info", {})
                        vulnerabilities.append(vuln)
                else:
                    logger.info(f"CPE {cpe} 未找到漏洞")
                    
        # 去除重複的漏洞 (通過cve_id)
        unique_vulns = {}
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            if cve_id and cve_id not in unique_vulns:
                unique_vulns[cve_id] = vuln
                
        result = list(unique_vulns.values())
        logger.info(f"資產 {asset_id} 最終找到 {len(result)} 個漏洞")
        return result

    @staticmethod
    def merge_asset_data(asset: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        asset_info = asset.get("asset_info", {}) or {}
        
        # 確保資產有ID
        asset_id = asset.get("asset_id")
        if not asset_id:
            host_name = asset_info.get("Host Name", "")
            ip_address = asset_info.get("IP Address", "")
            
            if host_name and ip_address:
                asset_id = f"{host_name}_{ip_address}"
            elif host_name:
                asset_id = f"host_{host_name}"
            elif ip_address:
                asset_id = f"ip_{ip_address}"
            else:
                import uuid
                asset_id = f"asset_{str(uuid.uuid4())}"
            
            logger.info(f"為資產生成 asset_id: {asset_id}")
        
        return {
            "asset_id": asset_id,
            "asset_info": asset_info,
            "vulnerabilities": vulnerabilities,
            "raw_vulnerabilities": vulnerabilities,
            "弱點管理": {
                "漏洞總數": len(vulnerabilities),
                "未修補漏洞": sum(1 for v in vulnerabilities if not v.get("patched", False)),
                "關鍵漏洞": sum(1 for v in vulnerabilities if v.get("base_score", 0) >= 9.0),
                "高風險漏洞": sum(1 for v in vulnerabilities if 7.0 <= v.get("base_score", 0) < 9.0),
                "中風險漏洞": sum(1 for v in vulnerabilities if 4.0 <= v.get("base_score", 0) < 7.0),
                "低風險漏洞": sum(1 for v in vulnerabilities if v.get("base_score", 0) < 4.0),
                "KEV漏洞": sum(1 for v in vulnerabilities if v.get("in_kev", False))
            }
        }

    @staticmethod
    async def get_assets_with_vulnerabilities(
        min_score: float = 0.0,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        db_manager = DatabaseManager.get_instance()
        asset_query = additional_filters.get("asset_filters", {}) if additional_filters else {}
        assets = await db_manager.asset_repo.get_assets(asset_query)
        logger.info(f"根據查詢條件找到 {len(assets)} 個資產")
        
        base_vuln_query = {"base_score": {"$gte": min_score}}
        if additional_filters and "vuln_filters" in additional_filters:
            base_vuln_query.update(additional_filters["vuln_filters"])
        
        merged_assets = []
        for asset in assets:
            vulnerabilities = await AssetVulnerabilityService.query_vulnerabilities_for_asset(
                db_manager, asset, base_vuln_query
            )
            
            merged = AssetVulnerabilityService.merge_asset_data(asset, vulnerabilities)
            merged_assets.append(merged)
        
        merged_assets.sort(key=lambda x: x["弱點管理"].get("未修補漏洞", 0), reverse=True)
        
        return merged_assets

def get_instance() -> DatabaseManager:
    return DatabaseManager.get_instance()

async def get_assets_with_vulnerabilities(min_score=0.0, additional_filters=None):
    return await AssetVulnerabilityService.get_assets_with_vulnerabilities(
        min_score=min_score, additional_filters=additional_filters
    )