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


import os
import json
import logging
import asyncio
import torch
import chromadb
import aiofiles
import numpy as np
from enum import Enum
from pathlib import Path
from bson import ObjectId
from dotenv import load_dotenv
from pymongo import MongoClient
from functools import lru_cache
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from transformers import AutoTokenizer, AutoModel
from concurrent.futures import ThreadPoolExecutor

load_dotenv()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class InitMode(Enum):
    INITIALIZE = "initialize"
    LAZY = "lazy"
    INCREMENTAL = "incremental"

class ResourceConfig:
    BATCH_SIZE = 100
    MAX_MEMORY_PERCENT = 75.0
    SIMILARITY_THRESHOLD = 0.7
    RETENTION_DAYS = 365
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0
    LLM_TIMEOUT = 30
    CACHE_SIZE = 10000
    COLLECTIONS = {"vulnerabilities": {"collection": "vulnerabilities"}, "kev": {"collection": "kev"}, "epss": {"collection": "epss"}, "rss_clear": {"collection": "rss_clear"}, "cpe": {"collection": "cpe"}}

class LRUCache:
    def __init__(self, maxsize: int = 1000):
        self.cache = {}
        self.maxsize = maxsize
        self.order = []
    def __getitem__(self, key):
        if key in self.cache:
            self.order.remove(key)
            self.order.append(key)
            return self.cache[key]
        raise KeyError(key)
    def __setitem__(self, key, value):
        if len(self.cache) >= self.maxsize:
            oldest = self.order.pop(0)
            del self.cache[oldest]
        self.cache[key] = value
        self.order.append(key)
    def __contains__(self, key):
        return key in self.cache

class VectorStore:
    def __init__(self, data_path: str = r"C:\Users\OTTO\Desktop\TANET 2024\Proposal\src\data\data_lake\chroma_db", init_mode: Optional[str] = None, checkpoint_file: str = "checkpoint.json"):
        try:
            self.data_path = Path(data_path)
            self.checkpoint_file = self.data_path / checkpoint_file
            os.makedirs(self.data_path, exist_ok=True)
            os.makedirs(self.data_path / "model_cache", exist_ok=True)
            if init_mode is None:
                init_mode = InitMode.INCREMENTAL.value
            self.init_mode = init_mode
            logger.info(f"向量存儲初始化模式：{init_mode}")
            try:
                self.chroma_client = chromadb.PersistentClient(path=str(self.data_path))
                logger.info("ChromaDB 客戶端初始化成功")
            except Exception as e:
                logger.error(f"ChromaDB 客戶端初始化失敗：{e}")
                self.chroma_client = None
                raise
            existing_collections = self.chroma_client.list_collections()
            logger.info(f"發現現有集合: {existing_collections}")
            self.collections = {}
            self.collection_naming = {}
            for collection_name in existing_collections:
                try:
                    self.collections[collection_name] = self.chroma_client.get_collection(name=collection_name)
                    self.collection_naming[collection_name] = collection_name
                    logger.info(f"載入現有集合: {collection_name}")
                except Exception as e:
                    logger.error(f"載入集合 {collection_name} 失敗: {e}")
            self.mongo_client = MongoClient(os.getenv('MONGODB_URI'))
            self.db = self.mongo_client[os.getenv('NVD_DB', 'nvd_db')]
            self.executor = ThreadPoolExecutor(max_workers=(os.cpu_count() or 4))
            self.processed_ids = self._load_checkpoint()
            self.vector_cache = LRUCache(maxsize=ResourceConfig.CACHE_SIZE)
            self.document_cache = LRUCache(maxsize=ResourceConfig.CACHE_SIZE // 2)
            self.checkpoint_buffer = {}
            self.checkpoint_lock = asyncio.Lock()
            self.doc_process_semaphore = asyncio.Semaphore(8)
            self.loop = None
            self.embedding_model = None
            self.embedding_queue = asyncio.Queue()
            self.upsert_queue = asyncio.Queue()
            self.embedding_worker_task = None
            self.upsert_worker_task = None
            logger.info(f"向量存儲系統初始化完成：{self.data_path}")
        except Exception as e:
            logger.error(f"向量存儲系統初始化失敗：{e}", exc_info=True)
            self.chroma_client = None
            raise
    async def initialize(self):
        try:
            if self.loop is None:
                try:
                    self.loop = asyncio.get_running_loop()
                except RuntimeError:
                    self.loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(self.loop)
            self.embedding_worker_task = asyncio.create_task(self._embedding_worker())
            self.upsert_worker_task = asyncio.create_task(self._upsert_worker())
            logger.info("向量存儲系統工作線程已啟動")
            return True
        except Exception as e:
            logger.error(f"向量存儲系統異步初始化失敗：{e}", exc_info=True)
            return False
    def lazy_initialize_collection(self, key: str):
        if not self.chroma_client:
            self.chroma_client = chromadb.PersistentClient(path=str(self.data_path))
        existing = set(self.chroma_client.list_collections())
        if key in existing:
            docs_name = key
            logger.debug(f"Lazy: 沿用現有舊版文檔集合: {docs_name}")
        else:
            docs_name = f"{key}_docs"
            logger.info(f"Lazy: 創建新文檔集合: {docs_name}")
        if docs_name not in self.collections:
            self.collections[docs_name] = (self.chroma_client.get_collection(name=docs_name) if docs_name in existing else self.chroma_client.create_collection(name=docs_name, metadata={"type": "documents"}))
        self.collection_naming[key] = docs_name
    def _load_checkpoint(self) -> Dict[str, str]:
        try:
            if self.checkpoint_file.exists():
                with open(self.checkpoint_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"錯誤：讀取斷點文件失敗：{e}", exc_info=True)
            return {}
    async def _flush_checkpoint(self):
        async with self.checkpoint_lock:
            if self.checkpoint_buffer:
                self.processed_ids.update(self.checkpoint_buffer)
                try:
                    async with aiofiles.open(self.checkpoint_file, 'w') as f:
                        await f.write(json.dumps(self.processed_ids))
                    logger.info(f"已刷新 {len(self.checkpoint_buffer)} 條斷點記錄")
                    self.checkpoint_buffer.clear()
                except Exception as e:
                    logger.error(f"錯誤：刷新斷點記錄失敗：{e}", exc_info=True)
    async def _periodic_flush_checkpoint(self, interval: int = 10):
        try:
            while True:
                await asyncio.sleep(interval)
                await self._flush_checkpoint()
        except asyncio.CancelledError:
            logger.info("定期刷新斷點任務已取消")
            raise
    def get_new_documents(self) -> List[Dict]:
        try:
            all_docs = list(self.db["enriched_view"].find({}))
            new_docs = []
            three_years_ago = datetime.now(timezone.utc) - timedelta(days=365)
            for doc in all_docs:
                processed_ts = self.processed_ids.get(str(doc.get("_id")))
                doc_ts = doc.get("last_modified") or doc.get("published")
                if doc_ts:
                    if isinstance(doc_ts, str):
                        try:
                            dt = datetime.fromisoformat(doc_ts.replace("Z", "+00:00"))
                        except Exception:
                            dt = None
                    elif isinstance(doc_ts, datetime):
                        dt = doc_ts
                    else:
                        dt = None
                    if dt and dt < three_years_ago:
                        continue
                if (processed_ts is None) or (doc_ts and doc_ts > processed_ts):
                    new_docs.append(doc)
            return new_docs
        except Exception as e:
            logger.error(f"錯誤：在獲取新文檔過程中發生異常：{e}", exc_info=True)
            return []
    def mark_documents_as_indexed(self, docs: List[Dict]) -> None:
        try:
            doc_ids = [doc["_id"] for doc in docs if "_id" in doc]
            self.db["vulnerabilities"].update_many({"_id": {"$in": doc_ids}}, {"$set": {"indexed": True}})
        except Exception as e:
            logger.error(f"錯誤：更新文檔索引狀態失敗：{e}", exc_info=True)
    async def poll_for_updates(self, interval: int = 604800):
        while True:
            try:
                new_docs = self.get_new_documents()
                if new_docs:
                    total_docs = len(new_docs)
                    logger.info(f"發現 {total_docs} 個新文檔，開始進行向量化更新")
                    start_time = datetime.now(timezone.utc)
                    tasks = [self.process_document(doc, "vulnerabilities") for doc in new_docs]
                    results = await asyncio.gather(*tasks)
                    end_time = datetime.now(timezone.utc)
                    duration = (end_time - start_time).total_seconds()
                    success_count = sum(1 for r in results if r)
                    fail_count = total_docs - success_count
                    self.mark_documents_as_indexed(new_docs)
                    logger.info(f"向量化更新完成：總文檔數: {total_docs}, 成功: {success_count}, 失敗: {fail_count}, 總耗時: {duration:.2f} 秒")
                else:
                    logger.info("暫無新文檔需要更新")
            except Exception as e:
                logger.error(f"錯誤：在增量更新過程中發生異常：{e}", exc_info=True)
            await asyncio.sleep(interval)

    def _init_embedding_model(self):
        try:
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info(f"使用設備: {device}")
            logger.info("開始載入 tokenizer...")
            tokenizer = AutoTokenizer.from_pretrained("intfloat/multilingual-e5-large", cache_dir=str(self.data_path / "model_cache"))
            if not tokenizer:
                raise ValueError("Tokenizer 載入失敗")
            logger.info("Tokenizer 載入完成")
            logger.info("開始載入模型...")
            model = AutoModel.from_pretrained("intfloat/multilingual-e5-large", cache_dir=str(self.data_path / "model_cache"))
            if not model:
                raise ValueError("模型載入失敗")
            model = model.to(device)
            model.eval()
            logger.info("模型載入完成")
            return {"device": device, "tokenizer": tokenizer, "model": model}
        except Exception as e:
            logger.error(f"錯誤：初始化嵌入模型失敗：{e}", exc_info=True)
            return None
    @lru_cache(maxsize=1000)
    def _generate_embedding(self, text: str) -> Optional[List[float]]:
        if not self.embedding_model:
            logger.error("錯誤：嵌入模型尚未初始化，無法生成向量。請先調用查詢方法以進行懶初始化。")
            return None
        try:
            if not text:
                logger.error("錯誤：輸入文本為空，無法生成向量。")
                return None
            tokenizer = self.embedding_model.get("tokenizer")
            model = self.embedding_model.get("model")
            device = self.embedding_model.get("device")
            if not all([tokenizer, model, device]):
                logger.error("錯誤：嵌入模型缺少必要組件（tokenizer/model/device）。請檢查配置與依賴。")
                return None
            inputs = tokenizer(text, padding=True, truncation=True, return_tensors="pt", max_length=512)
            inputs = {k: v.to(device) for k, v in inputs.items()}
            with torch.no_grad():
                outputs = model(**inputs)
                if outputs is None or outputs.last_hidden_state is None:
                    logger.error("錯誤：模型未返回有效輸出，無法生成向量。")
                    return None
                embedding = outputs.last_hidden_state.mean(dim=1)
                if embedding.shape[-1] != 1024:
                    logger.error(f"錯誤：生成的向量維度不正確，預期為 1024，實際獲得 {embedding.shape[-1]}。")
                    return None
                return embedding.cpu().numpy()[0].tolist()
        except Exception as e:
            logger.error(f"錯誤：向量生成失敗：{e}", exc_info=True)
            return None
    def _generate_embeddings_batch(self, texts: List[str]) -> List[Optional[List[float]]]:
        if not self.embedding_model:
            logger.error("錯誤：嵌入模型尚未初始化，無法生成批次向量。請先初始化模型。")
            return [None] * len(texts)
        try:
            tokenizer = self.embedding_model.get("tokenizer")
            model = self.embedding_model.get("model")
            device = self.embedding_model.get("device")
            inputs = tokenizer(texts, padding=True, truncation=True, return_tensors="pt", max_length=512)
            inputs = {k: v.to(device) for k, v in inputs.items()}
            with torch.no_grad():
                outputs = model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
            embeddings_list = embeddings.cpu().numpy().tolist()
            for emb in embeddings_list:
                if len(emb) != 1024:
                    logger.error(f"錯誤：生成的向量維度不正確，預期為 1024，實際獲得 {len(emb)}。")
                    return [None] * len(texts)
            return embeddings_list
        except Exception as e:
            logger.error(f"錯誤：批次向量生成失敗：{e}", exc_info=True)
            return [None] * len(texts)
    async def generate_embedding_async(self, text: str) -> Optional[List[float]]:
        if self.loop is None:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                self.loop = asyncio.get_event_loop()
        fut = self.loop.create_future()
        await self.embedding_queue.put((text, fut))
        return await fut
    async def query(self, text: str, collection_name: str = None, top_k: int = 5, threshold: float = 0.7, use_cache: bool = True) -> Dict:
        if self.loop is None:
            try:
                self.loop = asyncio.get_running_loop()
            except RuntimeError:
                self.loop = asyncio.get_event_loop()
        if self.embedding_model is None:
            logger.info("嵌入模型未初始化，進行懶初始化...")
            self.embedding_model = self._init_embedding_model()
            if not self.embedding_model:
                logger.error("錯誤：嵌入模型懶初始化失敗。")
                return {'query': text, 'timestamp': datetime.now(timezone.utc).isoformat(), 'results': []}
        try:
            query_embedding = await self.loop.run_in_executor(self.executor, self._generate_embedding, text)
            if query_embedding is None:
                logger.error("錯誤：查詢向量生成失敗。")
                return {'query': text, 'timestamp': datetime.now(timezone.utc).isoformat(), 'results': []}
            if len(query_embedding) != 1024:
                logger.error(f"錯誤：查詢向量維度不符，預期 1024，實際獲得 {len(query_embedding)}。")
                return {'query': text, 'timestamp': datetime.now(timezone.utc).isoformat(), 'results': []}
            results = {'query': text, 'timestamp': datetime.now(timezone.utc).isoformat(), 'results': []}
            collections_to_query = ([collection_name] if collection_name else ResourceConfig.COLLECTIONS.keys())
            for key in collections_to_query:
                if self.init_mode == InitMode.LAZY.value:
                    if key not in self.collection_naming:
                        self.lazy_initialize_collection(key)
                cache_key = f"{key}:{text}"
                if use_cache and cache_key in self.vector_cache:
                    logger.info(f"使用快取結果: {cache_key}")
                    results['results'].extend(self.vector_cache[cache_key])
                    continue
                try:
                    batch_results = await self._batch_query(key, query_embedding, top_k, threshold)
                    if batch_results:
                        if use_cache:
                            self.vector_cache[cache_key] = batch_results
                        results['results'].extend(batch_results)
                except Exception as e:
                    logger.error(f"錯誤：在查詢集合 '{key}' 時發生異常：{e}", exc_info=True)
                    continue
            results['results'].sort(key=lambda x: x.get('final_score', x.get('score', 0)), reverse=True)
            results['results'] = results['results'][:top_k]
            return results
        except Exception as e:
            logger.error(f"錯誤：查詢過程中發生異常：{e}", exc_info=True)
            return {'query': text, 'timestamp': datetime.now(timezone.utc).isoformat(), 'results': []}
    async def _process_batch_results(self, batch_results: Dict, key: str, threshold: float, query_embedding: List[float]) -> List[Dict]:
        processed_results = []
        try:
            for i, (doc_id, doc_dist) in enumerate(zip(batch_results['ids'][0], batch_results['distances'][0])):
                try:
                    if doc_dist < threshold:
                        continue
                    if doc_id in self.document_cache:
                        processed_results.append(self.document_cache[doc_id])
                        continue
                    mapping_prefix = "" if self.collection_naming.get(key) == key else f"{key}_"
                    raw_doc_id = doc_id[len(mapping_prefix):] if doc_id.startswith(mapping_prefix) else doc_id
                    result = {'id': doc_id, 'raw_doc_id': raw_doc_id, 'document': json.loads(batch_results['documents'][0][i]), 'doc_score': doc_dist, 'metadata': batch_results['metadatas'][0][i], 'score': doc_dist}
                    self.document_cache[doc_id] = result
                    processed_results.append(result)
                except Exception as e:
                    logger.error(f"錯誤：在處理文檔 (doc_id: {doc_id}) 結果時發生異常：{e}", exc_info=True)
                    continue
            return processed_results
        except Exception as e:
            logger.error(f"錯誤：批次處理結果時發生異常：{e}", exc_info=True)
            return []
    async def _batch_query(self, key: str, query_embedding: List[float], top_k: int, threshold: float) -> List[Dict]:
        try:
            collection = self.collections.get("all")
            if not collection:
                logger.error("錯誤：未找到集合：all")
                return []
            batch_results = collection.query(query_embeddings=[query_embedding], n_results=top_k)
            if not batch_results['ids'][0]:
                logger.info(f"集合 {key} 未返回查詢結果")
                return []
            batch_processed = await self._process_batch_results(batch_results, key, threshold, query_embedding)
            return batch_processed
        except Exception as e:
            logger.error(f"錯誤：執行批次查詢操作時發生異常：{e}", exc_info=True)
            return []
    def _handle_mongo_doc(self, doc: Dict) -> Dict:
        if not doc:
            logger.warning("警告：收到空的文檔，跳過處理。")
            return {}
        def convert_value(value: Any) -> Any:
            if isinstance(value, ObjectId):
                return str(value)
            elif isinstance(value, datetime):
                return value.isoformat()
            elif isinstance(value, dict):
                return {k: convert_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [convert_value(item) for item in value]
            return value
        try:
            return {k: convert_value(v) for k, v in doc.items()}
        except Exception as e:
            logger.error(f"錯誤：在處理 MongoDB 文檔 (ID: {doc.get('_id', '未知')}) 時發生異常：{e}", exc_info=True)
            return {}
    async def _handle_mongo_doc_async(self, doc: Dict) -> Dict:
        try:
            if not doc:
                return {}
            def convert():
                return self._handle_mongo_doc(doc)
            return await self.loop.run_in_executor(self.executor, convert)
        except Exception as e:
            logger.error(f"錯誤：在異步處理 MongoDB 文檔時發生異常：{e}", exc_info=True)
            return {}
    def _convert_to_json(self, doc: Dict) -> str:
        try:
            return json.dumps(self._handle_mongo_doc(doc), ensure_ascii=False)
        except Exception as e:
            logger.error(f"錯誤：文檔轉換為 JSON 格式失敗：{e}", exc_info=True)
            return ""
    async def process_document(self, doc: Dict, key: str) -> bool:
        async with self.doc_process_semaphore:
            try:
                docs_collection_name = self.collection_naming.get(key)
                if self.init_mode == InitMode.LAZY.value:
                    if key not in self.collection_naming:
                        self.lazy_initialize_collection(key)
                    docs_collection_name = self.collection_naming.get(key)
                elif not docs_collection_name:
                    logger.error(f"錯誤：集合 '{key}' 尚未初始化，請確認初始化過程是否正確。")
                    return False
                processed_doc = self._handle_mongo_doc(doc)
                if not processed_doc:
                    logger.error("錯誤：文檔處理失敗，無法進行後續處理，跳過此文檔。")
                    return False
                raw_doc_id = str(processed_doc.get('_id', ''))
                if not raw_doc_id:
                    logger.error("錯誤：文檔缺少唯一識別碼 (ID)，無法進行處理。")
                    return False
                storage_doc_id = raw_doc_id if self.collection_naming.get(key) == key else f"{key}_{raw_doc_id}"
                last_modified = processed_doc.get('last_modified', processed_doc.get('published'))
                if self.init_mode == InitMode.INCREMENTAL.value:
                    if storage_doc_id in self.processed_ids and self.processed_ids[storage_doc_id] == last_modified:
                        logger.info(f"文檔 {storage_doc_id} 未更新，跳過處理")
                        return True
                try:
                    doc_text = self._convert_to_json(processed_doc)
                    if not doc_text:
                        logger.error("錯誤：文檔序列化失敗，無法轉換為 JSON 格式。")
                        return False
                    doc_embedding = await self.generate_embedding_async(doc_text)
                    if doc_embedding is None:
                        logger.error("錯誤：生成文檔向量失敗。")
                        return False
                except Exception as e:
                    logger.error(f"錯誤：向量生成失敗：{e}", exc_info=True)
                    return False
                try:
                    fut = self.loop.create_future()
                    upsert_job = (self.collection_naming.get(key), storage_doc_id, doc_embedding, doc_text, {"type": "document", "source": key, "timestamp": datetime.now(timezone.utc).isoformat(), "doc_id": raw_doc_id}, fut)
                    await self.upsert_queue.put(upsert_job)
                    upsert_result = await fut
                    if not upsert_result:
                        logger.error(f"錯誤：集合 {self.collection_naming.get(key)} 批次上傳失敗")
                        return False
                    logger.info(f"文檔向量更新成功：{storage_doc_id}")
                    try:
                        self._update_checkpoint(storage_doc_id, last_modified)
                    except AttributeError as ae:
                        logger.error("錯誤：向量存儲更新失敗：找不到方法 '_update_checkpoint'。請確認是否已定義此方法或是否拼寫錯誤。", exc_info=True)
                        return False
                    return True
                except Exception as e:
                    logger.error(f"錯誤：向量存儲更新失敗：{e}", exc_info=True)
                    return False
            except Exception as e:
                logger.error(f"錯誤：處理文檔時發生異常：{e}", exc_info=True)
                return False
    def _update_checkpoint(self, doc_id: str, last_modified: Any):
        self.processed_ids[doc_id] = last_modified
        self.checkpoint_buffer[doc_id] = last_modified
    async def _embedding_worker(self):
        batch_size = 16
        wait_timeout = 0.05
        while True:
            try:
                items = []
                item = await self.embedding_queue.get()
                items.append(item)
                try:
                    for _ in range(batch_size - 1):
                        item = await asyncio.wait_for(self.embedding_queue.get(), timeout=wait_timeout)
                        items.append(item)
                except asyncio.TimeoutError:
                    pass
                texts = [t for (t, fut) in items]
                embeddings = await self.loop.run_in_executor(self.executor, self._generate_embeddings_batch, texts)
                for ((t, fut), embedding) in zip(items, embeddings):
                    if not fut.done():
                        fut.set_result(embedding)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Embedding worker encountered an error: {e}", exc_info=True)
    async def _upsert_worker(self):
        batch_size = 32
        wait_timeout = 0.05
        while True:
            try:
                items = []
                item = await self.upsert_queue.get()
                items.append(item)
                try:
                    for _ in range(batch_size - 1):
                        item = await asyncio.wait_for(self.upsert_queue.get(), timeout=wait_timeout)
                        items.append(item)
                except asyncio.TimeoutError:
                    pass
                groups = {}
                for coll_name, doc_id, embedding, doc_text, metadata, fut in items:
                    groups.setdefault(coll_name, []).append((doc_id, embedding, doc_text, metadata, fut))
                for coll_name, tasks in groups.items():
                    ids = [x[0] for x in tasks]
                    embeddings = [x[1] for x in tasks]
                    documents = [x[2] for x in tasks]
                    metadatas = [x[3] for x in tasks]
                    futures = [x[4] for x in tasks]
                    try:
                        docs_collection = self.collections.get(coll_name)
                        if not docs_collection:
                            raise Exception(f"集合 {coll_name} 未初始化")
                        docs_collection.upsert(ids=ids, embeddings=embeddings, documents=documents, metadatas=metadatas)
                        for fut in futures:
                            if not fut.done():
                                fut.set_result(True)
                    except Exception as e:
                        logger.error(f"批次上傳向量失敗（集合 {coll_name}）：{e}", exc_info=True)
                        for fut in futures:
                            if not fut.done():
                                fut.set_result(False)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Upsert worker encountered an error: {e}", exc_info=True)
    async def close(self):
        try:
            if self.embedding_worker_task:
                self.embedding_worker_task.cancel()
                try:
                    await self.embedding_worker_task
                except asyncio.CancelledError:
                    logger.info("Embedding worker task cancelled")
            if self.upsert_worker_task:
                self.upsert_worker_task.cancel()
                try:
                    await self.upsert_worker_task
                except asyncio.CancelledError:
                    logger.info("Upsert worker task cancelled")
            resources = [('database', self.db), ('chroma_client', self.chroma_client), ('executor', self.executor)]
            for name, res in resources:
                if res is not None:
                    try:
                        if name == 'executor':
                            res.shutdown()
                        elif name == 'chroma_client':
                            self.chroma_client = None
                        logger.info(f"成功關閉 {name}")
                    except Exception as e:
                        logger.error(f"錯誤：在關閉 {name} 時發生異常：{str(e)}", exc_info=True)
            logger.info("所有資源清理完成")
        except Exception as e:
            logger.error(f"錯誤：在清理資源過程中發生異常：{e}", exc_info=True)
            raise
