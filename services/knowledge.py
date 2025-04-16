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

import os, csv, glob, logging, asyncio, chromadb
from typing import List, Dict, Any

from langchain_huggingface import HuggingFaceEmbeddings

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class KnowledgeBase:
    """
    知識庫管理類：
      - 使用 ChromaDB 作為向量檢索介面
      - 從 CSV 載入數據構建向量庫（針對資產向量）
    """
    def __init__(self, 
                 model_name: str = "intfloat/multilingual-e5-large", 
                 csv_path: str = None, 
                 persist_path: str = None,
                 eager_load: bool = False):
        self.embeddings = HuggingFaceEmbeddings(model_name=model_name)
        self.csv_path = csv_path
        self.asset_path = r"C:\Users\OTTO\Desktop\TANET 2024\Proposal\src\data_lake\chroma_asset"
        if not os.path.exists(self.asset_path):
            logger.info("asset_path %s 不存在，建立目錄", self.asset_path)
            os.makedirs(self.asset_path, exist_ok=True)
        else:
            logger.info("asset_path %s 已存在，直接讀取資產向量資料庫", self.asset_path)
        self.persist_path = r"C:\Users\OTTO\Desktop\TANET 2024\Proposal\src\data_lake\chroma_db"
        self._data_loaded = False
        self.cache: Dict[str, List[Dict[str, Any]]] = {}
        self.chroma_client = chromadb.PersistentClient(path=self.asset_path)
        collections = self.chroma_client.list_collections()
        logger.info("目前現有集合: %s", collections)
        if collections:
            self.collections = {coll: self.chroma_client.get_collection(name=coll) for coll in collections}
            self.collection = list(self.collections.values())[0]
            logger.info("使用現有集合作為向量庫：%s", list(self.collections.keys())[0])
            self._data_loaded = True
        else:
            logger.warning("未發現任何集合，將自動建立預設集合")
            self.collection = self.chroma_client.create_collection(
                name="asset_collection",
                metadata={"type": "documents"}
            )
            self.collections = {"asset_collection": self.collection}
            logger.info("預設集合 'asset_collection' 已建立")
        logger.info("KnowledgeBase 初始化完成，使用 ChromaDB 作為向量檢索介面")
        if eager_load and not self._data_loaded:
            asyncio.create_task(self._load_data())

    async def _load_data(self):
        if self._data_loaded:
            return
        texts = []
        metadatas = []
        csv_files = []
        if self.csv_path:
            csv_path_norm = os.path.normpath(self.csv_path)
            if not os.path.isabs(csv_path_norm):
                csv_path_norm = os.path.join(os.path.dirname(__file__), csv_path_norm)
            if os.path.isdir(csv_path_norm):
                csv_files = glob.glob(os.path.join(csv_path_norm, "*.csv"))
            elif os.path.isfile(csv_path_norm) and csv_path_norm.lower().endswith(".csv"):
                csv_files = [csv_path_norm]
            if not csv_files:
                logger.warning("指定路徑 '%s' 中未找到任何 CSV 檔案", csv_path_norm)
        else:
            default_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "data"))
            csv_files = glob.glob(os.path.join(default_dir, "*.csv"))
            if not csv_files:
                logger.warning("預設目錄 '%s' 中未找到任何 CSV 檔案", default_dir)
        for csv_file in csv_files:
            logger.info("載入 CSV 檔案: %s", csv_file)
            try:
                # 使用異步方法讀取 CSV（借助 to_thread）
                rows = await asyncio.to_thread(self._read_csv, csv_file)
                for row in rows:
                    text = ", ".join(f"{key}: {str(value).strip()}" for key, value in row.items())
                    texts.append(text)
                    metadatas.append(row)
            except Exception as e:
                logger.error("讀取 CSV 檔案 %s 失敗: %s", csv_file, e)
        # if texts:
        #     logger.info("開始從 CSV 數據構建向量庫...")
        #     embeddings = self.embeddings.embed_documents(texts)
        #     ids = [str(i) for i in range(len(texts))]
        #     self.collection.add(
        #         documents=texts,
        #         metadatas=metadatas,
        #         embeddings=embeddings,
        #         ids=ids
        #     )
        #     logger.info("向量庫已更新，持久化至 %s", self.asset_path)
        # else:
        #     logger.warning("未從 CSV 中讀取到有效資料，向量庫未更新")
        # self._data_loaded = True

    def _read_csv(self, filepath: str) -> List[Dict[str, Any]]:
        with open(filepath, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)

    async def search(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        if not self._data_loaded:
            await self._load_data()
        query_embedding = self.embeddings.embed_query(query)
        results = self.collection.query(query_embeddings=[query_embedding], n_results=k)
        result_list = []
        for doc, score in zip(results["documents"][0], results["distances"][0]):
            result_list.append({
                "content": doc,
                "score": float(score)
            })
        return result_list

    async def close(self) -> None:
        logger.info("KnowledgeBase 已關閉。")
