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
import logging
import asyncio
from typing import List, Dict, Any, Optional, Callable, Union, Tuple
from functools import lru_cache
from contextlib import asynccontextmanager

# 設定日誌
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# 環境變數
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
ASSET_DB = os.getenv("ASSET_DB", "assets")
KG = os.getenv("KNOWLEDGE", "KG")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "openai:gpt-4o-mini")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "intfloat/multilingual-e5-large")

# 匯入外部依賴
try:
    from pymongo import MongoClient
    from llama_index.core.schema import Document, NodeWithScore, QueryBundle
    from llama_index.core import VectorStoreIndex, load_index_from_storage, StorageContext
    from llama_index.core.retrievers import VectorIndexRetriever, QueryFusionRetriever
    from llama_index.core.postprocessor import LLMRerank, SimilarityPostprocessor
    from llama_index.core.query_engine import RetrieverQueryEngine
    from llama_index.core.response_synthesizers import get_response_synthesizer
    from llama_index.core.node_parser import SentenceSplitter
    from llama_index.core.storage import StorageContext
    import aisuite as ai
    from langchain_huggingface import HuggingFaceEmbeddings
    from llama_index.postprocessor.colbert_rerank import ColbertRerank
    from llama_index.postprocessor.rankgpt_rerank import RankGPTRerank
except ImportError as e:
    logger.error(f"依賴庫導入失敗: {e}")
    raise

# -----------------------------
# 工具函式
# -----------------------------
def get_text_from_node(node: Any) -> str:
    if isinstance(node, NodeWithScore):
        return node.node.text
    return getattr(node, "text", str(node))

@lru_cache(maxsize=100)
def get_query_embedding(query: str, embed_model: Any) -> List[float]:
    try:
        return embed_model.get_query_embedding(query)
    except Exception as e:
        logger.error(f"獲取查詢嵌入向量失敗: {e}")
        return []

# -----------------------------
# 增強型重排序器
# -----------------------------
class EnhancedReranker:    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rerankers = {}
        self._initialize_rerankers()
        
    def _initialize_rerankers(self):
        top_n = self.config.get('rerank_top_n', 3)
        
        self.rerankers = {
            'llm': LLMRerank(
                choice_batch_size=3, 
                top_n=top_n
            ),
            'colbert': ColbertRerank(
                top_n=top_n
            ),
            'rankgpt': self._create_enhanced_rankgpt(top_n),
            'similarity': SimilarityPostprocessor(
                similarity_cutoff=self.config.get('min_score_threshold', 0.3)
            )
        }
    
    def _create_enhanced_rankgpt(self, top_n: int) -> RankGPTRerank:
        class EnhancedRankGPTRerank(RankGPTRerank):
            def postprocess_nodes(self, nodes, query_bundle):
                try:
                    valid_nodes = [n for n in nodes if n and hasattr(n, 'metadata')]
                    return super().postprocess_nodes(valid_nodes, query_bundle) if valid_nodes else []
                except Exception as e:
                    return nodes
                    
        return EnhancedRankGPTRerank(top_n=top_n)
    
    def get_reranker(self, name: str):
        return self.rerankers.get(name)
    
    def hybrid_rerank(self, nodes: List[Any], query: Union[str, QueryBundle], 
                      strategies: List[str] = None) -> List[Any]:
        if not nodes:
            return []
            
        if strategies is None:
            strategies = ['similarity', 'colbert']
            
        current_nodes = nodes
        for strategy in strategies:
            reranker = self.get_reranker(strategy)
            if reranker:
                try:
                    if isinstance(query, str):
                        query_bundle = QueryBundle(query_str=query)
                    else:
                        query_bundle = query
                    current_nodes = reranker.postprocess_nodes(current_nodes, query_bundle)
                except Exception as e:
                    logger.error(f"{strategy} 重排序錯誤: {e}")
        
        return current_nodes

# -----------------------------
# 知識庫模組
# -----------------------------
class KnowledgeBase:
    """知識庫基礎類"""
    _instances = {}  # 單例模式實現

    def __new__(cls, db_name=ASSET_DB, collection_name=KG, llm=None):
        key = f"{db_name}:{collection_name}"
        if key not in cls._instances:
            cls._instances[key] = super(KnowledgeBase, cls).__new__(cls)
            cls._instances[key]._initialized = False
        return cls._instances[key]

    def __init__(self, db_name=ASSET_DB, collection_name=KG, llm=None):
        if getattr(self, "_initialized", False):
            return

        self.db_name = db_name
        self.collection_name = collection_name
        self.llm = llm
        self.documents = []
        self.doc_store = {}  # 文檔快取
        
        # 初始化數據庫連接
        try:
            self.mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
            self.db = self.mongo_client[db_name]
            self.collection = self.db[collection_name]
            self.db_available = True
            logger.info(f"MongoDB連接成功: {db_name}.{collection_name}")
        except Exception as e:
            logger.error(f"MongoDB連接失敗: {e}")
            self.db_available = False
            self.mongo_client = self.db = self.collection = None
            
        self._initialized = True

    async def load_from_vuln_data(self, vuln_data: List[Dict[str, Any]]) -> None:
        """載入漏洞數據"""
        if not vuln_data:
            logger.warning("沒有漏洞數據可載入")
            return
            
        logger.info(f"載入 {len(vuln_data)} 筆漏洞數據")
        self.documents = []
        for vuln in vuln_data:
            cve_id = vuln.get("cve_id", "")
            if not cve_id:
                continue
                
            # 處理漏洞描述，增強 faithfulness
            description = vuln.get("description", "")
            references = vuln.get("references", [])
            ref_text = "\n".join(references) if references else ""
            
            # 結合描述和參考資料，提高相關性
            full_text = f"CVE ID: {cve_id}\n描述: {description}"
            if ref_text:
                full_text += f"\n參考資料: {ref_text}"
                
            # 添加嚴重性和基本評分以提高檢索相關性
            severity = vuln.get("severity", "")
            base_score = vuln.get("base_score", 0)
            if severity and base_score:
                full_text += f"\n嚴重性: {severity}\n基本評分: {base_score}"
            
            processed_data = {
                "cve_id": cve_id,
                "description": description,
                "base_score": base_score,
                "severity": severity,
                "references": references,
                "full_text": full_text  # 用於檢索的完整文本
            }
            
            self.documents.append(processed_data)
            # 保存文檔到快取，方便後續查詢
            self.doc_store[cve_id] = processed_data
                
        logger.info(f"成功載入 {len(self.documents)} 筆文檔")

    def get_documents(self) -> List[Dict]:
        """獲取文檔列表"""
        return self.documents
    
    def get_document_by_id(self, doc_id: str) -> Optional[Dict]:
        """根據ID獲取文檔"""
        return self.doc_store.get(doc_id)
        
    def close(self):
        """關閉資源連接"""
        if hasattr(self, 'mongo_client') and self.mongo_client:
            self.mongo_client.close()

# -----------------------------
# 統一檢索引擎
# -----------------------------
class UnifiedRetriever:
    """統一檢索引擎，整合多種檢索策略"""
    
    def __init__(self, knowledge_base: KnowledgeBase, config: Optional[Dict[str, Any]] = None):
        self.kb = knowledge_base
        self.index = None
        self.retriever = None
        self.cache = {}
        self.last_refresh = 0
        
        # 配置參數
        self.config = {
            'rerank_top_n': 3,
            'similarity_top_k': 5,
            'cache_ttl': 3600,  # 快取有效期 (秒)
            'min_score_threshold': 0.3,  # 最低分數閾值
            'default_strategy': 'hybrid'  # 預設策略
        }
        if config:
            self.config.update(config)
        
        # 初始化組件
        self.embeddings = None
        self.reranker = None
        self.synthesizer = None
        self._initialize_components()
        
    def _initialize_components(self):
        """初始化所有必要組件"""
        try:
            # 嵌入模型
            self.embeddings = HuggingFaceEmbeddings(model_name=EMBEDDING_MODEL)
            
            # 重排序器
            self.reranker = EnhancedReranker(self.config)
            
            # 回應合成器
            self.synthesizer = get_response_synthesizer(response_mode="compact")
            
            logger.info("檢索引擎組件初始化成功")
        except Exception as e:
            logger.error(f"初始化組件失敗: {e}")
            raise

    def _prepare_documents(self, docs: List[Dict]) -> List[Document]:
        """準備文檔用於索引建立，提高文檔質量以增強 faithfulness"""
        index_docs = []
        for doc in docs:
            # 使用完整文本或描述
            text = doc.get("full_text", "") or doc.get("description", "")
            if not text:
                text = str(doc)
            
            # 豐富描述內容，確保文檔包含完整信息
            cve_id = doc.get("cve_id", "")
            if cve_id and cve_id not in text:
                text = f"CVE ID: {cve_id}\n{text}"
                
            # 添加漏洞嚴重性和評分信息
            severity = doc.get("severity", "")
            base_score = doc.get("base_score", "")
            if severity and str(severity) not in text:
                text += f"\n嚴重性: {severity}"
            if base_score and str(base_score) not in text:
                text += f"\n基本評分: {base_score}"
                
            # 添加參考資料
            references = doc.get("references", [])
            if references and "\n參考資料:" not in text:
                ref_text = "\n參考資料:\n- " + "\n- ".join(references[:3])  # 限制引用數量
                text += ref_text
                
            # 提取元數據，確保包含所有重要信息
            metadata = {k: v for k, v in doc.items() if k not in ["full_text", "description"] and v}
            
            # 確保 cve_id 存在於元數據中
            if cve_id and "cve_id" not in metadata:
                metadata["cve_id"] = cve_id
                
            # 創建文檔對象，使用增強的文本和完整元數據
            index_docs.append(Document(text=text, metadata=metadata))
        
        return index_docs

    def build_index(self, docs: List[Dict] = None) -> bool:
        """建立或更新檢索索引"""
        try:
            # 使用提供的文檔或知識庫中的文檔
            docs_to_index = docs if docs is not None else self.kb.documents
            if not docs_to_index:
                logger.warning("沒有文檔可用，無法建立索引")
                return False

            # 準備文檔            
            index_docs = self._prepare_documents(docs_to_index)
            
            # 建立索引，使用文本分割器提高精度
            splitter = SentenceSplitter(chunk_size=512, chunk_overlap=50)
            self.index = VectorStoreIndex.from_documents(
                index_docs,
                embed_model=self.embeddings,
                transformations=[splitter]
            )
            
            # 創建檢索器
            self.retriever = self.index.as_retriever(
                similarity_top_k=self.config['similarity_top_k']
            )
            
            self.last_refresh = asyncio.get_event_loop().time()
            logger.info(f"索引建立成功，包含 {len(index_docs)} 個文檔")
            return True
        except Exception as e:
            logger.error(f"索引創建失敗: {e}")
            return False

    def _check_cache(self, query: str) -> Optional[List[Any]]:
        """檢查是否有有效的快取結果"""
        if query not in self.cache:
            return None
            
        cache_entry = self.cache[query]
        current_time = asyncio.get_event_loop().time()
        
        # 檢查快取是否過期
        if current_time - cache_entry['timestamp'] > self.config['cache_ttl']:
            return None
            
        return cache_entry['nodes']

    async def retrieve(self, query: str, strategy: str = None) -> List[Any]:
        """統一檢索接口"""
        # 檢查文檔和索引
        if not self.kb.documents:
            logger.warning("沒有文檔可用於檢索")
            return []
            
        # 建立索引（如果需要）
        if not self.retriever:
            if not self.build_index():
                return []
        
        # 檢查快取
        cached_result = self._check_cache(query)
        if cached_result:
            return cached_result
        
        # 使用指定策略或默認策略
        strategy = strategy or self.config['default_strategy']
        
        try:
            # 執行檢索
            nodes = await self._execute_strategy(query, strategy)
            
            # 更新快取
            if nodes:
                self.cache[query] = {
                    'nodes': nodes,
                    'timestamp': asyncio.get_event_loop().time()
                }
                
            return nodes
        except Exception as e:
            logger.error(f"檢索錯誤: {e}")
            return []

    async def _execute_strategy(self, query: str, strategy: str) -> List[Any]:
        """執行檢索策略"""
        if strategy == 'basic':
            return await self._basic_retrieval(query)
        elif strategy == 'llm_rerank':
            return await self._llm_reranked_retrieval(query)
        elif strategy == 'colbert':
            return await self._colbert_retrieval(query)
        elif strategy == 'hybrid':
            return await self._hybrid_retrieval(query)
        elif strategy == 'multi_query':
            return await self._multi_query_retrieval(query)
        else:
            logger.warning(f"未知策略 '{strategy}'，使用混合策略")
            return await self._hybrid_retrieval(query)

    async def _basic_retrieval(self, query: str) -> List[Any]:
        """基本檢索"""
        try:
            nodes = self.retriever.retrieve(query)
            return nodes
        except Exception as e:
            logger.error(f"基本檢索錯誤: {e}")
            return []

    async def _llm_reranked_retrieval(self, query: str) -> List[Any]:
        """LLM重排序檢索"""
        try:
            # 先進行基本檢索
            nodes = self.retriever.retrieve(query)
            # 應用LLM重排序
            reranked_nodes = self.reranker.get_reranker('llm').postprocess_nodes(
                nodes, 
                QueryBundle(query_str=query)
            )
            return reranked_nodes
        except Exception as e:
            logger.error(f"LLM重排序檢索錯誤: {e}")
            return []

    async def _colbert_retrieval(self, query: str) -> List[Any]:
        """ColBERT檢索"""
        try:
            nodes = self.retriever.retrieve(query)
            reranked_nodes = self.reranker.get_reranker('colbert').postprocess_nodes(
                nodes, 
                QueryBundle(query_str=query)
            )
            return reranked_nodes
        except Exception as e:
            logger.error(f"ColBERT檢索錯誤: {e}")
            return []

    async def _hybrid_retrieval(self, query: str) -> List[Any]:
        """混合策略檢索 (提高 faithfulness 和 relevancy)"""
        try:
            # 1. 基本檢索獲取更多候選節點
            raw_nodes = self.retriever.retrieve(query)
            
            # 2. 計算查詢與每個節點的相似度分數
            for node in raw_nodes:
                if not hasattr(node, 'score') or node.score is None:
                    # 計算文本相似度作為備份分數
                    node_text = get_text_from_node(node)
                    similarity = self._calculate_text_similarity(query, node_text)
                    node.score = similarity
            
            # 3. 首先過濾掉明顯不相關的節點
            threshold = self.config.get('min_score_threshold', 0.3)
            filtered_nodes = [n for n in raw_nodes if n.score >= threshold]
            
            # 如果過濾後沒有節點，回退到原始節點的前幾個
            if not filtered_nodes and raw_nodes:
                filtered_nodes = sorted(raw_nodes, key=lambda x: getattr(x, 'score', 0), reverse=True)[:3]
            
            # 4. 應用 ColBERT 重排序提高相關性
            if filtered_nodes:
                try:
                    reranked_nodes = self.reranker.get_reranker('colbert').postprocess_nodes(
                        filtered_nodes,
                        QueryBundle(query_str=query)
                    )
                    if reranked_nodes:
                        return reranked_nodes
                except Exception as e:
                    logger.warning(f"ColBERT 重排序失敗: {e}")
            
            # 5. 回退到過濾後的節點
            return filtered_nodes or raw_nodes[:3]
            
        except Exception as e:
            logger.error(f"混合檢索錯誤: {e}")
            return []
    
    def _calculate_text_similarity(self, query: str, text: str) -> float:
        """計算文本相似度分數作為備份"""
        # 簡單的基於關鍵詞的相似度計算
        query_words = set(query.lower().split())
        text_words = set(text.lower().split())
        
        if not query_words or not text_words:
            return 0.0
            
        # 計算詞彙重疊比例
        common_words = query_words.intersection(text_words)
        similarity = len(common_words) / max(len(query_words), 1)
        
        # 提高分數以反映更高的相關性
        return min(similarity * 1.5, 1.0)

    async def _multi_query_retrieval(self, query: str) -> List[Any]:
        """多查詢融合檢索"""
        try:
            # 創建融合檢索器
            fusion_retriever = QueryFusionRetriever(
                [self.retriever],
                similarity_top_k=self.config['similarity_top_k'],
                num_queries=3,
                mode="reciprocal_rerank",
                use_async=True
            )
            
            # 獲取結果
            nodes = fusion_retriever.retrieve(query)
            
            # 應用相似度過濾
            filtered_nodes = self.reranker.get_reranker('similarity').postprocess_nodes(
                nodes, 
                QueryBundle(query_str=query)
            )
            
            return filtered_nodes
        except Exception as e:
            logger.error(f"多查詢檢索錯誤: {e}")
            return []

    async def generate_answer(self, query: str, nodes: List[Any] = None) -> str:
        """根據檢索結果生成回答，提高 faithfulness 評分
        
        Args:
            query: 查詢字符串
            nodes: 檢索到的節點列表，如果為 None 則會自動檢索
            
        Returns:
            str: 生成的回答
        """
        if nodes is None:
            nodes = await self.retrieve(query)
            
        if not nodes:
            return "沒有找到相關資訊。"
            
        try:
            # 1. 識別關鍵來源節點
            source_texts = []
            for i, node in enumerate(nodes[:3]):  # 只使用最相關的前3個節點
                text = get_text_from_node(node)
                if hasattr(node, 'score'):
                    confidence = f"(相關度: {node.score:.2f})"
                else:
                    confidence = ""
                    
                # 提取節點元數據中的 ID (如CVE ID)
                node_id = ""
                if hasattr(node, 'metadata') and 'cve_id' in node.metadata:
                    node_id = f"[{node.metadata['cve_id']}] "
                
                source_texts.append(f"來源 {i+1} {node_id}{confidence}: {text}")
            
            # 2. 合併來源文本，增加引文標記
            combined_text = "\n\n".join(source_texts)
            
            # 3. 創建明確的提示，強調依據來源生成答案
            prompt = f"""基於以下資訊來源回答查詢：
            
查詢: {query}

來源資訊:
{combined_text}

請根據上述來源提供準確回答。如果來源資訊不足以完整回答查詢，請明確指出哪些部分是有根據的，哪些部分缺乏資訊。不要添加未在來源中提及的資訊。

回答:
"""
            # 4. 使用 LLM 生成回答
            response = await ai.Client().complete(prompt, max_tokens=512)
            answer = response.completion.strip()
            
            # 5. 為回答添加來源引用
            if len(nodes) > 0:
                citations = []
                for i, node in enumerate(nodes[:3]):
                    if hasattr(node, 'metadata') and 'cve_id' in node.metadata:
                        citations.append(f"[{i+1}] {node.metadata['cve_id']}")
                    else:
                        citations.append(f"[{i+1}] 來源 {i+1}")
                
                if citations:
                    answer += f"\n\n參考來源:\n" + "\n".join(citations)
            
            return answer
            
        except Exception as e:
            logger.error(f"生成答案錯誤: {e}")


    def clear_cache(self) -> None:
        """清除查詢快取"""
        cache_size = len(self.cache)
        self.cache.clear()
        logger.info(f"已清除 {cache_size} 個快取項目")

    def close(self) -> None:
        """關閉並釋放資源"""
        self.cache.clear()
        self.index = None
        self.retriever = None
        self.embeddings = None
        self.reranker = None
        self.synthesizer = None

# -----------------------------
# 上下文管理器
# -----------------------------
@asynccontextmanager
async def get_retriever(strategy: str = "hybrid", llm: Any = None, config: Optional[Dict[str, Any]] = None):
    """取得檢索器的上下文管理器
    
    Args:
        strategy: 檢索策略 (向後相容參數)
        llm: 語言模型客戶端 (向後相容參數)
        config: 配置參數
    """
    kb = None
    retriever = None
    try:
        kb = KnowledgeBase(llm=llm)
        
        # 處理配置
        effective_config = config or {}
        if strategy != "hybrid":  # 如果指定了非默認策略
            effective_config['default_strategy'] = strategy
            
        retriever = UnifiedRetriever(kb, effective_config)
        yield retriever
    finally:
        if retriever:
            retriever.close()
        if kb:
            kb.close()

# 為了向後相容性，添加別名
EnhancedRetriever = UnifiedRetriever

# 導出所需函數和類
__all__ = [
    'KnowledgeBase', 
    'UnifiedRetriever', 
    'EnhancedRetriever',  # 為了向後相容
    'EnhancedReranker',
    'get_retriever', 
    'get_text_from_node'
]