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


import os, time, logging, asyncio, random
from typing import List, Dict, Any, Optional
from functools import lru_cache
import aisuite as ai
from pymongo import MongoClient
from llama_index.core.schema import Document
from llama_index.core import VectorStoreIndex
from llama_index.core.postprocessor import LLMRerank
from playwright.async_api import async_playwright
from scrapegraphai.graphs import SmartScraperGraph
from llama_index.core.query_engine import RetrieverQueryEngine
from llama_index.core.response_synthesizers import get_response_synthesizer

try:
    from langchain_huggingface import HuggingFaceEmbeddings
except ImportError:
    from langchain_community.embeddings import HuggingFaceEmbeddings

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
ASSET_DB = os.getenv("ASSET_DB", "assets")
KG = os.getenv("KNOWLEDGE", "KG")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "openai:gpt-4o-mini")
USER_AGENTS = os.getenv("USER_AGENTS", "").split(",") if os.getenv("USER_AGENTS") else [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/92.0.4515.131 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/14.1 Safari/605.1.15"
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

RAGAS_AVAILABLE = False
try:
    from datasets import Dataset, Features, Value, Sequence
    import ragas
    from ragas import evaluate
    from ragas.metrics import faithfulness, answer_relevancy
    RAGAS_AVAILABLE = True
    logger.info(f"RAGAS 版本: {getattr(ragas, '__version__', 'unknown')}")
except ImportError as e:
    logger.warning(f"RAGAS 未能匯入: {e}")
except Exception as e:
    logger.warning(f"RAGAS 匯入時發生錯誤: {e}")

try:
    from llama_index.core.postprocessor import ColbertRerank
except ImportError:
    try:
        from llama_index.postprocessor import ColbertRerank
    except ImportError:
        ColbertRerank = None

def get_text_from_node(node: Any) -> str:
    return getattr(node, "text", str(node))

@lru_cache(maxsize=64)
async def scrape_with_playwright(url: str) -> Optional[str]:
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(user_agent=random.choice(USER_AGENTS))
            page = await context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=30000)
            content = await page.content()
            await browser.close()
            return content
    except Exception as e:
        logger.error(f"擷取頁面失敗: {e}")
        return None

@lru_cache(maxsize=32)
def extract_with_smartscraper(url: str) -> Dict:
    prompt = "Extract: cve_id, description, affected_versions, patched_versions, remediation_advice."
    config = {
        "llm": {"api_key": OPENAI_API_KEY, "model": OPENAI_MODEL, "temperature": 0, "max_tokens": 300},
        "verbose": False, "headless": True, "timeout": 30, "retry": 2,
        "user_agent": random.choice(USER_AGENTS),
        "playwright_wait_until": "networkidle"
    }
    try:
        scraper = SmartScraperGraph(prompt=prompt, source=url, config=config)
        return scraper.run() or {}
    except Exception:
        return {}

def merge_vulnerability_data(data_list: List[Dict]) -> Dict:
    merged = {}
    for data in data_list:
        for key, value in data.items():
            if key not in merged or not merged[key]:
                merged[key] = value
            elif isinstance(value, list) and isinstance(merged[key], list):
                merged[key] = list(set(merged[key] + value))
    return merged

async def process_references(references: List[str], limit: int = 3) -> List[Dict]:
    if not references:
        return []
    sem = asyncio.Semaphore(3)
    async def _process_one(url):
        async with sem:
            try:
                return extract_with_smartscraper(url)
            except:
                return {}
    tasks = [_process_one(ref) for ref in references[:limit]]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

class AISuiteClient:
    def __init__(self, api_key=None, model=None):
        self.model = model or OPENAI_MODEL
        if ':' not in self.model:
            self.model = f"openai:{self.model.replace('openai/', '')}"
        self.client = ai.Client()
        os.environ["OPENAI_API_KEY"] = api_key or OPENAI_API_KEY
    async def ainvoke(self, prompt, temperature=0, max_tokens=4000):
        messages = [{"role": "user", "content": prompt}]
        try:
            response = await asyncio.to_thread(
                self.client.chat.completions.create,
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens
            )
            return response.choices[0].message
        except Exception as e:
            logger.error(f"LLM調用錯誤: {e}")
            class FakeResponse:
                def __init__(self, content):
                    self.content = content
            return FakeResponse(f"LLM調用發生錯誤: {e}")

class Evaluator:
    def __init__(self):
        self._ragas_available = RAGAS_AVAILABLE
        self._setup_metrics()
    def _setup_metrics(self):
        if not self._ragas_available:
            return
        try:
            from ragas.metrics import ContextUtilization
            self.context_utilization = ContextUtilization()
            self.ragas_version = "new"
            logger.info("使用新版 RAGAS API (ContextUtilization 類)")
        except ImportError:
            try:
                from ragas.metrics import context_utilization
                self.context_utilization = context_utilization
                self.ragas_version = "old"
                logger.info("使用舊版 RAGAS API (context_utilization 函數)")
            except ImportError:
                self.context_utilization = None
                self.ragas_version = "unavailable"
                logger.warning("無法導入 context_utilization")
    def evaluate(self, query: str, contexts: List[str], answer: str) -> Dict:
        if not query or not answer or not contexts or not self._ragas_available:
            return self._get_default_scores()
        try:
            logger.info(f"開始RAGAS評估，查詢長度: {len(query)}，答案長度: {len(answer)}，上下文數: {len(contexts)}")
            valid_contexts = [ctx for ctx in contexts if isinstance(ctx, str) and ctx.strip()]
            if not valid_contexts:
                logger.warning("RAGAS 評估輸入不完整: 有效上下文為空")
                return self._get_default_scores()
            metrics = [faithfulness, answer_relevancy]
            if self.context_utilization:
                metrics.append(self.context_utilization)
            if self.ragas_version == "new":
                dataset = Dataset.from_dict({
                    "question": [query],
                    "answer": [answer],
                    "contexts": [valid_contexts]
                })
            else:
                contexts_str = "\n".join(valid_contexts)
                dataset = Dataset.from_dict({
                    "question": [query],
                    "answer": [answer],
                    "contexts": [contexts_str]
                }, features=Features({
                    'question': Value('string'),
                    'answer': Value('string'),
                    'contexts': Value('string')
                }))
            results = evaluate(dataset=dataset, metrics=metrics)
            logger.info(f"RAGAS 評估結果: {results}")
            if isinstance(results, dict):
                return results
            else:
                return self._get_default_scores()
        except Exception as e:
            logger.error(f"RAGAS評估過程中發生錯誤: {e}", exc_info=True)
        return self._get_default_scores()
    def _get_default_scores(self) -> Dict:
        return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
    def calculate_overall_score(self, scores: Dict) -> float:
        if not scores:
            return 0.0
        values = [v for v in scores.values() if isinstance(v, (int, float))]
        if not values:
            return 0.0
        return sum(values) / len(values)

class KnowledgeBase:
    def __init__(self, llm=None):
        self.llm = llm if llm else AISuiteClient()
        self.documents: List[Dict] = []
        self.db_available = False
        try:
            self.mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
            self.db = self.mongo_client[ASSET_DB]
            self.collection = self.db[KG]
            self.db_available = True
            logger.info(f"MongoDB連接成功: {MONGODB_URI}")
        except Exception as e:
            logger.error(f"MongoDB連接失敗: {e}")
            self.mongo_client = self.db = self.collection = None
    async def load_from_vuln_data(self, vuln_data: List[Dict[str, Any]]) -> None:
        for vuln in vuln_data:
            cve_id = vuln.get("cve_id")
            if cve_id and self.db_available:
                existing_data = await asyncio.to_thread(self._get_from_mongodb, cve_id)
                if existing_data:
                    self.documents.append(existing_data)
                    continue
            references = vuln.get("references", [])[:3]
            extracted_list = await process_references(references)
            merged_data = merge_vulnerability_data(extracted_list) if extracted_list else {}
            for field in ["cve_id", "description", "base_score", "severity"]:
                if field not in merged_data or not merged_data[field]:
                    merged_data[field] = vuln.get(field)
            self.documents.append(merged_data)
            if self.db_available:
                await asyncio.to_thread(self.save_to_mongodb)
    def _get_from_mongodb(self, cve_id) -> Optional[Dict]:
        if not self.db_available:
            return None
        try:
            if isinstance(cve_id, list) and cve_id:
                cve_id = cve_id[0]
            doc = self.collection.find_one({"_id": cve_id})
            if doc:
                doc_copy = doc.copy()
                if "_id" in doc_copy:
                    del doc_copy["_id"]
                return doc_copy
            if cve_id and isinstance(cve_id, str) and cve_id.startswith("CVE-"):
                pattern = {"$regex": f"^{cve_id}$", "$options": "i"}
                doc = self.collection.find_one({"_id": pattern})
                if doc:
                    doc_copy = doc.copy()
                    if "_id" in doc_copy:
                        del doc_copy["_id"]
                    return doc_copy
            return None
        except Exception as e:
            logger.error(f"從 MongoDB 取得資料錯誤: {e}")
            return None
    def save_to_mongodb(self) -> None:
        if not self.db_available:
            return
        for doc in self.documents:
            try:
                cve = doc.get("cve_id")
                if not cve:
                    continue
                cve_id = cve[0] if isinstance(cve, list) else cve
                doc["_id"] = cve_id
                self.collection.replace_one({"_id": cve_id}, doc, upsert=True)
            except Exception as e:
                logger.error(f"儲存到MongoDB錯誤: {e}")
    def get_documents(self) -> List[Dict]:
        return self.documents

class EnhancedRetriever:
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.index = None
        self.retriever = None
        self.reranker = None
        self.rag_strategy = "colbert"
        self.cache = {}
        self.config = {'rerank_top_n': 5, 'similarity_top_k': 5}
        try:
            self.embeddings = HuggingFaceEmbeddings(model_name="intfloat/multilingual-e5-large")
            self._setup_components()
        except Exception as e:
            logger.error(f"嵌入模型初始化失敗: {e}")
            self.embeddings = None
    def _setup_components(self):
        self._setup_retriever()
        self._setup_synthesizer()
        self._setup_reranker()
    def _setup_retriever(self) -> None:
        try:
            docs = self.kb.get_documents()
            if not docs or not self.embeddings:
                return
            index_docs = [Document(text=str(doc)) for doc in docs]
            self.index = VectorStoreIndex.from_documents(index_docs, embed_model=self.embeddings)
            self.retriever = self.index.as_retriever(similarity_top_k=self.config['similarity_top_k'])
        except Exception as e:
            logger.error(f"設置檢索器錯誤: {e}")
            self.index = self.retriever = None
    def _setup_reranker(self) -> None:
        try:
            if ColbertRerank:
                self.reranker = ColbertRerank(top_n=self.config['rerank_top_n'])
            else:
                self.reranker = LLMRerank(choice_batch_size=5, top_n=self.config['rerank_top_n'])
        except Exception as e:
            logger.error(f"設置重排序器錯誤: {e}")
            self.reranker = None
    def _setup_synthesizer(self):
        try:
            self.synthesizer = get_response_synthesizer(response_mode="compact")
        except Exception as e:
            logger.error(f"設置回應合成器失敗: {e}")
            self.synthesizer = None
    def retrieve(self, query: str) -> List[Any]:
        if not self.retriever:
            return []
        if query in self.cache:
            return self.cache[query]
        try:
            nodes = self._colbert_strategy(query)
            if nodes:
                self.cache[query] = nodes
            return nodes
        except Exception as e:
            logger.error(f"檢索錯誤: {e}")
            return []
    def _colbert_strategy(self, query: str) -> List[Any]:
        try:
            if self.retriever and self.reranker and self.synthesizer:
                engine = RetrieverQueryEngine(
                    retriever=self.retriever,
                    node_postprocessors=[self.reranker],
                    response_synthesizer=self.synthesizer
                )
                response = engine.query(query)
                if hasattr(response, 'source_nodes'):
                    return response.source_nodes
            return self.retriever.retrieve(query) if self.retriever else []
        except Exception as e:
            return self.retriever.retrieve(query) if self.retriever else []
    def close(self) -> None:
        self.cache.clear()
        self.index = self.retriever = self.reranker = None

class RAGProcessor:
    def __init__(self, knowledge_base: KnowledgeBase):
        self.kb = knowledge_base
        self.retriever = EnhancedRetriever(knowledge_base)
        self.evaluator = Evaluator()
    def _generate_prompt(self, contexts: List[str]) -> str:
        return f"""
You are an experienced cybersecurity expert. Based on the following information, please provide professional vulnerability remediation recommendations:
Context:
{contexts}

Please provide detailed information on the following aspects:

Vulnerability Overview: Briefly describe the nature and impact of this vulnerability.
Affected Systems: List all potentially affected systems, applications, or product versions.
Vulnerability Impact: Provide a detailed explanation of the potential consequences and damages if the vulnerability is exploited.
Remediation Steps: Offer clear and specific remediation methods and steps (if an official patch is available, please include update instructions).
Temporary Mitigation Measures: If immediate remediation is not possible, suggest feasible risk mitigation strategies.
Priority and Timeline: Recommend the remediation priority and a proposed timeframe.
Please respond in Traditional Chinese.
"""
    async def generate_remediation(self, vuln_data: Dict) -> Dict[str, Any]:
        start_time = time.time()
        try:
            query = f"tell me about {vuln_data.get('cve_id', 'N/A')}, what can i fix it?"
            nodes = self.retriever.retrieve(query)
            contexts = [get_text_from_node(n) for n in nodes if get_text_from_node(n)]
            rag_strategy = self.retriever.rag_strategy
            if not contexts:
                contexts = [
                    f"cve: {vuln_data.get('cve_id', 'N/A')}",
                    f"description: {vuln_data.get('description', '')}",
                    f"severity: {vuln_data.get('severity', '')}"
                ]
                rag_strategy = "直接使用漏洞資訊"
            prompt = self._generate_prompt(contexts)
            response = await self.kb.llm.ainvoke(prompt)
            answer = response.content if hasattr(response, "content") else str(response)
            try:
                from datasets import Dataset, Features, Value, Sequence
                from ragas import evaluate
                valid_contexts = [ctx for ctx in contexts if isinstance(ctx, str) and ctx.strip()]
                dataset = Dataset.from_dict({
                    "question": [query],
                    "answer": [answer],
                    "contexts": [valid_contexts]
                })
                from ragas.metrics import faithfulness, answer_relevancy
                metrics = [faithfulness, answer_relevancy]
                try:
                    try:
                        from ragas.metrics import ContextUtilization
                        context_utilization = ContextUtilization()
                        metrics.append(context_utilization)
                    except ImportError:
                        try:
                            from ragas.metrics import context_utilization
                            metrics.append(context_utilization)
                        except ImportError:
                            pass
                except Exception as e:
                    logger.warning(f"無法加載 context_utilization: {e}")
                ragas_results = evaluate(dataset=dataset, metrics=metrics)
                result_string = str(ragas_results)
                logger.info(f"RAGAS 評估原始結果: {result_string}")
                import re
                faithfulness_match = re.search(r"faithfulness['\"]*\s*[:=]\s*([\d\.]+)", result_string)
                answer_relevancy_match = re.search(r"answer_relevancy['\"]*\s*[:=]\s*([\d\.]+)", result_string)
                context_utilization_match = re.search(r"context_utilization['\"]*\s*[:=]\s*([\d\.]+)", result_string)
                faithfulness_score = float(faithfulness_match.group(1)) if faithfulness_match else 0.0
                answer_relevancy_score = float(answer_relevancy_match.group(1)) if answer_relevancy_match else 0.0
                context_utilization_score = float(context_utilization_match.group(1)) if context_utilization_match else 0.0
                logger.info(f"從字符串提取的評估分數: 忠實度={faithfulness_score}, 回答相關性={answer_relevancy_score}, 上下文利用率={context_utilization_score}")
                evaluation_results = {
                    "faithfulness": faithfulness_score,
                    "answer_relevancy": answer_relevancy_score,
                    "context_utilization": context_utilization_score
                }
            except Exception as e:
                logger.error(f"評估過程出錯: {e}", exc_info=True)
                evaluation_results = {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
            faithfulness = evaluation_results.get('faithfulness', 0.0)
            answer_relevancy = evaluation_results.get('answer_relevancy', 0.0)
            context_utilization = evaluation_results.get('context_utilization', 0.0)
            execution_time = round(time.time() - start_time, 3)
            metrics_values = [v for v in [faithfulness, answer_relevancy, context_utilization] if v > 0]
            overall_score = sum(metrics_values) / len(metrics_values) if metrics_values else 0.0
            logger.info(f"最終評估指標: faithfulness={faithfulness}, answer_relevancy={answer_relevancy}, context_utilization={context_utilization}")
            result = {
                "recommendation": answer,
                "query": query,
                "contexts": contexts,
                "rag_strategy": rag_strategy,
                "evaluation": evaluation_results,
                "overall_score": round(overall_score, 4),
                "time_used": execution_time,
                "faithfulness": faithfulness,
                "answer_relevancy": answer_relevancy,
                "context_utilization": context_utilization
            }
            return result
        except Exception as e:
            logger.error(f"生成修補建議失敗: {e}", exc_info=True)
            return {
                "recommendation": f"生成修補建議失敗: {e}",
                "query": vuln_data.get('cve_id', 'N/A'),
                "contexts": [],
                "rag_strategy": "生成失敗",
                "evaluation": {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0},
                "overall_score": 0.0,
                "time_used": round(time.time() - start_time, 3),
                "faithfulness": 0.0,
                "answer_relevancy": 0.0,
                "context_utilization": 0.0
            }
    def close(self) -> None:
        if self.retriever:
            self.retriever.close()

async def generate_vulnerability_remediation(vuln_data: Dict, api_key: str = None, model: str = None, temperature: float = None, max_tokens: int = None) -> Dict:
    start_time = time.time()
    try:
        model_name = model or OPENAI_MODEL
        temp = temperature if temperature is not None else 0
        tokens = max_tokens if max_tokens is not None else 4000
        llm = AISuiteClient(api_key=api_key, model=model_name)
        kb = KnowledgeBase(llm=llm)
        await kb.load_from_vuln_data([vuln_data])
        processor = RAGProcessor(kb)
        try:
            return await processor.generate_remediation(vuln_data)
        finally:
            processor.close()
    except Exception as e:
        logger.error(f"生成錯誤: {e}")
        return {
            "recommendation": f"生成修補建議時發生錯誤: {e}",
            "query": vuln_data.get('cve_id', 'N/A'),
            "contexts": [],
            "rag_strategy": "生成失敗",
            "evaluation": {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0},
            "overall_score": 0.0,
            "time_used": round(time.time() - start_time, 3),
            "faithfulness": 0.0,
            "answer_relevancy": 0.0,
            "context_utilization": 0.0
        }

if __name__ == "__main__":
    sample_vuln = {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 存在漏洞，可能被攻擊者利用進行遠程代碼執行。",
        "base_score": 10.0,
        "severity": "Critical",
        "product": "Apache Log4j",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"
        ]
    }
    result = asyncio.run(generate_vulnerability_remediation(sample_vuln))
    print(f"\n=== 漏洞修補建議 (耗時: {result.get('time_used', '?')} 秒) ===")
    print(result["recommendation"])
    print("\n=== 評估結果 ===")
    print(f"整體評分: {result['overall_score']}")
    print(f"忠實度: {result['faithfulness']}")
    print(f"回答相關性: {result['answer_relevancy']}")
    print(f"上下文利用率: {result['context_utilization']}")
    print(f"查詢: {result.get('query', '')}")

    print("\n上下文:")
    for i, ctx in enumerate(result.get("contexts", []), 1):
        print(f"  {i}. {ctx}")
