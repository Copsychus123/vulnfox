import asyncio
from contextlib import contextmanager
import logging
import time
import psutil
import numpy as np
import torch
from typing import Dict, List, Optional, Any
from datasets import Dataset, Features, Value, Sequence

try:
    # 嘗試新版 RAGAS 導入方式
    from ragas import evaluate
    from ragas.metrics import faithfulness, answer_relevancy, ContextUtilization
    # 兼容性處理
    context_utilization = ContextUtilization()
    logger = logging.getLogger(__name__)
    logger.info("使用新版 RAGAS API (ContextUtilization 類)")
    RAGAS_VERSION = "new"
except ImportError:
    try:
        # 嘗試舊版 RAGAS 導入方式
        from ragas import evaluate
        from ragas.metrics import faithfulness, answer_relevancy, context_utilization
        logger = logging.getLogger(__name__)
        logger.info("使用舊版 RAGAS API (context_utilization 函數)")
        RAGAS_VERSION = "old"
    except ImportError as e:
        logger = logging.getLogger(__name__)
        logger.error(f"無法導入 RAGAS: {e}")
        RAGAS_VERSION = "unavailable"


class RagasEvaluator:
    """使用 RAGAS 評估模型"""

    def evaluate(self, query: str, answer: str, contexts: List[str]) -> Dict:
        """進行全面評估"""
        ragas_scores = self._evaluate_ragas(query, answer, contexts)
        return ragas_scores
        
    def _evaluate_ragas(self, query: str, answer: str, contexts: List[str]) -> Dict:
        """RAGAS 評估"""
        try:
            if not query or not answer or not contexts:
                logger.warning("RAGAS 評估輸入不完整: 查詢、回答或上下文缺失")
                return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}

            valid_contexts = [ctx for ctx in contexts if isinstance(ctx, str) and ctx.strip()]
            if not valid_contexts:
                logger.warning("RAGAS 評估輸入不完整: 有效上下文為空")
                return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
            
            logger.debug(f"RAGAS 評估: 查詢長度={len(query)}, 回答長度={len(answer)}, 上下文數量={len(valid_contexts)}")
            
            if RAGAS_VERSION == "new":
                dataset = Dataset.from_dict({
                    "question": [query],
                    "answer": [answer],
                    "contexts": [valid_contexts]  # 作為列表的列表傳入
                })
                metrics = [faithfulness, answer_relevancy, context_utilization]
            else:
                contexts_str = "\n".join(valid_contexts)
                dataset = Dataset.from_dict({
                    "question": [query],
                    "answer": [answer],
                    "contexts": [contexts_str]
                }, features=Features({
                    'question': Value('string'),
                    'answer': Value('string'),
                    'contexts': Value('string'),
                }))
                metrics = [faithfulness, answer_relevancy, context_utilization]
            
            logger.debug("開始評估 RAGAS 指標")
            results = evaluate(
                dataset=dataset,
                metrics=metrics
            )
            
            logger.info(f"RAGAS 評估結果: {results}")
            if isinstance(results, dict):
                return results
            else:
                return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
        except Exception as e:
            logger.error(f"RAGAS 評估錯誤 (詳細): {str(e)}", exc_info=True)
            return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}

    def calculate_overall_score(self, scores: Dict) -> float:
        if not scores:
            return 0.0
        values = [v for v in scores.values() if isinstance(v, (int, float))]
        if not values:
            return 0.0
        return sum(values) / len(values)
