import asyncio
from contextlib import contextmanager
import logging
import time
import psutil
import numpy as np
import torch
from typing import Dict, List, Optional, Any
from datasets import Dataset, Features, Value, Sequence

# 修正 RAGAS 導入 - 使用 try/except 處理不同版本
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
        # 無法導入 RAGAS
        logger = logging.getLogger(__name__)
        logger.error(f"無法導入 RAGAS: {e}")
        RAGAS_VERSION = "unavailable"

from transformers import RobertaTokenizer, RobertaForSequenceClassification

class QueryResourceMonitor:
    """精確的查詢資源監控器"""
    
    def __init__(self):
        """初始化監控器"""
        self.process = psutil.Process()
        self.reset()

    def reset(self):
        """重置所有監控數據"""
        self._start_time = None
        self._end_time = None
        self._start_memory = None
        self._end_memory = None
        self._cpu_percent = None
        self._cpu_samples = []
        self._is_monitoring = False

    @contextmanager
    def monitor_query(self):
        """使用上下文管理器監控單個查詢的資源使用"""
        try:
            self.start_monitoring()
            yield
        finally:
            self.stop_monitoring()

    def start_monitoring(self):
        """開始監控"""
        self.reset()
        self._is_monitoring = True
        self._start_time = time.time()
        
        # 強制進行一次 CPU 採樣以重置計數器
        psutil.cpu_percent()
        time.sleep(0.1)  # 短暫等待以獲得有效的 CPU 讀數
        
        # 記錄初始狀態
        self._start_memory = self.process.memory_info().rss / (1024 * 1024)
        self._cpu_samples = []
        self.sample_resources()  # 第一次採樣

    def stop_monitoring(self):
        """停止監控"""
        if self._is_monitoring:
            self.sample_resources()  # 最後一次採樣
            self._end_time = time.time()
            self._end_memory = self.process.memory_info().rss / (1024 * 1024)
            self._is_monitoring = False

    def sample_resources(self):
        """採樣當前資源使用情況"""
        if self._is_monitoring:
            try:
                cpu_percent = psutil.cpu_percent()
                if cpu_percent is not None:
                    self._cpu_samples.append(cpu_percent)
            except Exception as e:
                logger.error(f"資源採樣錯誤: {str(e)}")

    async def continuous_sampling(self, interval: float = 0.1):
        """持續採樣資源使用情況"""
        while self._is_monitoring:
            self.sample_resources()
            await asyncio.sleep(interval)

    def get_usage(self) -> Dict:
        """獲取資源使用統計"""
        if not self._start_time:
            logger.warning("在開始監控前嘗試獲取資源使用情況")
            return self._get_default_metrics()

        try:
            # 確保有結束時間
            if not self._end_time:
                self.stop_monitoring()

            # 計算平均 CPU 使用率
            valid_samples = [sample for sample in self._cpu_samples if sample is not None]
            avg_cpu = sum(valid_samples) / len(valid_samples) if valid_samples else 0

            # 計算記憶體變化
            memory_used = self._end_memory - self._start_memory
            
            # 計算總時間
            total_time = self._end_time - self._start_time

            metrics = {
                "Memory Used (MB)": round(memory_used, 2),
                "CPU Percent": round(avg_cpu, 2),
                "Total Time (s)": round(total_time, 3)
            }

            logger.debug(f"資源使用指標: {metrics}")
            return metrics

        except Exception as e:
            logger.error(f"計算資源使用指標時發生錯誤: {str(e)}")
            return self._get_default_metrics()

    def _get_default_metrics(self) -> Dict:
        """返回預設的指標數據"""
        return {
            "Memory Used (MB)": 0.0,
            "CPU Percent": 0.0,
            "Total Time (s)": 0.0
        }

class SimpleResourceMonitor:
    """簡單的資源監控器（供環境不支援時使用）"""
    
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
    
class MetricsCalculator:
    @staticmethod
    def calculate_metrics(raw_metrics: Dict, resource_usage: Dict) -> Dict[str, float]:
        """計算性能指標"""
        try:
            total_duration = max(
                float(raw_metrics.get("end_time", 0)) - float(raw_metrics.get("start_time", 0)), 
                0.001
            )
            
            def estimate_tokens(text: str) -> int:
                if not text:
                    return 0
                words = len(text.split())
                chinese_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff')
                english_chars = sum(1 for c in text if c.isascii() and c.isprintable())
                return max(1, words + chinese_chars + (english_chars - words * 4) // 4)
            
            prompt_tokens = estimate_tokens(str(raw_metrics.get("prompt", "")))
            response_tokens = estimate_tokens(str(raw_metrics.get("response_text", "")))
            tokens_per_second = (prompt_tokens + response_tokens) / total_duration
            
            return {
                "total_duration_s": round(total_duration, 4),
                "prompt_eval_count": int(prompt_tokens),
                "response_eval_count": int(response_tokens),
                "tokens_per_second": round(tokens_per_second, 4),
                "efficiency_score": round(1.0 / (1.0 + total_duration), 4)
            }
        except Exception as e:
            logger.error(f"指標計算錯誤: {e}")
            return {
                "total_duration_s": 0.0,
                "prompt_eval_count": 0,
                "response_eval_count": 0,
                "tokens_per_second": 0.0,
                "efficiency_score": 0.0
            }

class SimpleMetricsCalculator:
    @staticmethod
    def calculate_metrics(raw_metrics: Dict, resource_usage: Dict) -> Dict[str, float]:
        """簡易版指標計算（無需估計 token 量）"""
        try:
            total_duration = max(
                float(raw_metrics.get("end_time", 0)) - float(raw_metrics.get("start_time", 0)), 
                0.001
            )
            
            return {
                "total_duration_s": round(total_duration, 4),
                "efficiency_score": round(1.0 / (1.0 + total_duration), 4)
            }
        except Exception as e:
            logger.error(f"簡易指標計算錯誤: {e}")
            return {
                "total_duration_s": 0.0,
                "efficiency_score": 0.0
            }

class RagasEvaluator:
    """使用 RAGAS 評估模型"""
    
    def __init__(self):
        try:
            # 測試 RAGAS 是否可用
            self._test_ragas_availability()
            logger.info("RAGAS 評估器初始化成功")
        except Exception as e:
            logger.error(f"RAGAS 評估器初始化失敗: {e}")
            raise

    def _test_ragas_availability(self):
        """測試 RAGAS 可用性"""
        if RAGAS_VERSION == "unavailable":
            raise ImportError("RAGAS 無法導入")
            
        # 測試 RAGAS 功能
        try:
            # 創建一個簡單的測試數據集
            test_dataset = Dataset.from_dict({
                "question": ["測試問題"],
                "answer": ["測試回答"],
                "contexts": [["測試上下文"]]
            })
            
            # 根據 RAGAS 版本選擇評估方式
            if RAGAS_VERSION == "new":
                metrics = [faithfulness, answer_relevancy, context_utilization]
            else:
                metrics = [faithfulness, answer_relevancy, context_utilization]
                
            # 確保可以調用 evaluate 函數
            _ = evaluate(
                dataset=test_dataset,
                metrics=metrics
            )
            logger.info("RAGAS 測試成功")
        except Exception as e:
            logger.error(f"RAGAS 測試失敗: {e}")
            raise

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

            # 過濾空上下文
            valid_contexts = [ctx for ctx in contexts if isinstance(ctx, str) and ctx.strip()]
            if not valid_contexts:
                logger.warning("RAGAS 評估輸入不完整: 有效上下文為空")
                return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}
            
            logger.debug(f"RAGAS 評估: 查詢長度={len(query)}, 回答長度={len(answer)}, 上下文數量={len(valid_contexts)}")
            
            # 根據 RAGAS 版本選擇正確的評估方式
            if RAGAS_VERSION == "new":
                # 新版 RAGAS API
                dataset = Dataset.from_dict({
                    "question": [query],
                    "answer": [answer],
                    "contexts": [valid_contexts]  # 作為列表的列表傳入
                })
                metrics = [faithfulness, answer_relevancy, context_utilization]
            else:
                # 舊版 RAGAS API
                # 將上下文合併為單一字串
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
            
            # 處理結果
            scores = {}
            for name, score in results.items():
                if isinstance(score, (list, np.ndarray)):
                    scores[name] = round(float(score[0]), 4)
                else:
                    scores[name] = round(float(score), 4)
            
            logger.info(f"處理後的 RAGAS 分數: {scores}")
            return scores
        except Exception as e:
            logger.error(f"RAGAS 評估錯誤 (詳細): {str(e)}", exc_info=True)
            return {"faithfulness": 0.0, "answer_relevancy": 0.0, "context_utilization": 0.0}

    def calculate_overall_score(self, scores: Dict) -> float:
        """計算整體評分"""
        if not scores:
            return 0.0
        
        # 計算均值
        values = [v for v in scores.values() if isinstance(v, (int, float))]
        if not values:
            return 0.0
        return sum(values) / len(values)

class SimpleEvaluator:
    """簡易評估器（供環境不支援 RAGAS 時使用）"""
    
    def __init__(self):
        logger.info("簡易評估器初始化成功")
        
    def _evaluate_ragas(self, query: str, answer: str, contexts: List[str]) -> Dict:
        """模擬 RAGAS 評估"""
        # 簡單檢查函數
        def check_faithfulness():
            if not answer or not contexts:
                return 0.0
            # 簡單檢查答案是否包含上下文關鍵詞
            context_words = set()
            for ctx in contexts:
                context_words.update([w.lower() for w in ctx.split() if len(w) > 3])
            
            answer_words = set([w.lower() for w in answer.split() if len(w) > 3])
            
            if not context_words:
                return 0.5
                
            overlap = len(context_words.intersection(answer_words))
            return min(1.0, overlap / (len(context_words) * 0.3))
            
        def check_relevancy():
            if not query or not answer:
                return 0.0
                
            query_words = set([w.lower() for w in query.split() if len(w) > 3])
            answer_words = set([w.lower() for w in answer.split() if len(w) > 3])
            
            if not query_words:
                return 0.5
                
            overlap = len(query_words.intersection(answer_words))
            return min(1.0, overlap / (len(query_words) * 0.5))
            
        def check_utilization():
            if not contexts or not answer:
                return 0.0
                
            total_ctx_len = sum(len(ctx) for ctx in contexts)
            if total_ctx_len == 0:
                return 0.5
                
            # 簡單基於文本長度比例估計利用率
            ratio = min(1.0, len(answer) / (total_ctx_len * 0.2))
            return ratio
        
        return {
            "faithfulness": round(check_faithfulness(), 4),
            "answer_relevancy": round(check_relevancy(), 4),
            "context_utilization": round(check_utilization(), 4),
        }
        
    def evaluate(self, query: str, answer: str, contexts: List[str]) -> Dict:
        """進行簡單評估"""
        return self._evaluate_ragas(query, answer, contexts)
    
    def calculate_overall_score(self, scores: Dict) -> float:
        """計算整體評分"""
        if not scores:
            return 0.0
        
        return sum(scores.values()) / len(scores)

# 測試 RAGAS 可用性的函數
def test_ragas_availability():
    """測試 RAGAS 是否可用，返回 True 表示可用，False 表示不可用"""
    if RAGAS_VERSION == "unavailable":
        logger.warning("RAGAS 模組不可用")
        return False
        
    try:
        # 創建一個簡單的測試數據集
        test_dataset = Dataset.from_dict({
            "question": ["測試問題"],
            "answer": ["測試回答"],
            "contexts": [["測試上下文"]] if RAGAS_VERSION == "new" else ["測試上下文"]
        })
        
        # 根據 RAGAS 版本選擇評估方式
        if RAGAS_VERSION == "new":
            metrics = [faithfulness, answer_relevancy, context_utilization]
        else:
            metrics = [faithfulness, answer_relevancy, context_utilization]
            
        # 嘗試執行評估
        result = evaluate(
            dataset=test_dataset,
            metrics=metrics
        )
        
        # 檢查結果是否有效
        if result:
            logger.info(f"RAGAS 測試成功: {result}")
            return True
        else:
            logger.warning(f"RAGAS 測試結果無效: {result}")
            return False
    except Exception as e:
        logger.error(f"RAGAS 測試失敗: {str(e)}", exc_info=True)
        return False

# 在模組載入時測試 RAGAS 可用性
RAGAS_AVAILABLE = test_ragas_availability()
logger.info(f"RAGAS 可用性: {'可用' if RAGAS_AVAILABLE else '不可用'}")