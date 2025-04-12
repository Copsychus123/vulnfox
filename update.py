import os, gc, psutil, asyncio, logging
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import dateutil.parser


from collectors.api_collector import APICollector
from collectors.core.db import DatabaseManager
from collectors.json_collector import JSONCollector
from collectors.rss_collector import RSSCollector

from services.vector_store import VectorStore, InitMode, ResourceConfig

# 載入環境變數
load_dotenv()

# 設定日誌格式與級別
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def parse_date_safely(date_value):
    """
    安全解析日期，返回 timezone-aware 的 datetime 對象，若無法解析則返回 None。
    如果解析結果為 naive，則假設為 UTC。
    """
    if not date_value:
        return None
    if isinstance(date_value, datetime):
        if date_value.tzinfo is None:
            return date_value.replace(tzinfo=timezone.utc)
        return date_value
    if isinstance(date_value, str):
        try:
            # 嘗試解析 ISO 格式
            dt = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception as e:
            try:
                # 使用 dateutil 解析其他格式
                dt = dateutil.parser.parse(date_value)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception as e:
                logger.debug(f"日期解析失敗 '{date_value}': {e}")
                return None
    return None

async def run_collectors(db_manager: DatabaseManager) -> bool:
    """
    並行調用 API、JSON 和 RSS 收集器，
    利用 asyncio.create_task 與 asyncio.to_thread 將同步收集方法放入線程池中執行。
    """
    logger.info("開始並行數據收集（API, JSON, RSS）")
    collectors = [
        APICollector(db_manager),
        JSONCollector(db_manager),
        RSSCollector(db_manager)
    ]
    tasks = [asyncio.create_task(asyncio.to_thread(col.update_data)) for col in collectors]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for idx, result in enumerate(results):
        if isinstance(result, Exception) or not result:
            logger.error(f"{collectors[idx].__class__.__name__} 收集器失敗：{result}")
    return all(not isinstance(result, Exception) and result for result in results)

async def integrate_data(db_manager: DatabaseManager) -> bool:
    """通過調用 all_view 完成數據整合工作 """
    logger.info("開始調用 all_view 進行數據整合...")
    try:
        db_manager.all_view()  # 直接調用 all_view 完成數據整合
        logger.info("數據整合完成")
        return True
    except Exception as e:
        logger.error(f"數據整合失敗: {e}")
        return False

async def run_vector_store() -> bool:
    """
    從 MongoDB 的 all 集合中讀取所有記錄，
    使用 parse_date_safely 取得 published 日期後，僅保留三年內的文檔，
    並完成向量化與批次上傳。
    """
    try:
        logger.info("開始向量處理（僅針對 all 集合且只檢查 published 日期）")
        data_lake_path = os.getenv("DATA_LAKE_PATH", "./data_lake")
        init_mode = os.getenv("INIT_MODE", "incremental")
        if not os.path.exists(data_lake_path):
            logger.info(f"{data_lake_path} 不存在，切換為 initialize 模式")
            init_mode = InitMode.INITIALIZE.value
            os.makedirs(data_lake_path, exist_ok=True)
        
        # 初始化向量存儲系統
        vector_store = VectorStore(data_path=data_lake_path, init_mode=init_mode)
        ResourceConfig.COLLECTIONS["all"] = {"collection": "all"}
        collections = vector_store.chroma_client.list_collections()
        logger.info(f"ChromaDB 現有集合: {collections}")
        if "all" not in collections:
            logger.info("創建 all 集合向量存儲")
            vector_store.chroma_client.create_collection(name="all")
            vector_store.collections["all"] = vector_store.chroma_client.get_collection(name="all")
            vector_store.collection_naming["all"] = "all"
        
        # 檢查並初始化嵌入模型（若尚未初始化）
        if vector_store.embedding_model is None:
            logger.info("嵌入模型尚未初始化，開始初始化嵌入模型...")
            vector_store.embedding_model = vector_store._init_embedding_model()
            if vector_store.embedding_model is None:
                logger.error("錯誤：嵌入模型初始化失敗，無法生成向量。")
                return False
        
        # 計算三年前的日期（使用 timezone-aware）
        three_years_ago = datetime.now(timezone.utc) - timedelta(days=365*3)
        logger.info(f"三年前的日期為: {three_years_ago.isoformat()}")
        
        # 從 all 集合中讀取所有記錄後進行過濾
        logger.info("從 all 集合中讀取所有文檔...")
        all_docs = list(vector_store.db["all"].find())
        logger.info(f"從 all 集合中讀取到 {len(all_docs)} 條記錄")
        
        filtered_docs = []
        no_date_docs = recent_docs = old_docs = 0
        for doc in all_docs:
            published_date = parse_date_safely(doc.get("published"))
            if published_date is None:
                no_date_docs += 1
                continue
            if published_date >= three_years_ago:
                recent_docs += 1
                filtered_docs.append(doc)
            else:
                old_docs += 1
        
        logger.info(
            f"過濾統計: 總記錄 {len(all_docs)}，過濾後得到 {len(filtered_docs)} 條紀錄"
        )
        
        if filtered_docs:
            sample_size = min(3, len(filtered_docs))
            logger.info(f"隨機 {sample_size} 條記錄樣例:")
            for i in range(sample_size):
                sample_doc = filtered_docs[i]
                last_date = sample_doc.get("last_modified")
                logger.info(f"  - CVE ID: {sample_doc.get('cve_id')}, 發布日期: {last_date}")
            
            process_limit = int(os.getenv("PROCESS_LIMIT", "0"))
            if process_limit > 0:
                logger.info(f"限制處理文檔數為 {process_limit} 條")
                filtered_docs = filtered_docs[:process_limit]
            
            batch_size = 50
            for i in range(0, len(filtered_docs), batch_size):
                batch = filtered_docs[i:i+batch_size]
                tasks = [vector_store.process_document(doc, "all") for doc in batch]
                results = await asyncio.gather(*tasks)
                success_count = sum(1 for r in results if r)
                logger.info(f"批次處理進度：{i+len(batch)}/{len(filtered_docs)}，成功 {success_count}/{len(batch)}")
            
            doc_ids = [doc["_id"] for doc in filtered_docs if "_id" in doc]
            if doc_ids:
                vector_store.db["all"].update_many({"_id": {"$in": doc_ids}}, {"$set": {"indexed": True}})
            logger.info("文檔向量化處理完成")
        else:
            logger.info("無符合條件的文檔需要向量化")
        
        await vector_store.close()
        return True
    except Exception as e:
        logger.error(f"向量處理錯誤: {e}")
        return False

async def main_async():
    logger.info("程式開始執行")
    db_manager = DatabaseManager()
    try:
        if not db_manager.test_connection():
            raise Exception("數據庫連接失敗")
        
        # if os.getenv("RUN_COLLECTION", "true").lower() == "true":
        #     logger.info("開始數據收集")
        #     if await run_collectors(db_manager):
        #         logger.info("數據收集成功")
        #     else:
        #         logger.warning("數據收集過程中發生錯誤")
        
        if os.getenv("RUN_INTEGRATION", "true").lower() == "true":
            logger.info("開始數據整合")
            if await integrate_data(db_manager):
                logger.info("數據整合成功")
            else:
                logger.error("數據整合失敗")
        
        # if os.getenv("RUN_VECTOR", "true").lower() == "true":
        #     logger.info("開始向量處理")
        #     if await run_vector_store():
        #         logger.info("向量處理成功")
        #     else:
        #         logger.error("向量處理失敗")
        
        gc.collect()
        logger.info(f"記憶體使用：{psutil.Process().memory_info().rss / 1024 / 1024:.2f} MB")
        logger.info("所有任務執行完成")
    except Exception as e:
        logger.error(f"程式執行失敗: {e}")
    finally:
        db_manager.close()
        logger.info("程式結束執行")

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        logger.info("程式被用戶中斷")
    except Exception as e:
        logger.error(f"程序運行失敗: {e}")

if __name__ == "__main__":
    main()
