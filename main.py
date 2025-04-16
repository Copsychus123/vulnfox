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

import os, io, logging, pandas as pd
from typing import Dict, List, Any, Optional, Callable
from abc import ABC, abstractmethod
import streamlit as st


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

###############################################################################
# Model 部分：CSV 資產載入器定義
###############################################################################
class BaseDataLoader(ABC):
    """資料載入器的基礎抽象類別"""

    @abstractmethod
    def load(self, data_source: Any) -> Dict[str, Any]:
        """載入資料的抽象方法"""
        pass

    @abstractmethod
    def validate(self, data: Dict[str, Any]) -> bool:
        """驗證資料的抽象方法"""
        pass

    @abstractmethod
    def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """轉換資料的抽象方法"""
        pass

class CSVAssetLoader(BaseDataLoader):
    """CSV 資產載入器實作"""

    def __init__(self, required_fields: List[str] = None, transform_func: Optional[Callable] = None):
        # 只要求 CSV 至少包含這五個必要欄位
        self.required_fields = required_fields or ["Host Name", "IP Address", "cpe_os", "cpe_firmware", "cpe_software"]
        self.transform_func = transform_func

    def load(self, file_obj: Any) -> Dict[str, Any]:
        """從文件對象或本地路徑載入 CSV 資料"""
        try:
            if isinstance(file_obj, str):
                abs_path = os.path.abspath(file_obj)
                logger.info(f"嘗試從本地路徑讀取 CSV 檔案：{abs_path}")
                if not os.path.exists(abs_path):
                    raise FileNotFoundError(f"指定的 CSV 檔案不存在：{abs_path}")
                df = pd.read_csv(abs_path)
            elif isinstance(file_obj, (bytes, io.IOBase)):
                df = pd.read_csv(file_obj)
            else:
                df = pd.read_csv(file_obj, encoding='utf-8')

            df.columns = [col.strip() for col in df.columns]
            missing_fields = [field for field in self.required_fields if field not in df.columns]
            if missing_fields:
                raise ValueError(f"CSV 缺少必要欄位: {', '.join(missing_fields)}")

            records = df.to_dict(orient="records")
            result = {"assets": records, "source_type": "csv", "total_count": len(records)}
            if self.validate(result):
                return self.transform(result)
            else:
                raise ValueError("資料驗證失敗")
        except Exception as e:
            logger.error(f"CSV 載入錯誤: {e}")
            st.error(f"讀取 CSV 檔案時發生錯誤：{e}")
            raise

    def validate(self, data: Dict[str, Any]) -> bool:
        """僅檢查必要欄位是否存在（值可為空）"""
        if not data or "assets" not in data or not data["assets"]:
            logger.error("驗證失敗：資料結構不正確或無資產資料")
            return False
        for asset in data["assets"]:
            if not all(field in asset for field in self.required_fields):
                logger.error(f"驗證失敗：資產記錄缺少必要欄位，資產資料：{asset}")
                return False
        return True

    def transform(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """轉換資料格式，其他欄位缺失時以空字串補齊"""
        if self.transform_func:
            return self.transform_func(data)
        transformed_assets = []
        for item in data["assets"]:
            host_name = item.get("Host Name", "").strip()
            ip_address = item.get("IP Address", "").strip()
            asset_id = f"ASSET-{host_name or ip_address}"
            cpe_info = {field: item.get(field, "") for field in ["cpe_os", "cpe_firmware", "cpe_software"]}
            asset_info = {
                "Item": item.get("Item", ""),
                "Host Name": host_name,
                "IP Address": ip_address,
                "Vendor": item.get("Vendor", ""),
                "Model": item.get("Model", ""),
                "Serial No#": item.get("Serial No#", ""),
                "Department": item.get("Department", ""),
                "Service": item.get("Service", ""),
                "Purchase Cost": item.get("Purchase Cost", ""),
                "Maintenance Cost (per year)": item.get("Maintenance Cost (per year)", ""),
                "Maintenance Level": item.get("Maintenance Level", ""),
                "Warranty Start Date": item.get("Warranty Start Date", ""),
                "Warranty End Date": item.get("Warranty End Date", "")
            }
            asset = {
                "asset_id": asset_id,
                "asset_info": asset_info,
                "cpe_info": cpe_info,
                "vulnerabilities": [],
                "raw_vulnerabilities": [],
                "source": "imported_csv"
            }
            transformed_assets.append(asset)
        return {"assets": transformed_assets, "total_count": len(transformed_assets)}

###############################################################################
# 上傳與 MVC 切換：使用 st.empty() 進行內容替換
###############################################################################
def load_app():
    container = st.empty()  # 建立一個佔位容器
    # 檢查是否已有上傳資料
    if "imported_assets" not in st.session_state:
        with container.container():
            st.title("請先上傳 CSV 資產清單")
            st.info("上傳的 CSV 檔案必須包含必要欄位：Host Name、IP Address、cpe_os、cpe_firmware、cpe_software。")
            uploaded_file = st.file_uploader("選擇 CSV 檔案", type=["csv"])
            if uploaded_file:
                try:
                    loader = CSVAssetLoader()
                    result = loader.load(uploaded_file)
                    st.session_state["imported_assets"] = result

                    # 新增：呼叫後端 API，將資產寫入資料庫
                    from core.model import DataModel
                    api_response = DataModel.api_request(
                        endpoint="upload_assets",
                        method="POST",
                        data={"assets": result["assets"]}
                    )

                    if api_response and api_response.get("status") == "success":
                        st.success(api_response.get("message", "成功上傳資產至後端"))
                        # 成功上傳後，清空容器，再自動載入 MVC 主流程
                        container.empty()
                        mvc_view(container)
                    else:
                        raise ValueError(api_response.get("message", "資產上傳失敗"))
                except Exception as e:
                    st.error(f"CSV 資料處理或上傳失敗：{e}")
            else:
                st.warning("請上傳 CSV 檔案以進行後續操作。")
    else:
        mvc_view(container)


def mvc_view(container):
    with container.container():
        st.title("企業漏洞風險管理系統")

        from core.controller import AppController

        controller = AppController()
        controller.handle_tab_click()
        controller.render_sidebar()

        tabs = st.tabs(["系統概覽", "資產管理", "弱點管理", "風險降低", "風險接受"])
        with tabs[0]:
            controller.show_overview()
        with tabs[1]:
            controller.show_asset()
        with tabs[2]:
            controller.show_vuln()
        with tabs[3]:
            controller.show_risk_reduction()
        with tabs[4]:
            controller.show_risk_acceptance()

        if st.session_state.get("current_tab", 0) > 0:

            from core.view import UIView

            UIView.render_tab_navigation(st.session_state["current_tab"])

###############################################################################
# 主程式：根據 session_state 載入上傳或 MVC 視圖
###############################################################################
def main():
    st.set_page_config(
        page_title="企業漏洞風險管理系統",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    try:
        from core.view import UIView
        UIView.load_css()
    except Exception as e:
        logger.warning(f"無法載入 CSS: {e}")

    load_app()

if __name__ == "__main__":
    main()