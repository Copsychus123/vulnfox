import streamlit as st
import pandas as pd
import altair as alt
from typing import Dict, List, Optional, Any

SEVERITY_CLASSES = {
    "關鍵": "severity-critical",
    "高風": "severity-high", 
    "中風": "severity-medium",
    "低風": "severity-low"
}

class UIView:
    """視圖類，負責所有界面顯示相關功能"""
    
    @staticmethod
    def load_css():
        if 'css_loaded' not in st.session_state:
            st.markdown("""
            <style>
            /* 卡片樣式 */
            .dashboard-card {
                padding: 1rem;
                border-radius: 10px;
                background-color: #2C2C2C; 
                margin-bottom: 1rem;
                transition: transform 0.3s ease, box-shadow 0.3s ease;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.5);
                height: 100%;
                display: flex;
                flex-direction: column;
                cursor: pointer;
            }
            .dashboard-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 6px 12px rgba(0, 0, 0, 0.7);
                background-color: #3A3A3A; 
            }
            .dashboard-card h3 {
                margin-top: 0;
                color: #90CAF9; 
                font-size: 1.2rem;
                border-bottom: 2px solid #1E88E5;
                padding-bottom: 0.5rem;
                margin-bottom: 0.8rem;
            }
            .dashboard-card .metric {
                font-size: 2rem;
                font-weight: bold;
                margin: 0.5rem 0;
                color: #E0E0E0; 
            }
            .dashboard-card p {
                margin: 0.3rem 0;
                color: #BDBDBD;
            }
            .dashboard-card .footer {
                color: #90CAF9;
                margin-top: auto;
                font-weight: 500;
                border-top: 1px solid #424242;
                padding-top: 0.5rem;
                text-align: right;
            }
            /* 表格樣式 */
            .vuln-table {
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
            }
            .vuln-table th {
                background-color: #1e1e1e;
                color: white;
                padding: 8px;
                text-align: left;
                border: 1px solid #ddd;
            }
            .vuln-table td {
                padding: 8px;
                border: 1px solid #ddd;
            }
            .vuln-table tr:nth-child(even) {
                background-color: #2a2a2a;
            }
            .vuln-table tr:hover {
                background-color: #3a3a3a;
            }
            /* 嚴重性標籤樣式 */
            .severity-critical {
                background-color: #d62728;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
                display: inline-block;
                min-width: 70px;
                text-align: center;
            }
            .severity-high {
                background-color: #ff7f0e;
                color: white;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
                display: inline-block;
                min-width: 70px;
                text-align: center;
            }
            .severity-medium {
                background-color: #ffbb78;
                color: black;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
                display: inline-block;
                min-width: 70px;
                text-align: center;
            }
            .severity-low {
                background-color: #98df8a;
                color: black;
                padding: 3px 8px;
                border-radius: 4px;
                font-weight: bold;
                display: inline-block;
                min-width: 70px;
                text-align: center;
            }
            /* SLA 標籤樣式 */
            .sla-normal { color: #2ca02c; font-weight: bold; }
            .sla-overdue { color: #d62728; font-weight: bold; }
            /* 文字顏色 */
            .critical-text { color: #F44336; font-weight: bold; }
            .high-text { color: #FF9800; font-weight: bold; }
            .medium-text { color: #FFC107; }
            .low-text { color: #8BC34A; }
            /* 詳情區塊 */
            .detail-section {
                background-color: #2a2a2a;
                border-radius: 8px;
                padding: 15px;
                margin-top: 20px;
            }
            /* 工具列按鈕 */
            .tool-button {
                margin-right: 5px;
                background-color: #333;
                color: white;
                border: none;
                padding: 5px 10px;
                cursor: pointer;
            }
            /* 表格容器 */
            .table-container {
                max-height: 500px;
                overflow-y: auto;
                margin-bottom: 20px;
            }
            /* 漏洞篩選區域 */
            .filter-container {
                background-color: #2a2a2a;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 15px;
            }
            /* 標籤頁樣式 */
            .stTabs [data-baseweb="tab-list"] {
                gap: 10px;
            }
            .stTabs [data-baseweb="tab"] {
                background-color: #2a2a2a;
                border-radius: 4px 4px 0 0;
                padding: 5px 15px;
                font-weight: 500;
            }
            .stTabs [aria-selected="true"] {
                background-color: #3a3a3a;
                border-bottom: 3px solid #1E88E5;
            }
            /* 修補建議區域樣式 */
            .remediation-section {
                background-color: #2a2a2a;
                border-radius: 8px;
                padding: 15px;
                margin-top: 20px;
                border-left: 4px solid #4CAF50;
            }
            .remediation-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid #424242;
                padding-bottom: 8px;
                margin-bottom: 15px;
            }
            .remediation-body {
                padding: 0 10px;
                font-size: 0.95rem;
                line-height: 1.5;
            }
            .remediation-section h1, 
            .remediation-section h2, 
            .remediation-section h3 {
                color: #90CAF9;
            }
            .remediation-section ul {
                margin-bottom: 15px;
            }
            /* RAGAS 指標區域 */
            .ragas-metrics {
                padding: 10px;
                background-color: #333;
                border-radius: 5px;
                margin-bottom: 15px;
            }
            </style>
            """, unsafe_allow_html=True)
            st.session_state.css_loaded = True

    @staticmethod
    def display_metric_cards(metrics: List[Dict]) -> None:
        cols = st.columns(len(metrics))
        for i, metric in enumerate(metrics):
            with cols[i]:
                card_key = f"card_{i}"
                st.markdown(f"""
                <div class="dashboard-card" id="{card_key}"
                    onclick="
                        window.parent.postMessage({{
                            type: 'streamlit:setComponentValue',
                            value: {metric.get('tab_index', i+1)},
                            dataType: 'number',
                            key: 'clicked_card'
                        }}, '*');
                    ">
                    <h3>{metric['title']}</h3>
                    <div class="metric">{metric['value']}</div>
                    {metric.get('content', '')}
                </div>
                """, unsafe_allow_html=True)

    @staticmethod
    def display_vuln_table(data: List[Dict], columns: List[str]) -> None:
        if not data:
            st.warning("沒有符合條件的漏洞")
            return
        display_data = []
        for v in data:
            severity_text = v.get("弱點嚴重度", "")
            severity_class = next((SEVERITY_CLASSES[key] for key in SEVERITY_CLASSES if key in severity_text), "")
            sla_class = "sla-overdue" if v.get("SLA") == "超時" else "sla-normal"
            row = {}
            for col in columns:
                if col == "弱點嚴重度":
                    row[col] = f'<span class="{severity_class}">{severity_text}</span>'
                elif col == "SLA":
                    row[col] = f'<span class="{sla_class}">{v.get(col, "N/A")}</span>'
                elif col == "弱點ID":
                    cve = v.get(col, "")
                    row[col] = f'<a href="#" onclick="window.parent.postMessage({{type: \'streamlit:setComponentValue\', value: \'{cve}\', dataType: \'string\', key: \'selected_cve\'}}, \'*\'); return false;">{cve}</a>'
                else:
                    row[col] = v.get(col, "N/A")
            display_data.append(row)
        df = pd.DataFrame(display_data)
        html_table = df.to_html(escape=False, classes='vuln-table', index=False)
        st.markdown(f'<div class="table-container">{html_table}</div>', unsafe_allow_html=True)

    @staticmethod
    def download_buttons(data: List[Dict], prefix: str = "data") -> None:
        cols = st.columns([1, 1, 1, 1, 4])
        with cols[0]:
            if st.button("📋 複製", help="複製表格資料到剪貼簿", key=f"copy_{prefix}"):
                st.info("表格資料已複製到剪貼簿。")
        with cols[1]:
            if st.download_button(
                label="📄 PDF",
                data=f"{prefix}_report.pdf",
                file_name=f"{prefix}_report.pdf",
                mime="application/pdf",
                help="導出PDF報告", 
                key=f"pdf_{prefix}"
            ):
                pass
        with cols[2]:
            if data:
                csv_data = pd.DataFrame([{k: v for k, v in item.items() if k != '_original_data'} for item in data])
                csv = csv_data.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="📊 CSV",
                    data=csv,
                    file_name=f"{prefix}_data.csv",
                    mime="text/csv",
                    help="導出CSV資料",
                    key=f"csv_{prefix}"
                )
        with cols[3]:
            if st.button("🖨️ 列印", help="列印表格資料", key=f"print_{prefix}"):
                st.info("請使用瀏覽器的列印功能。")

    @staticmethod
    def display_remediation_plan(plan: str, key_prefix: str = "remediation") -> None:
        if not plan:
            st.warning("無可用的修補建議")
            return
        st.markdown(
            f"""
            <div class="remediation-section">
                <div class="remediation-header">
                    <h2>漏洞修補建議</h2>
                </div>
                <div class="remediation-body">
                    {plan}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        st.download_button(
            label="📄 下載修補建議",
            data=plan,
            file_name="漏洞修補建議.md",
            mime="text/markdown",
            help="以Markdown格式下載修補建議", 
            key=f"download_{key_prefix}"
        )

    @staticmethod
    def display_vulnerability_details(vuln_id: str, enhanced_vulnerabilities: List[Dict], update_callback, recommendation_callback=None) -> None:
        selected_vuln = next((v for v in enhanced_vulnerabilities if v["弱點ID"] == vuln_id), None)
        if not selected_vuln:
            st.warning(f"找不到 {vuln_id} 的詳細資訊")
            return
        st.session_state.selected_vuln_details = selected_vuln
        original_data = selected_vuln.get("_original_data", {})
        st.markdown(f'<div class="detail-section">', unsafe_allow_html=True)
        st.markdown(f'### 漏洞詳細資訊: {vuln_id}')
        detail_cols = st.columns(2)
        with detail_cols[0]:
            st.markdown("#### 基本資訊")
            st.markdown(f"**CVE ID**: {vuln_id}")
            st.markdown(f"**描述**: {original_data.get('description', 'N/A')}")
            st.markdown(f"**嚴重性**: {selected_vuln['弱點嚴重度']}")
            st.markdown(f"**CVSS**: {original_data.get('base_score', 'N/A')}")
            st.markdown(f"**EPSS**: {selected_vuln['EPSS 分數']}")
            st.markdown(f"**CWE**: {selected_vuln.get('CWE', 'N/A')}")
            st.markdown(f"**發布日期**: {selected_vuln.get('發布日期', 'N/A')}")
            st.markdown(f"**KEV狀態**: {'是' if original_data.get('in_kev', False) else '否'}")
        with detail_cols[1]:
            st.markdown("#### 資產資訊")
            st.markdown(f"**主機名稱**: {original_data.get('host_name', 'N/A')}")
            st.markdown(f"**IP 位址**: {original_data.get('ip_address', 'N/A')}")
            st.markdown(f"**群組**: {selected_vuln.get('群組', 'N/A')}")
            st.markdown(f"**產品**: {selected_vuln.get('產品', 'N/A')}")
            st.markdown(f"**服務**: {selected_vuln.get('服務', 'N/A')}")
            st.markdown(f"**狀態**: {selected_vuln['狀態']}")
            st.markdown(f"**修復計畫**: {selected_vuln.get('修復計畫', 'N/A')}")
        action_cols = st.columns(4)
        with action_cols[0]:
            if selected_vuln["狀態"] == "已修補":
                if st.button("標記為未修補", key=f"unpatch_{vuln_id}"):
                    success, message = update_callback(vuln_id, False)
                    if success:
                        st.success(message)
                        st.experimental_rerun()
                    else:
                        st.error(message)
            else:
                if st.button("標記為已修補", key=f"patch_{vuln_id}"):
                    success, message = update_callback(vuln_id, True)
                    if success:
                        st.success(message)
                        st.experimental_rerun()
                    else:
                        st.error(message)
        with action_cols[1]:
            if st.button("設定修復日期", key=f"date_{vuln_id}"):
                import datetime
                default_date = datetime.datetime.now() + datetime.timedelta(days=30)
                remediation_date = st.date_input(
                    "選擇計劃修復日期",
                    value=default_date,
                    key=f"date_input_{vuln_id}"
                )
                if st.button("保存日期", key=f"save_date_{vuln_id}"):
                    st.success(f"已設定修復日期為: {remediation_date}")
        with action_cols[2]:
            if st.button("添加筆記", key=f"note_{vuln_id}"):
                note = st.text_area("輸入筆記內容", key=f"note_text_{vuln_id}")
                if st.button("保存筆記", key=f"save_note_{vuln_id}"):
                    st.success("筆記已保存")
        with action_cols[3]:
            if st.button("返回列表", key=f"back_{vuln_id}"):
                st.session_state.selected_cve = None
                st.experimental_rerun()
        st.markdown("#### 參考資料")
        references = original_data.get("references", [])
        if references:
            for ref in references:
                st.markdown(f"- [{ref}]({ref})")
        else:
            st.markdown("無參考資料")
        if recommendation_callback:
            st.markdown("#### 漏洞修補建議與評估")
            recommendation_result = recommendation_callback(vuln_id)
            recommendation_text = recommendation_result.get("recommendation", "")
            ragas_scores = recommendation_result.get("ragas_scores", {})
            resource_usage = recommendation_result.get("resource_usage", {})
            performance_metrics = recommendation_result.get("performance_metrics", {})
            recommendation_tabs = st.tabs(["修補建議", "可信度評估", "性能指標", "歷史記錄"])
            with recommendation_tabs[0]:
                generated_at = recommendation_result.get("generated_at", "")
                if generated_at:
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
                        generated_at = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass
                st.markdown(f"""
                <div style="color: #666; font-size: 0.8rem; text-align: right; margin-bottom: 10px;">
                    生成時間: {generated_at}
                </div>
                """, unsafe_allow_html=True)
                if recommendation_text:
                    st.markdown('<div class="remediation-section">', unsafe_allow_html=True)
                    st.markdown(recommendation_text)
                    st.markdown('</div>', unsafe_allow_html=True)
                else:
                    st.info("無修補建議可用")
                if st.button("重新生成修補建議", key=f"regenerate_{vuln_id}"):
                    st.session_state.regenerate_recommendation = True
                    st.experimental_rerun()
            
            with recommendation_tabs[1]:
                st.markdown("##### RAGAS 評估指標")
                # 確保從ragas_scores中正確獲取指標，同時提供直接從結果對象訪問的備用方案
                faithfulness = ragas_scores.get("faithfulness", recommendation_result.get("faithfulness", 0.0))
                answer_relevancy = ragas_scores.get("answer_relevancy", recommendation_result.get("answer_relevancy", 0.0))
                
                st.markdown("""
                **評估指標說明:**
                - **忠實度 (Faithfulness)**: 測量建議內容是否基於事實而非幻覺，避免產生不準確的資訊
                - **相關性 (Answer Relevancy)**: 測量建議內容與漏洞問題的相關程度，評估回答是否針對特定漏洞
                """)
                
                # 計算整體評分
                overall_score = (faithfulness + answer_relevancy) / 2
                
                # 使用更清晰的視覺布局顯示指標
                metric_cols = st.columns(2)
                with metric_cols[0]:
                    for i, (metric_name, metric_value) in enumerate([
                        ("忠實度 (Faithfulness)", faithfulness),
                        ("相關性 (Answer Relevancy)", answer_relevancy)
                    ]):
                        # 根據分數確定顏色
                        color = "green" if metric_value >= 0.7 else "orange" if metric_value >= 0.4 else "red"
                        
                        st.markdown(f"""
                        <div style="margin-bottom: 15px;">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                                <span>{metric_name.split(' ')[0]}</span>
                                <span style="color: {color}; font-weight: bold;">{metric_value:.2f}</span>
                            </div>
                            <div style="height: 10px; width: 100%; background-color: #eee; border-radius: 5px;">
                                <div style="height: 10px; width: {metric_value*100}%; background-color: {color}; border-radius: 5px;"></div>
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                
                with metric_cols[1]:
                    # 顯示總體評價和建議
                    if overall_score >= 0.7:
                        st.success("✅ 高可信度：此修補建議可信度高，可以參考使用")
                    elif overall_score >= 0.4:
                        st.warning("⚠️ 中等可信度：此修補建議部分可信，請謹慎檢查後使用")
                    else:
                        st.error("❌ 低可信度：此修補建議可能包含幻覺或不相關內容，不建議直接使用")
                    
                    st.markdown(f"""
                    <div style="margin-top: 15px; padding: 10px; background-color: #333; border-radius: 5px;">
                        <div style="font-weight: bold; margin-bottom: 8px;">整體可信度評分</div>
                        <div style="display: flex; align-items: center;">
                            <div style="font-size: 24px; font-weight: bold; color: {'green' if overall_score >= 0.7 else 'orange' if overall_score >= 0.4 else 'red'};">
                                {overall_score:.2f}
                            </div>
                            <div style="margin-left: 10px; flex-grow: 1;">
                                <div style="height: 15px; width: 100%; background-color: #555; border-radius: 5px;">
                                    <div style="height: 15px; width: {overall_score*100}%; background-color: {'green' if overall_score >= 0.7 else 'orange' if overall_score >= 0.4 else 'red'}; border-radius: 5px;"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    st.markdown("""
                    **評分標準:**
                    - **0.7-1.0**: 高可信度 - 建議可靠且全面
                    - **0.4-0.7**: 中等可信度 - 建議部分可信，需謹慎使用
                    - **0.0-0.4**: 低可信度 - 建議可能有誤，不建議直接使用
                    """)
            
            with recommendation_tabs[2]:
                st.markdown("##### 生成性能指標")
                metric_cols = st.columns(2)
                with metric_cols[0]:
                    st.markdown("**資源使用情況**")
                    for key, value in resource_usage.items():
                        st.markdown(f"- **{key}**: {value}")
                with metric_cols[1]:
                    st.markdown("**效能指標**")
                    for key, value in performance_metrics.items():
                        if isinstance(value, float):
                            st.markdown(f"- **{key}**: {value:.4f}")
                        else:
                            st.markdown(f"- **{key}**: {value}")
                if "query" in recommendation_result and "contexts" in recommendation_result:
                    with st.expander("查詢與上下文詳情", expanded=False):
                        st.markdown(f"**查詢**: {recommendation_result['query']}")
                        st.markdown("**上下文**:")
                        for i, ctx in enumerate(recommendation_result['contexts']):
                            st.markdown(f"{i+1}. {ctx}")
            with recommendation_tabs[3]:
                st.markdown("##### 建議生成歷史記錄")
                if "recommendation_history" in st.session_state and vuln_id in st.session_state.recommendation_history:
                    history = st.session_state.recommendation_history[vuln_id]
                    if history:
                        for i, entry in enumerate(reversed(history)):
                            timestamp = entry.get("timestamp", "")
                            try:
                                from datetime import datetime
                                dt = datetime.fromisoformat(timestamp)
                                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                pass
                            score = entry.get("overall_score", 0.0)
                            score_color = "green" if score >= 0.7 else "orange" if score >= 0.4 else "red"
                            with st.expander(f"記錄 {len(history)-i} - {timestamp} (分數: {score:.2f})", expanded=(i==0)):
                                st.markdown(f"""
                                <div style="display: flex; align-items: center; margin-bottom: 10px;">
                                    <div style="margin-right: 5px;">可信度分數:</div>
                                    <div style="background-color: {score_color}; color: white; padding: 3px 10px; border-radius: 10px; font-weight: bold;">
                                        {score:.2f}
                                    </div>
                                </div>
                                """, unsafe_allow_html=True)
                                st.markdown(entry.get("recommendation", "無內容"))
                                ragas = entry.get("ragas_scores", {})
                                if ragas:
                                    st.markdown("**評估指標:**")
                                    for metric, value in ragas.items():
                                        st.markdown(f"- {metric}: {value:.4f}")
                    else:
                        st.info("無歷史記錄")
                else:
                    st.info("無歷史記錄")
        st.markdown('</div>', unsafe_allow_html=True)

    @staticmethod
    def create_risk_chart(risk_data: pd.DataFrame, chart_title: str, 
                          domain: List[str], color_range: List[str], 
                          height: int = 300) -> alt.Chart:
        chart = alt.Chart(risk_data).mark_bar().encode(
            x=alt.X("策略:N", title="策略"),
            y=alt.Y("數量:Q", title="數量"),
            color=alt.Color("策略:N", scale=alt.Scale(
                domain=domain,
                range=color_range
            )),
            tooltip=["策略:N", "數量:Q"]
        ).properties(
            title=chart_title,
            height=height
        )
        return chart

    @staticmethod
    def create_pie_chart(data: pd.DataFrame, theta_field: str, color_field: str, 
                         title: str, domain: List[str], color_range: List[str],
                         width: int = 400, height: int = 300) -> alt.Chart:
        chart = alt.Chart(data).mark_arc().encode(
            theta=alt.Theta(f"{theta_field}:Q"),
            color=alt.Color(f"{color_field}:N", scale=alt.Scale(
                domain=domain,
                range=color_range
            )),
            tooltip=[f"{color_field}:N", f"{theta_field}:Q"]
        ).properties(
            title=title,
            width=width,
            height=height
        )
        return chart

    @staticmethod
    def render_tab_navigation(current_tab: int) -> None:
        if current_tab > 0:
            js = f"""
            <script>
                requestAnimationFrame(function() {{
                    const tabs = window.parent.document.querySelectorAll("[data-baseweb='tab']");
                    if (tabs && tabs.length > {current_tab}) {{
                        tabs[{current_tab}].click();
                    }}
                    setTimeout(function() {{
                        window.parent.postMessage({{
                            type: 'streamlit:setComponentValue',
                            value: 0,
                            dataType: 'number',
                            key: 'current_tab'
                        }}, '*');
                    }}, 100);
                }});
            </script>
            """
            st.markdown(js, unsafe_allow_html=True)

    @staticmethod
    def display_evaluation_results(ragas_scores: Dict[str, float]) -> None:
        """顯示RAGAS評估指標的詳細結果"""
        if not ragas_scores:
            st.warning("無可用的評估結果")
            return
            
        faithfulness = ragas_scores.get("faithfulness", 0.0)
        answer_relevancy = ragas_scores.get("answer_relevancy", 0.0)
        
        # 計算整體評分 (僅使用faithfulness和answer_relevancy)
        overall_score = (faithfulness + answer_relevancy) / 2
        
        st.markdown("### RAGAS 評估指標")
        
        # 使用卡片式布局顯示指標
        metrics_col1, metrics_col2 = st.columns(2)
        
        with metrics_col1:
            st.markdown(f"""
            <div style="padding: 15px; background-color: #2a2a2a; border-radius: 8px; margin-bottom: 15px;">
                <h4 style="margin-top: 0; color: #90CAF9;">指標評分</h4>
                <table style="width: 100%;">
                    <tr>
                        <td style="padding: 8px 0; border-bottom: 1px solid #444;">忠實度 (Faithfulness)</td>
                        <td style="padding: 8px 0; border-bottom: 1px solid #444; text-align: right; font-weight: bold; color: {'green' if faithfulness >= 0.7 else 'orange' if faithfulness >= 0.4 else 'red'};">
                            {faithfulness:.2f}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; border-bottom: 1px solid #444;">相關性 (Answer Relevancy)</td>
                        <td style="padding: 8px 0; border-bottom: 1px solid #444; text-align: right; font-weight: bold; color: {'green' if answer_relevancy >= 0.7 else 'orange' if answer_relevancy >= 0.4 else 'red'};">
                            {answer_relevancy:.2f}
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">整體可信度</td>
                        <td style="padding: 8px 0; text-align: right; font-weight: bold; color: {'green' if overall_score >= 0.7 else 'orange' if overall_score >= 0.4 else 'red'};">
                            {overall_score:.2f}
                        </td>
                    </tr>
                </table>
            </div>
            """, unsafe_allow_html=True)
        
        with metrics_col2:
            # 顯示視覺化的整體評分
            st.markdown(f"""
            <div style="padding: 15px; background-color: #2a2a2a; border-radius: 8px; height: 92%;">
                <h4 style="margin-top: 0; color: #90CAF9;">整體評估</h4>
                <div style="text-align: center; padding: 15px 0;">
                    <div style="font-size: 48px; font-weight: bold; color: {'green' if overall_score >= 0.7 else 'orange' if overall_score >= 0.4 else 'red'};">
                        {overall_score:.2f}
                    </div>
                    <div style="margin: 15px 0; height: 20px; background-color: #444; border-radius: 10px; overflow: hidden;">
                        <div style="height: 100%; width: {overall_score*100}%; background-color: {'green' if overall_score >= 0.7 else 'orange' if overall_score >= 0.4 else 'red'}; border-radius: 10px;"></div>
                    </div>
                    <div style="font-weight: bold; color: {'green' if overall_score >= 0.7 else 'orange' if overall_score >= 0.4 else 'red'};">
                        {
                        "高可信度" if overall_score >= 0.7 else 
                        "中等可信度" if overall_score >= 0.4 else 
                        "低可信度"
                        }
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        # 顯示指標說明
        with st.expander("評估指標說明", expanded=False):
            st.markdown("""
            ### 評估指標詳細說明
            
            #### 忠實度 (Faithfulness)
            測量建議內容是否基於事實而非幻覺。高分表示建議內容與上下文資訊一致，不包含虛構或誤導性資訊。
            
            #### 相關性 (Answer Relevancy)
            測量建議內容與特定漏洞問題的相關程度。高分表示建議直接針對所詢問的漏洞，提供了相關且有用的修補資訊。
            
            ### 評分標準
            - **0.7-1.0**: 高可信度 - 建議內容可靠、相關且全面
            - **0.4-0.7**: 中等可信度 - 建議部分可信，需專業人員審核後使用
            - **0.0-0.4**: 低可信度 - 建議可能包含不準確或不相關的內容，不建議直接使用
            """)
        
        # 提供具體建議
        if overall_score >= 0.7:
            st.success("✅ 評估結果：此修補建議可信度高，可以參考使用。")
        elif overall_score >= 0.4:
            st.warning("⚠️ 評估結果：此修補建議部分可信，建議由專業安全人員審核後再使用。某些修補步驟可能需要額外驗證。")
        else:
            st.error("❌ 評估結果：此修補建議可信度低，不建議直接使用。")