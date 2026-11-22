#!/bin/zsh
# ดับเบิลคลิก = เปิดหน้า Dashboard ในเบราว์เซอร์ (http://localhost:8501)
cd "$(dirname "$0")"
source .venv/bin/activate
streamlit run dashboard/app.py
