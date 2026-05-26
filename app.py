import json
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from collections import defaultdict, Counter

st.set_page_config(
    page_title="Аналіз журналів автентифікації",
    page_icon="🔒",
    layout="wide"
)

st.title("🔒 Аналіз журналів автентифікації")
st.markdown("Завантажте JSON-файл із журналами автентифікації для виявлення підозрілої активності.")

uploaded_file = st.file_uploader("Оберіть JSON-файл журналу", type=["json"])

def validate_data(data):
    required = {"timestamp", "username", "ip", "status"}
    if not isinstance(data, list):
        raise ValueError("JSON має містити список записів.")
    for row in data:
        if not required.issubset(row.keys()):
            raise ValueError("Кожен запис має містити поля: timestamp, username, ip, status")
        datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
        if row["status"] not in ["success", "failed"]:
            raise ValueError("Поле status має бути success або failed.")

def detect_bruteforce(data):
    alerts = []
    failed_counter = defaultdict(int)
    for log in data:
        if log["status"] == "failed":
            key = (log["username"], log["ip"])
            failed_counter[key] += 1
    for (user, ip), count in failed_counter.items():
        if count >= 5:
            alerts.append({
                "Користувач": user,
                "IP-адреса": ip,
                "Тип загрози": "Brute-force",
                "Ризик": 90,
                "Опис": f"{count} невдалих спроб входу з однієї IP-адреси"
            })
    return alerts

def detect_night_logins(data):
    alerts = []
    for log in data:
        if log["status"] == "success":
            t = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
            if 0 <= t.hour <= 6:
                alerts.append({
                    "Користувач": log["username"],
                    "IP-адреса": log["ip"],
                    "Тип загрози": "Нічний вхід",
                    "Ризик": 50,
                    "Опис": "Успішний вхід у нетиповий нічний час (00:00–06:00)"
                })
    return alerts

def detect_multiple_ips(data):
    alerts = []
    user_ips = defaultdict(set)
    for log in data:
        if log["status"] == "success":
            user_ips[log["username"]].add(log["ip"])
    for user, ips in user_ips.items():
        if len(ips) >= 4:
            alerts.append({
                "Користувач": user,
                "IP-адреса": ", ".join(sorted(ips)),
                "Тип загрози": "Різні IP-адреси",
                "Ризик": 70,
                "Опис": f"Користувач входив із {len(ips)} різних IP-адрес"
            })
    return alerts

def detect_success_after_failures(data):
    alerts = []
    logs_by_user = defaultdict(list)
    for log in data:
        logs_by_user[log["username"]].append(log)
    for user, logs in logs_by_user.items():
        logs.sort(key=lambda x: x["timestamp"])
        failed_count = 0
        for log in logs:
            if log["status"] == "failed":
                failed_count += 1
            elif log["status"] == "success":
                if failed_count >= 3:
                    alerts.append({
                        "Користувач": user,
                        "IP-адреса": log["ip"],
                        "Тип загрози": "Успіх після помилок",
                        "Ризик": 85,
                        "Опис": f"Успішний вхід після {failed_count} невдалих спроб"
                    })
                failed_count = 0
    return alerts

if uploaded_file is not None:
    try:
        data = json.load(uploaded_file)
        validate_data(data)
        st.success(f"Завантажено {len(data)} записів журналу.")

        alerts = []
        alerts += detect_bruteforce(data)
        alerts += detect_night_logins(data)
        alerts += detect_multiple_ips(data)
        alerts += detect_success_after_failures(data)

        st.subheader(f"Виявлено підозрілих подій: {len(alerts)}")
        if alerts:
            df = pd.DataFrame(alerts)
            st.dataframe(df, use_container_width=True)

            st.subheader("Візуалізація результатів")
            col1, col2, col3 = st.columns(3)

            status_counter = Counter(log["status"] for log in data)
            df_status = pd.DataFrame(status_counter.items(), columns=["Статус", "Кількість"])
            with col1:
                fig1 = px.bar(df_status, x="Статус", y="Кількість", title="Успішні та невдалі входи", color="Статус")
                st.plotly_chart(fig1, use_container_width=True)

            user_counter = Counter(log["username"] for log in data).most_common(8)
            df_users = pd.DataFrame(user_counter, columns=["Користувач", "Кількість"])
            with col2:
                fig2 = px.bar(df_users, x="Користувач", y="Кількість", title="Топ активних користувачів")
                fig2.update_xaxes(tickangle=45)
                st.plotly_chart(fig2, use_container_width=True)

            alert_counter = Counter(a["Тип загрози"] for a in alerts)
            df_types = pd.DataFrame(alert_counter.items(), columns=["Тип", "Кількість"])
            with col3:
                fig3 = px.pie(df_types, values="Кількість", names="Тип", title="Розподіл типів загроз")
                st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info("Підозрілої активності не виявлено.")
    except Exception as e:
        st.error(f"Помилка: {e}")
else:
    st.info("Завантажте JSON-файл для початку аналізу.")