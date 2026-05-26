import json
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
from collections import defaultdict, Counter

st.set_page_config(
    page_title=&quot;Аналіз журналів автентифікації&quot;,
    page_icon=&quot;&#x1F512;&quot;,
    layout=&quot;wide&quot;
)

st.title(&quot;&#x1F512; Аналіз журналів автентифікації&quot;)
st.markdown(&quot;Завантажте JSON-файл із журналами автентифікації для виявлення підозрілої активності.&quot;)

# --- Завантаження файлу ---
uploaded_file = st.file_uploader(&quot;Оберіть JSON-файл журналу&quot;, type=[&quot;json&quot;])

def validate_data(data):
    required = {&quot;timestamp&quot;, &quot;username&quot;, &quot;ip&quot;, &quot;status&quot;}
    if not isinstance(data, list):
        raise ValueError(&quot;JSON має містити список записів.&quot;)
    for row in data:
        if not required.issubset(row.keys()):
            raise ValueError(&quot;Кожен запис має містити поля: timestamp, username, ip, status&quot;)
        datetime.strptime(row[&quot;timestamp&quot;], &quot;%Y-%m-%d %H:%M:%S&quot;)
        if row[&quot;status&quot;] not in [&quot;success&quot;, &quot;failed&quot;]:
            raise ValueError(&quot;Поле status має бути success або failed.&quot;)

def detect_bruteforce(data):
    alerts = []
    failed_counter = defaultdict(int)
    for log in data:
        if log[&quot;status&quot;] == &quot;failed&quot;:
            key = (log[&quot;username&quot;], log[&quot;ip&quot;])
            failed_counter[key] += 1
    for (user, ip), count in failed_counter.items():
        if count &gt;= 5:
            alerts.append({
                &quot;Користувач&quot;: user, &quot;IP-адреса&quot;: ip,
                &quot;Тип загрози&quot;: &quot;Brute-force&quot;, &quot;Ризик&quot;: 90,
                &quot;Опис&quot;: f&quot;{count} невдалих спроб входу з однієї IP-адреси&quot;
            })
    return alerts

def detect_night_logins(data):
    alerts = []
    for log in data:
        if log[&quot;status&quot;] == &quot;success&quot;:
            t = datetime.strptime(log[&quot;timestamp&quot;], &quot;%Y-%m-%d %H:%M:%S&quot;)
            if 0 &lt;= t.hour &lt;= 6:
                alerts.append({
                    &quot;Користувач&quot;: log[&quot;username&quot;], &quot;IP-адреса&quot;: log[&quot;ip&quot;],
                    &quot;Тип загрози&quot;: &quot;Нічний вхід&quot;, &quot;Ризик&quot;: 50,
                    &quot;Опис&quot;: &quot;Успішний вхід у нетиповий нічний час (00:00&#x2013;06:00)&quot;
                })
    return alerts

def detect_multiple_ips(data):
    alerts = []
    user_ips = defaultdict(set)
    for log in data:
        if log[&quot;status&quot;] == &quot;success&quot;:
            user_ips[log[&quot;username&quot;]].add(log[&quot;ip&quot;])
    for user, ips in user_ips.items():
        if len(ips) &gt;= 4:
            alerts.append({
                &quot;Користувач&quot;: user, &quot;IP-адреса&quot;: &quot;, &quot;.join(sorted(ips)),
                &quot;Тип загрози&quot;: &quot;Різні IP-адреси&quot;, &quot;Ризик&quot;: 70,
                &quot;Опис&quot;: f&quot;Користувач входив із {len(ips)} різних IP-адрес&quot;
            })
    return alerts

def detect_success_after_failures(data):
    alerts = []
    logs_by_user = defaultdict(list)
    for log in data:
        logs_by_user[log[&quot;username&quot;]].append(log)
    for user, logs in logs_by_user.items():
        logs.sort(key=lambda x: x[&quot;timestamp&quot;])
        failed_count = 0
        for log in logs:
            if log[&quot;status&quot;] == &quot;failed&quot;:
                failed_count += 1
            elif log[&quot;status&quot;] == &quot;success&quot;:
                if failed_count &gt;= 3:
                    alerts.append({
                        &quot;Користувач&quot;: user, &quot;IP-адреса&quot;: log[&quot;ip&quot;],
                        &quot;Тип загрози&quot;: &quot;Успіх після помилок&quot;, &quot;Ризик&quot;: 85,
                        &quot;Опис&quot;: f&quot;Успішний вхід після {failed_count} невдалих спроб&quot;
                    })
                failed_count = 0
    return alerts

# --- Основна логіка ---
if uploaded_file is not None:
    try:
        data = json.load(uploaded_file)
        validate_data(data)
        st.success(f&quot;Завантажено {len(data)} записів журналу.&quot;)

        # Аналіз
        alerts = []
        alerts += detect_bruteforce(data)
        alerts += detect_night_logins(data)
        alerts += detect_multiple_ips(data)
        alerts += detect_success_after_failures(data)

        st.subheader(f&quot;Виявлено підозрілих подій: {len(alerts)}&quot;)

        if alerts:
            df = pd.DataFrame(alerts)
            st.dataframe(df, use_container_width=True)

            # Графіки
            st.subheader(&quot;Візуалізація результатів&quot;)
            col1, col2, col3 = st.columns(3)

            status_counter = Counter(log[&quot;status&quot;] for log in data)
            df_status = pd.DataFrame(status_counter.items(), columns=[&quot;Статус&quot;, &quot;Кількість&quot;])
            with col1:
                fig1 = px.bar(df_status, x=&quot;Статус&quot;, y=&quot;Кількість&quot;,
                              title=&quot;Успішні та невдалі входи&quot;, color=&quot;Статус&quot;)
                st.plotly_chart(fig1, use_container_width=True)

            user_counter = Counter(log[&quot;username&quot;] for log in data).most_common(8)
            df_users = pd.DataFrame(user_counter, columns=[&quot;Користувач&quot;, &quot;Кількість&quot;])
            with col2:
                fig2 = px.bar(df_users, x=&quot;Користувач&quot;, y=&quot;Кількість&quot;,
                              title=&quot;Топ активних користувачів&quot;)
                fig2.update_xaxes(tickangle=45)
                st.plotly_chart(fig2, use_container_width=True)

            alert_counter = Counter(a[&quot;Тип загрози&quot;] for a in alerts)
            df_types = pd.DataFrame(alert_counter.items(), columns=[&quot;Тип&quot;, &quot;Кількість&quot;])
            with col3:
                fig3 = px.pie(df_types, values=&quot;Кількість&quot;, names=&quot;Тип&quot;,
                              title=&quot;Розподіл типів загроз&quot;)
                st.plotly_chart(fig3, use_container_width=True)
        else:
            st.info(&quot;Підозрілої активності не виявлено.&quot;)

    except Exception as e:
        st.error(f&quot;Помилка: {e}&quot;)
else:
    st.info(&quot;Завантажте JSON-файл для початку аналізу.&quot;)