import pyshark
import pandas as pd
import matplotlib.pyplot as plt

# Файл дампа
pcap_file = 'dns.pcap'

# Загрузка дампа
cap = pyshark.FileCapture(pcap_file)

dns_requests = []

# Сбор DNS-запросов
for packet in cap:
    try:
        if 'DNS' in packet and 'IP' in packet:
            if hasattr(packet.dns, 'qry_name'):
                dns_requests.append({
                    'time': packet.sniff_time,
                    'domain': packet.dns.qry_name
                })
    except AttributeError:
        continue

cap.close()

# Создание DataFrame
df = pd.DataFrame(dns_requests)

if df.empty:
    print("DNS-запросы не найдены")
else:
    # ---------- ТОП-10 ДОМЕНОВ ----------
    top_domains = df['domain'].value_counts().head(10)

    # Сохранение в CSV
    top_domains.to_csv('top_10_domains.csv', header=['count'])
    print("Файл top_10_domains.csv сохранён")

    # ---------- ГРАФИК DNS ПО ВРЕМЕНИ ----------
    df['time'] = pd.to_datetime(df['time'])
    df['minute'] = df['time'].dt.floor('min')

    dns_by_time = df.groupby('minute').size()

    plt.figure(figsize=(10, 5))

    plt.bar(dns_by_time.index.astype(str), dns_by_time.values)

    plt.xticks(rotation=45)
    plt.xlabel('Время')
    plt.ylabel('Количество DNS-запросов')
    plt.title('DNS-запросы по времени')

    plt.tight_layout()
    plt.savefig('dns_requests_over_time.png')
    plt.show()

    # Сохранение графика
    plt.savefig('dns_requests_over_time.png')
    plt.close()

    print("Файл dns_requests_over_time.png сохранён")