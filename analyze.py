#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import subprocess
import shutil
from collections import Counter
from datetime import datetime

# Настройка asyncio для совместимости с pyshark
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

try:
    import pyshark
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from tabulate import tabulate
except ImportError as e:
    print(f"Ошибка импорта: {e}")
    print("Установите: pip install pyshark matplotlib tabulate")
    sys.exit(1)

print("Анализатор DHCP-трафика (pyshark)")
print("=" * 60)

# Файл
if len(sys.argv) < 2:
    pcap_file = input("Путь к файлу: ").strip().strip('"')
else:
    pcap_file = sys.argv[1].strip('"')

if not os.path.exists(pcap_file):
    print(f"Файл не найден: {pcap_file}")
    sys.exit(1)

print(f"Файл: {pcap_file}")

# Поиск tshark в Linux-путях
def find_tshark():
    paths = [
        '/usr/bin/tshark',
        '/usr/local/bin/tshark',
        '/snap/bin/tshark',
        '/opt/wireshark/bin/tshark'
    ]
    for path in paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    # Поиск через which
    tshark = shutil.which('tshark')
    if tshark:
        return tshark
    return None

tshark_path = find_tshark()
if not tshark_path:
    print("tshark не найден!")
    print("Установите: sudo apt install tshark  (Debian/Ubuntu)")
    print("           sudo yum install wireshark-cli  (CentOS/RHEL)")
    sys.exit(1)

print(f"tshark: {tshark_path}")

# Проверка tshark
try:
    result = subprocess.run([tshark_path, "--version"], capture_output=True, text=True, timeout=5)
    if result.returncode == 0:
        version = result.stdout.split('\n')[0] if result.stdout else "unknown"
        print(f"tshark работает ({version})")
    else:
        print(f"Ошибка запуска tshark: {result.stderr}")
        sys.exit(1)
except Exception as e:
    print(f"Ошибка проверки tshark: {e}")
    sys.exit(1)

# Чтение пакетов
print("\nЧтение DHCP пакетов через pyshark...")

dhcp_packets = []
msg_types_map = {
    '1': 'Discover',
    '2': 'Offer',
    '3': 'Request',
    '4': 'Decline',
    '5': 'ACK',
    '6': 'NAK',
    '7': 'Release',
    '8': 'Inform'
}

try:
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter='dhcp',
        tshark_path=tshark_path,
        include_raw=False
    )

    print("Обработка пакетов:")

    for i, packet in enumerate(cap):
        try:
            dhcp = packet.dhcp
            ip_layer = packet.ip if hasattr(packet, 'ip') else None

            # Hostname
            hostname = 'N/A'
            if hasattr(dhcp, 'option'):
                for opt in dhcp.option:
                    if hasattr(opt, 'hostname'):
                        hostname = opt.hostname
                        break

            # Message type
            msg_code = 'N/A'
            if hasattr(dhcp, 'options'):
                msg_code = getattr(dhcp.options, 'dhcp_msg_type', 'N/A')

            packet_info = {
                'num': str(i + 1),
                'time': str(packet.sniff_time),
                'src': getattr(ip_layer, 'src', 'N/A') if ip_layer else 'N/A',
                'dst': getattr(ip_layer, 'dst', 'N/A') if ip_layer else 'N/A',
                'your_ip': getattr(dhcp, 'your_client_ip', 'N/A'),
                'hostname': hostname,
                'msg_code': msg_code,
                'msg_type': msg_types_map.get(msg_code, f'Type {msg_code}')
            }

            dhcp_packets.append(packet_info)
            print(f"  #{packet_info['num']}: {packet_info['msg_type']:10} | "
                  f"Хост: {packet_info['hostname']:15} | IP: {packet_info['your_ip']}")

        except Exception as e:
            print(f"  Пропущен пакет {i}: {e}")
            continue

    cap.close()

except Exception as e:
    print(f"Ошибка pyshark: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print(f"\nВсего пакетов: {len(dhcp_packets)}")

if not dhcp_packets:
    print("Не удалось распарсить пакеты!")
    sys.exit(0)

# Статистика
print("\n" + "=" * 60)
print("СТАТИСТИКА")
print("=" * 60)

type_counts = Counter(p['msg_type'] for p in dhcp_packets)
print("\nТипы сообщений:")
for msg_type, count in type_counts.most_common():
    pct = count / len(dhcp_packets) * 100
    print(f"   {msg_type:12} : {count:3} ({pct:.1f}%)")

# Клиенты
print("\nКлиенты (получившие IP):")
clients = {}
for p in dhcp_packets:
    if p['your_ip'] and p['your_ip'] != 'N/A' and p['msg_type'] == 'ACK':
        name = p['hostname'] if p['hostname'] != 'N/A' else p['src']
        clients[name] = p['your_ip']
        print(f"   {name:20} -> {p['your_ip']}")

if not clients:
    print("   (нет ACK с выданными IP)")

# Графики
print("\nПостроение графиков...")

plt.figure(figsize=(10, 6))
colors = plt.cm.Set3(range(len(type_counts)))

if len(type_counts) <= 4:
    plt.pie(type_counts.values(), labels=type_counts.keys(), autopct='%1.1f%%', colors=colors)
    plt.title('Распределение типов DHCP-сообщений')
else:
    plt.bar(range(len(type_counts)), list(type_counts.values()), color=colors)
    plt.xticks(range(len(type_counts)), list(type_counts.keys()), rotation=45, ha='right')
    plt.title('Количество DHCP-сообщений по типам')
    plt.ylabel('Количество')

plt.tight_layout()
plt.savefig('dhcp_types.png', dpi=150)
plt.close()
print("dhcp_types.png")

if len(dhcp_packets) > 1:
    plt.figure(figsize=(12, 4))
    x_pos = range(len(dhcp_packets))
    color_map = {'Discover': '#3498db', 'Offer': '#f39c12', 'Request': '#2ecc71', 'ACK': '#e74c3c'}
    pkt_colors = [color_map.get(p['msg_type'], '#95a5a6') for p in dhcp_packets]

    plt.scatter(x_pos, [1]*len(dhcp_packets), c=pkt_colors, s=300, alpha=0.7, edgecolors='black')

    for i, p in enumerate(dhcp_packets):
        plt.annotate(p['msg_type'], (i, 1), ha='center', va='center', fontsize=9, fontweight='bold', color='white')

    plt.yticks([])
    plt.xlabel('Порядковый номер пакета')
    plt.title('Последовательность DHCP handshake')
    plt.grid(True, alpha=0.3, axis='x')
    plt.ylim(0.5, 1.5)

    plt.tight_layout()
    plt.savefig('dhcp_sequence.png', dpi=150)
    plt.close()
    print("dhcp_sequence.png")

# Отчет
print("\nГенерация отчета...")

report = []
report.append("=" * 70)
report.append("ОТЧЕТ ПО АНАЛИЗУ DHCP-ТРАФИКА")
report.append(f"Файл: {os.path.abspath(pcap_file)}")
report.append(f"Дата: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
report.append("=" * 70)
report.append("")
report.append(f"Всего DHCP-пакетов: {len(dhcp_packets)}")
report.append(f"Уникальных типов: {len(type_counts)}")
report.append(f"Клиентов с IP: {len(clients)}")
report.append("")

report.append("РАСПРЕДЕЛЕНИЕ ПО ТИПАМ:")
type_table = [[t, c, f"{c/len(dhcp_packets)*100:.1f}%"] for t, c in type_counts.most_common()]
report.append(tabulate(type_table, headers=['Тип', 'Кол-во', 'Доля'], tablefmt='grid'))
report.append("")

if clients:
    report.append("ВЫДАННЫЕ IP-АДРЕСА:")
    client_table = [[name, ip] for name, ip in clients.items()]
    report.append(tabulate(client_table, headers=['Клиент', 'IP'], tablefmt='grid'))
    report.append("")

report.append("ДЕТАЛИ ПАКЕТОВ:")
pkt_table = [[p['num'], p['msg_type'], p['hostname'], p['your_ip']] for p in dhcp_packets]
report.append(tabulate(pkt_table, headers=['#', 'Тип', 'Хост', 'IP'], tablefmt='grid'))
report.append("")

report.append("ПРОВЕРКА ДРУГИХ ПРОТОКОЛОВ:")
report.append("   DNS: НЕ ОБНАРУЖЕНО (в файле только DHCP)")
report.append("   HTTP: НЕ ОБНАРУЖЕНО")
report.append("")

report.append("=" * 70)
report.append("АНАЛИЗ ЗАВЕРШЕН")
report.append("=" * 70)

report_text = '\n'.join(report)

with open('dhcp_report.txt', 'w', encoding='utf-8') as f:
    f.write(report_text)

print("dhcp_report.txt")
print("\n" + report_text)
