import sys
import subprocess
import geoip2.database
import re
import json
import time  # 상단에 이미 import 되어 있어야 함
from ipaddress import ip_network, ip_address
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton, QLabel,
    QLineEdit, QListWidget, QGroupBox, QSpinBox, QWidget, QMessageBox
)
from PyQt5.QtCore import QTimer

class PortScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()

        self.blocked_ips = set()
        self.blocked_networks = []

        self.setWindowTitle("Port Scanner & IP Blocker")
        self.setGeometry(100, 100, 700, 700)

        self.settings_file = "settings.json"
        self.blocked_ips_file = "blocked_ips.json"

        self.registered_ips = []
        self.registered_countries = []
        self.registered_orgs = []
        self.blocked_ips = set()

        self.timer_interval = 60
        self.remaining_time = self.timer_interval

        self.load_settings()
        self.blocked_ips = self.load_blocked_ips()

        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
            self.asn_reader = geoip2.database.Reader('GeoLite2-ASN.mmdb')
        except FileNotFoundError:
            self.log("GeoLite2 DB 오류: 파일이 없습니다.")
            QMessageBox.critical(self, "GeoLite2 오류", "GeoLite2 데이터베이스 파일이 없습니다.")
            sys.exit(1)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.countdown)

        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Port Scanner & IP Blocker")
        self.resize(1000, 700)

        main_widget = QWidget()
        main_layout = QHBoxLayout()
        self.setCentralWidget(main_widget)
        main_widget.setLayout(main_layout)

        # 왼쪽 UI
        left_layout = QVBoxLayout()
        left_container = QWidget()
        left_container.setLayout(left_layout)
        left_container.setMaximumWidth(600)
        main_layout.addWidget(left_container, stretch=2)

        header_label = QLabel("Port Scanner & IP Blocker")
        header_label.setStyleSheet("font-size: 18px; font-weight: bold;")
        left_layout.addWidget(header_label)

        desc_label = QLabel("등록된 IP, 국가, 회사명을 관리하고, 스캔 주기를 설정하세요.")
        desc_label.setStyleSheet("font-size: 14px;")
        desc_label.setWordWrap(True)
        left_layout.addWidget(desc_label)

        # IP 관리
        ip_group = QGroupBox("IP 관리")
        ip_layout = QVBoxLayout()
        ip_group.setLayout(ip_layout)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("IP 주소를 입력하세요")
        ip_layout.addWidget(self.ip_input)

        add_ip_button = QPushButton("IP 추가")
        add_ip_button.clicked.connect(self.add_ip)
        ip_layout.addWidget(add_ip_button)

        self.ip_list = QListWidget()
        self.ip_list.addItems(self.registered_ips)
        ip_layout.addWidget(self.ip_list)

        delete_ip_button = QPushButton("선택된 IP 삭제")
        delete_ip_button.clicked.connect(self.delete_ip)
        ip_layout.addWidget(delete_ip_button)

        left_layout.addWidget(ip_group)

        # 국가 관리
        country_group = QGroupBox("국가 코드 관리")
        country_layout = QVBoxLayout()
        country_group.setLayout(country_layout)

        self.country_input = QLineEdit()
        self.country_input.setPlaceholderText("국가 코드를 입력하세요 (2자리)")
        country_layout.addWidget(self.country_input)

        add_country_button = QPushButton("코드 추가")
        add_country_button.clicked.connect(self.add_country)
        country_layout.addWidget(add_country_button)

        self.country_list = QListWidget()
        self.country_list.addItems(self.registered_countries)
        country_layout.addWidget(self.country_list)

        delete_country_button = QPushButton("선택된 코드 삭제")
        delete_country_button.clicked.connect(self.delete_country)
        country_layout.addWidget(delete_country_button)

        left_layout.addWidget(country_group)

        # 회사 관리
        org_group = QGroupBox("회사(운영사) 관리")
        org_layout = QVBoxLayout()
        org_group.setLayout(org_layout)

        self.org_input = QLineEdit()
        self.org_input.setPlaceholderText("운영사(회사명)을 입력하세요")
        org_layout.addWidget(self.org_input)

        add_org_button = QPushButton("회사 추가")
        add_org_button.clicked.connect(self.add_org)
        org_layout.addWidget(add_org_button)

        self.org_list = QListWidget()
        self.org_list.addItems(self.registered_orgs)
        org_layout.addWidget(self.org_list)

        delete_org_button = QPushButton("선택된 회사 삭제")
        delete_org_button.clicked.connect(self.delete_org)
        org_layout.addWidget(delete_org_button)

        left_layout.addWidget(org_group)

        # 타이머 설정
        timer_group = QGroupBox("타이머 설정")
        timer_layout = QGridLayout()
        timer_group.setLayout(timer_layout)

        timer_label = QLabel("스캔 주기 (초):")
        self.timer_input = QSpinBox()
        self.timer_input.setValue(60)
        self.timer_input.setRange(1, 3600)

        set_timer_button = QPushButton("주기 설정")
        set_timer_button.clicked.connect(self.set_timer_interval)

        start_timer_button = QPushButton("스캔 시작")
        start_timer_button.clicked.connect(self.start_timer)

        stop_timer_button = QPushButton("스캔 중지")
        stop_timer_button.clicked.connect(self.stop_timer)

        self.timer_status_label = QLabel("타이머 상태: 정지")
        self.remaining_time_label = QLabel("남은 시간: 0초")

        timer_layout.addWidget(timer_label, 0, 0)
        timer_layout.addWidget(self.timer_input, 0, 1)
        timer_layout.addWidget(set_timer_button, 0, 2)
        timer_layout.addWidget(start_timer_button, 1, 0)
        timer_layout.addWidget(stop_timer_button, 1, 2)
        timer_layout.addWidget(self.timer_status_label, 2, 0, 1, 3)
        timer_layout.addWidget(self.remaining_time_label, 3, 0, 1, 3)

        left_layout.addWidget(timer_group)

        # 로그
        self.log_group = QGroupBox("스캔 로그")
        log_layout = QVBoxLayout()
        self.log_group.setLayout(log_layout)

        self.log_label = QLabel("")
        self.log_label.setStyleSheet("font-size: 12px;")
        self.log_label.setWordWrap(True)
        log_layout.addWidget(self.log_label)

        left_layout.addWidget(self.log_group)

        # 오른쪽: 강제 차단
        right_layout = QVBoxLayout()
        right_container = QWidget()
        right_container.setLayout(right_layout)
        main_layout.addWidget(right_container, stretch=1)

        forced_block_group = QGroupBox("강제 차단 IP")
        forced_layout = QVBoxLayout()
        forced_block_group.setLayout(forced_layout)

        self.forced_ip_input = QLineEdit()
        self.forced_ip_input.setPlaceholderText("강제 차단할 IP 주소를 입력하세요")
        forced_layout.addWidget(self.forced_ip_input)

        force_block_button = QPushButton("강제 차단")
        force_block_button.clicked.connect(self.add_forced_block_ip)
        forced_layout.addWidget(force_block_button)

        self.forced_block_list = QListWidget()
        forced_layout.addWidget(self.forced_block_list)

        right_layout.addWidget(forced_block_group)


    def add_forced_block_ip(self):
        ip = self.forced_ip_input.text().strip()
        if not self.is_valid_ip(ip):
            QMessageBox.warning(self, "경고", "올바르지 않은 IP 형식입니다.")
            return

        if any(ip_address(ip) in net for net in self.blocked_networks):
            QMessageBox.information(self, "정보", f"{ip}는 이미 차단된 IP입니다.")
            return

        # 국가 및 회사 정보 조회
        country = self.get_country(ip)
        asn = self.get_asn(ip)

        # 차단 실행
        self.block_ip(ip)

        # ✅ 차단 확인 & 보정
        if not self.is_forced_ip_blocked(ip):
            self.log(f"⚠️ {ip} 가 차단 목록에 없음 → 강제 차단 시도")
            self.block_ip(ip)
        else:
            self.log(f"✅ {ip} 는 이미 차단 목록에 포함되어 있음")

        # 차단 확인
        blocked = False
        try:
            for net_str in self.blocked_ips:
                if ip_address(ip) in ip_network(net_str):
                    blocked = True
                    break
        except Exception as e:
            self.log(f"차단 확인 중 오류 발생: {e}")

        # 국가 및 회사 자동 등록
        if country != "Unknown" and country not in self.registered_countries:
            self.registered_countries.append(country)
            self.country_list.addItem(country)

        if asn != "Unknown ASN" and asn not in self.registered_orgs:
            self.registered_orgs.append(asn)
            self.org_list.addItem(asn)

        # 강제 차단 리스트 UI에 표시
        self.forced_block_list.addItem(f"{ip} | 국가: {country} | 회사: {asn}")

        # 차단 성공 여부 로그 출력
        if blocked:
            self.log(f"✅ {ip} 강제 차단 성공 (국가: {country}, 회사: {asn})")
        else:
            self.log(f"❌ {ip} 차단 실패! 관리자 권한을 확인하거나 시스템 방화벽을 점검하세요.")

        self.forced_ip_input.clear()
        self.save_settings()

    def countdown(self):
        if self.remaining_time > 0:
            self.remaining_time -= 1
            self.remaining_time_label.setText(f"남은 시간: {self.remaining_time}초")
        else:
            self.remaining_time = self.timer_interval
            self.remaining_time_label.setText(f"남은 시간: {self.remaining_time}초")
            self.scan_ports()

    def set_timer_interval(self):
        self.timer_interval = self.timer_input.value()
        self.remaining_time = self.timer_interval
        self.remaining_time_label.setText(f"남은 시간: {self.remaining_time}초")

    def start_timer(self):
        self.set_timer_interval()
        self.timer.start(1000)
        self.timer_status_label.setText("타이머 상태: 실행 중")

    def stop_timer(self):
        self.timer.stop()
        self.timer_status_label.setText("타이머 상태: 정지")

    def add_ip(self):
        ip = self.ip_input.text().strip()
        if ip and ip not in self.registered_ips:
            self.registered_ips.append(ip)
            self.ip_list.addItem(ip)
            self.ip_input.clear()
            self.log(f"IP 추가: {ip}")
            self.save_settings()
        else:
            QMessageBox.warning(self, "경고", "유효하지 않거나 이미 등록된 IP입니다.")

    def delete_ip(self):
        selected_item = self.ip_list.currentItem()
        if selected_item:
            ip = selected_item.text()
            self.registered_ips.remove(ip)
            self.ip_list.takeItem(self.ip_list.row(selected_item))
            self.log(f"IP 삭제: {ip}")
            self.save_settings()

    def add_country(self):
        code = self.country_input.text().strip().upper()
        if code and code not in self.registered_countries:
            self.registered_countries.append(code)
            self.country_list.addItem(code)
            self.country_input.clear()
            self.log(f"국가 추가: {code}")
            self.save_settings()
        else:
            QMessageBox.warning(self, "경고", "유효하지 않거나 이미 등록된 국가 코드입니다.")

    def delete_country(self):
        selected_item = self.country_list.currentItem()
        if selected_item:
            code = selected_item.text()
            self.registered_countries.remove(code)
            self.country_list.takeItem(self.country_list.row(selected_item))
            self.log(f"국가 삭제: {code}")
            self.save_settings()

    def add_org(self):
        org = self.org_input.text().strip()
        if org and org not in self.registered_orgs:
            self.registered_orgs.append(org)
            self.org_list.addItem(org)
            self.org_input.clear()
            self.log(f"회사 추가: {org}")
            self.save_settings()
        else:
            QMessageBox.warning(self, "경고", "유효하지 않거나 이미 등록된 회사입니다.")

    def delete_org(self):
        selected_item = self.org_list.currentItem()
        if selected_item:
            org = selected_item.text()
            self.registered_orgs.remove(org)
            self.org_list.takeItem(self.org_list.row(selected_item))
            self.log(f"회사 삭제: {org}")
            self.save_settings()

    def scan_ports(self):
        start_time = time.time()
        self.log("스캔 시작...")

        # 현재 차단된 IP 먼저 표시
        self.log("차단된 IP 목록:")
        for ip_range in sorted(self.blocked_ips):
            self.log(f"- {ip_range}")

        connections = self.get_connections()
        for ip in connections:
            if not self.is_valid_ip(ip):
                continue
            if any(ip_address(ip) in ip_network(blocked) for blocked in self.blocked_ips):
                self.log(f"이미 차단된 IP 범위: {ip}")
                continue
            country = self.get_country(ip)
            asn = self.get_asn(ip)
            self.log(f"탐지: {ip} | 국가: {country} | 운영사: {asn}")
            if ip not in self.registered_ips and country not in self.registered_countries and asn not in self.registered_orgs:
                self.block_ip(ip)

        elapsed = round(time.time() - start_time, 2)
        self.log(f"스캔 완료 (소요 시간: {elapsed}초)")

    def is_forced_ip_blocked(self, ip):
        for net_str in self.blocked_ips:
            if ip_address(ip) in ip_network(net_str):
                return True
        return False

    def get_connections(self):
        result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
        ips = set()

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) > 2 and ":" in parts[2]:
                ip = parts[2].split(":")[0]
                if self.is_valid_ip(ip):
                    if any(ip_address(ip) in net for net in self.blocked_networks):
                        continue
                    ips.add(ip)
        return list(ips)


    def is_valid_ip(self, ip):
        pattern = r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        pattern += r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        pattern += r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
        pattern += r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"
        return re.match(pattern, ip)

    def get_country(self, ip):
        try:
            response = self.geoip_reader.country(ip)
            return response.country.iso_code
        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            self.log(f"GeoIP 에러: {e}")
            return "Unknown"

    def get_asn(self, ip):
        try:
            response = self.asn_reader.asn(ip)
            return response.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            return "Unknown ASN"
        except Exception as e:
            self.log(f"ASN 조회 에러: {e}")
            return "Error"

    def block_ip(self, ip):
        try:
            range_ip = f"{ip.split('.')[0]}.{ip.split('.')[1]}.0.0/16"
            if range_ip in self.blocked_ips:
                self.log(f"이미 차단된 범위: {range_ip}")
                return
            command = f"netsh advfirewall firewall add rule name=Block_{range_ip} dir=in action=block remoteip={range_ip}"
            subprocess.run(command, shell=True)
            self.blocked_ips.add(range_ip)
            self.blocked_networks.append(ip_network(range_ip))  # 이 줄 추가
            self.save_blocked_ips()
            self.log(f"IP 범위 차단: {range_ip}")
        except Exception as e:
            self.log(f"차단 실패: {ip} - {e}")

    def load_blocked_ips(self):
        try:
            with open(self.blocked_ips_file, "r") as file:
                return set(json.load(file))
        except FileNotFoundError:
            return set()
        except Exception as e:
            self.log(f"JSON 로드 오류: {e}")
            return set()

    def save_blocked_ips(self):
        try:
            with open(self.blocked_ips_file, "w") as file:
                json.dump(list(self.blocked_ips), file)
        except Exception as e:
            self.log(f"JSON 저장 오류: {e}")

    def save_settings(self):
        try:
            with open(self.settings_file, "w") as f:
                json.dump({
                    "ips": self.registered_ips,
                    "countries": self.registered_countries,
                    "orgs": self.registered_orgs
                }, f)
        except Exception as e:
            self.log(f"설정 저장 오류: {e}")

    def load_settings(self):
        try:
            with open(self.settings_file, "r") as f:
                data = json.load(f)
                self.registered_ips = data.get("ips", [])
                self.registered_countries = data.get("countries", [])
                self.registered_orgs = data.get("orgs", [])
        except FileNotFoundError:
            self.registered_ips = ["66.249.66.1", "207.46.13.153", "18.117.23.45"]
            self.registered_countries = ["KR", "JP", "US"]
            self.registered_orgs = [
                "Google LLC", "Google Inc.", "Alphabet Inc.",
                "Microsoft Corporation", "Microsoft Bing",
                "Amazon Technologies Inc.", "Amazon.com Inc.",
                "Meta Platforms, Inc.", "Facebook Inc.",
                "Cloudflare, Inc.", "Yahoo! Inc", "Yandex LLC",
                "Baidu, Inc.", "Naver Corp", "Kakao Corp",
                "Jumpline Inc.", "Jumio Inc."
            ]
        except Exception as e:
            self.log(f"설정 로드 오류: {e}")

    def log(self, message):
        current_text = self.log_label.text()
        lines = current_text.split("<br>") if current_text else []
        lines.append(message)
        if len(lines) > 20:
            lines.pop(0)
        self.log_label.setText("<br>".join(lines))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PortScannerApp()
    window.show()
    sys.exit(app.exec())