PortScannerApp
  GPTS (Geo-based Port Threat Shield)
  실시간 포트 연결 감지 및 IP 차단 시스템
  N/B 비트 흐름 분석 기반 확장 예정

🖥️ 소개
  이 애플리케이션은 다음 기능을 제공합니다
  
  실시간 포트 연결 감지
  
  국가, 회사, IP 주소 기반 자동 차단
  
  GeoLite2 데이터베이스를 사용한 GeoIP 정보 분석
  
  UI 기반 설정 저장 및 관리
  
  스캔 주기 타이머 및 자동 실행
  
  관리자 권한 기반 Windows 방화벽 차단 명령 실행

🛠️ 실행 전 준비
1. 필요한 파일 구조
  다음 파일이 루트에 위치해야 합니다
  
  GeoLite2-Country. mmdb
  
  GeoLite2-ASN. mmdb
  
  main. py
  
  settings. json
  
  blocked_ips. json (최초 실행 시 자동 생성)

2. Python 환경
  Python 3.7 이상이 필요하며, 다음 패키지를 설치해야 합니다
  
  pip install pyqt5 geoip2
  
  GeoLite2 데이터베이스는 MaxMind에서 발급받아야 하며, 아래 위치에 다운로드된 . mmdb 파일을 넣어주세요
  
  GeoLite2-Country. mmdb
  
  GeoLite2-ASN. mmdb

▶️ 실행 방법
  Windows 기준
  관리자 권한으로 실행 필수
  방화벽 설정을 위해 main. py는 관리자 권한으로 실행되어야 합니다.
  
  실행 명령어
  
  python main. py
  
  기능 사용법 요약
  
  좌측 패널에서 등록된 IP/국가/회사 설정
  
  우측 패널에서 실시간 포트 연결을 모니터링하고, 스캔 주기 설정
  
  로그 창을 통해 탐지 및 차단 현황 확인

📁 설정 저장 및 자동화
  프로그램은 settings. json에 사용자가 설정한 IP/국가/회사 정보를 저장합니다.
  
  차단된 IP는 blocked_ips. json에 저장되어 재실행 시 복원됩니다.

❗ 주의사항
  Windows 방화벽 명령어(netsh) 사용으로 인해 관리자 권한이 필요합니다.
  
  현재는 Windows OS에서만 동작하도록 구성되어 있습니다.
  
  방화벽 차단은 /16 단위로 처리됩니다. (예 123.45.0.0/16)
