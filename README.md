# Portsense

Portsense는 **포트 스캔 결과를 분석하기 위한 경량 분석 도구(scaffold)**이다.  
로컬에 존재하는 스캔 결과 파일(예: Nmap XML)을 파싱하고, 간단한 **공격 우선순위(위험도)** 및 **노출 신뢰도 평가**를 수행한 뒤 JSON 또는 Markdown 형태의 리포트를 생성한다.

이 도구 자체는 네트워크 스캔을 수행하지 않는다. 실제 네트워크 트래픽을 발생시키지 않으며, 이미 수집된 포트 스캔 결과를 분석하는 용도로 설계되었다.

## Status

- 실행 가능한 CLI 제공
- 전체 구조 및 주요 모듈 scaffold 완료
- 일부 분석 로직은 TODO 마커로 확장 가능
- 네트워크 접근 없음 (분석 전용 도구)

## Requirements

- Python 3.12 이상

## Installation (Editable Mode)

python -m venv .venv  
source .venv/bin/activate  
pip install -e .

## CLI Usage

portsense --help  

또는 모듈 방식으로 실행:

python -m portsense --help

### Screenshots (optional Selenium)

웹 서비스(HTTP/HTTPS) 증적(EVIDENCE) 스크린샷 수집은 선택 기능입니다. `analyze` 명령에 다음 옵션을 사용할 수 있습니다.

- `--screenshots/--no-screenshots` (기본: 비활성)
- `--screenshot-top N` (기본: 5) — 위험도 상위 N개 웹 항목만 캡처
- `--screenshot-timeout SECONDS` (기본: 8)
- `--screenshot-dir PATH` (기본: `<outdir>/assets/screenshots`)

동작 개요:
- 포트 상태가 `open`이고 위험도가 `High` 또는 `Critical`이며 서비스가 웹(http/https)으로 추정되는 항목만 캡처합니다.
- URL은 `scheme://host:port` 형식입니다. 포트 443/8443 또는 서비스가 https면 https를 사용합니다.
- 실패해도 보고서 생성은 계속되며, 증적에 `status` 및 `error`가 기록됩니다.

Selenium은 선택 의존성입니다. 설치되어 있지 않으면 스크린샷 수집은 건너뛰고(`skipped`) 보고서는 정상 생성됩니다.

간단한 예:

python -m portsense.cli analyze \
  -i samples/sample.xml \
  --outdir out \
  --screenshots \
  --screenshot-top 3

## Basic Example

Nmap XML 결과 파일을 분석하는 기본 예시:

portsense analyze --input path/to/scan.xml --format json > report.json  

portsense analyze --input path/to/scan.xml --format md > report.md

## Project Structure

- portsense/  
  CLI, 스캔 결과 파싱, 위험도 분석, 리포트 생성 로직
- scripts/  
  보조 스크립트 (선택 사항)
- examples/  
  예제 입력 파일 및 사용 예
- tests/  
  테스트 코드 scaffold

## Tests

pip install pytest  
python -m pytest -q

## License

MIT License