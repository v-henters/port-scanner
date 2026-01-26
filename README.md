# Portsense

Portsense는 **포트 스캔 결과를 분석하기 위한 경량 분석 도구(scaffold)**입니다.  
로컬에 존재하는 스캔 결과 파일(예: Nmap XML)을 파싱하고, 공격 표면 기준의 **위험도(Risk)** 및 **노출 신뢰도(Confidence)** 평가를 수행한 뒤 JSON 또는 Markdown 형태의 리포트를 생성합니다.

이 도구 자체는 네트워크 스캔을 수행하지 않습니다.  
실제 네트워크 트래픽을 발생시키지 않으며, **이미 수집된 포트 스캔 결과를 분석하는 용도**로 설계되었습니다.

---

## Status

- 실행 가능한 CLI 제공
- 전체 구조 및 주요 모듈 scaffold 완료
- 위험도 / 노출 신뢰도 산정 로직 구현
- 웹 서비스 증적 스크린샷(Selenium) 기능 구현
- Nuclei 취약점 스캔 통합 (Optional)
- 네트워크 접근 최소화 (기본 분석 도구, Nuclei 활성화 시에만 선택적 스캔 수행)
- 확장 기능(nslookup, CVE 연계 등) 추가 가능 구조

---

## Requirements

- Python 3.12 이상

---

## Installation (Editable Mode)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## CLI Usage

```bash
portsense --help
```

또는 모듈 방식으로 실행:

```bash
python -m portsense --help
```

---

## Basic Example

```bash
python -m portsense.cli analyze --input samples/sample.xml --outdir out
```

### Report Filenames
By default, the tool generates timestamped report files and a stable `latest` pointer in the specified `--outdir`:
- `report_<YYYYMMDD_HHMMSS>.json`
- `report_<YYYYMMDD_HHMMSS>.md`
- `report_latest.json` (overwritten each run)
- `report_latest.md` (overwritten each run)

If Nuclei is enabled, results are also timestamped:
- `nuclei/results_<YYYYMMDD_HHMMSS>.jsonl`

To keep the old behavior (overwriting `report.json` and `report.md`), use the `--overwrite` flag:

```bash
python -m portsense.cli analyze --input samples/sample.xml --outdir out --overwrite
```

---

## Risk & Confidence Analysis

### Risk (공격 우선순위)

- 포트 번호, 서비스 유형, 포트 상태(open/closed)를 기반으로 위험도를 산정합니다.
- 결과는 `Critical / High / Medium / Low / Info` 단계로 분류됩니다.
- 정책 기반(port category, service weight) 구조로 확장 가능합니다.

### Confidence (노출 신뢰도)

- 동일 자산이 여러 환경/시점에서 얼마나 일관되게 노출되는지를 기준으로 산정합니다.
- 단발성 노출과 반복 노출을 구분하여 **신뢰도(Low / Medium / High)**를 제공합니다.

---

## Screenshots (Optional Selenium Feature)

웹 서비스(HTTP/HTTPS)에 대해 **증적(Evidence) 스크린샷**을 자동 수집하는 선택 기능입니다.

### Options

- `--screenshots / --no-screenshots` (기본: 비활성)
- `--screenshot-top N` (기본: 5)
- `--screenshot-timeout SECONDS` (기본: 8)
- `--screenshot-dir PATH` (기본: <outdir>/assets/screenshots)

### Example

```bash
python -m portsense.cli analyze \
  -i samples/sample.xml \
  --outdir out \
  --screenshots \
  --screenshot-top 3
```

---

## CVE/CVSS Enrichment (New)

The tool now supports enriching Nuclei findings with CVE/CVSS data:
- **Automatic Extraction**: CVE IDs are extracted from Nuclei template info and results.
- **NVD Integration**: Fetches CVSS v3.1, v3.0, or v2.0 data from the NVD API (v2).
- **Caching**: Responses are cached locally to reduce API calls and improve performance.
- **Informational**: Enrichment is optional and non-blocking. If NVD is unavailable, the report will still be generated.
- **Sourcing**: CVSS scores are sourced directly from NVD. No exploitability prediction (EPSS) is performed.

### CLI Flags
- `--cve-enrich / --no-cve-enrich`: Enable or disable enrichment (default: enabled).
- `--nvd-timeout SECONDS`: Timeout for NVD API calls (default: 10).
- `--nvd-cache-dir PATH`: Custom directory for NVD cache.

---

## Nuclei Integration (Optional)

발견된 웹 엔드포인트에 대해 **Nuclei**를 사용한 취약점 스캔을 수행하는 선택 기능입니다.
이 기능은 활성화 시 **네트워크 트래픽을 발생**시키므로, 반드시 **허가된 자산**에 대해서만 사용해야 합니다.

### Options

- `--nuclei / --no-nuclei` (기본: 비활성)
- `--nuclei-severity` (기본: "critical,high,medium")
- `--nuclei-timeout` (기본: 120)
- `--nuclei-bin` (기본: "nuclei")
- `--nuclei-jsonl PATH` (기본: <outdir>/nuclei/results.jsonl)
- `--nuclei-templates PATH` (선택 사항)
- `--nuclei-tags TAGS` (선택 사항)
- `--nuclei-rate-limit RL` (선택 사항)

### Example

```bash
python -m portsense.cli analyze \
  -i samples/sample.xml \
  --outdir out \
  --nuclei \
  --nuclei-severity critical,high
```

---

## Project Structure

```
portsense/
  CLI, 파서, 위험도/신뢰도 분석, 리포트 생성
scripts/
  보조 스크립트
examples/
  예제 입력
tests/
  테스트 코드
```

---

## Tests

```bash
pip install pytest
python -m pytest -q
```

---

## License

MIT License
    