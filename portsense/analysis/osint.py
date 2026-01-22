
from typing import List, Dict

def compare_ports(local_ports: List[int], shodan_ports: List[int]) -> Dict[int, str]:
    """
    로컬 스캔 결과와 Shodan 결과를 비교해서
    포트별 신뢰도(high / medium)를 반환
    """

    result = {}

    all_ports = set(local_ports + shodan_ports)

    for port in all_ports:
        if port in local_ports and port in shodan_ports:
            result[port] = "high"
        else:
            result[port] = "medium"

    return result
