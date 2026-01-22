def compare_ports(local_ports: list[int], shodan_ports: list[int]) -> dict[int, str]:
    """
    Compare local scan ports with Shodan observed ports.
    Returns: {port: "high" | "low"}
    """
    result = {}

    shodan_set = set(shodan_ports)

    for port in local_ports:
        if port in shodan_set:
            result[port] = "high"
        else:
            result[port] = "low"

    return result
