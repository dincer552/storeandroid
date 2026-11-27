import psutil

def get_active_adapters():
    """Return active network adapters with their IPv4 info."""
    adapters = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addr_list in addrs.items():
        iface_stats = stats.get(name)
        if not iface_stats or not iface_stats.isup:
            continue

        ip = None
        netmask = None
        for addr in addr_list:
            if addr.family == 2:  # AF_INET
                ip = addr.address
                netmask = addr.netmask
                break

        if ip and netmask and not ip.startswith("127."):
            adapters.append({
                "name": name,
                "ip": ip,
                "netmask": netmask,
            })

    return adapters