
import random
from pathlib import Path

# Generate a reproducible routing table.
random.seed(42)

output = Path("data/routes_large.txt")
output.parent.mkdir(parents=True, exist_ok=True)

routes = {
    # Keep a default route so every destination has a fallback.
    "0.0.0.0/0": "192.168.1.1"
}

# Generate unique IPv4 prefixes of varying lengths.
while len(routes) < 10_000:
    prefix = random.choice([8, 12, 16, 20, 24, 28, 32])

    # Generate a random IPv4 address.
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))

    # Normalize the address to its network prefix.
    octets = list(map(int, ip.split(".")))
    value = (
        (octets[0] << 24)
        | (octets[1] << 16)
        | (octets[2] << 8)
        | octets[3]
    )
    mask = 0 if prefix == 0 else (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = value & mask

    normalized_ip = ".".join(
        str((network >> shift) & 255)
        for shift in (24, 16, 8, 0)
    )
    cidr = f"{normalized_ip}/{prefix}"

    # Assign a random next-hop address.
    next_hop = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    routes[cidr] = next_hop

with output.open("w") as file:
    for cidr, hop in routes.items():
        file.write(f"{cidr} {hop}\n")

print(f"Generated {len(routes)} routes: {output}")
