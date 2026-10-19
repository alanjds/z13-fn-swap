import re, sys
MAIN = {0x8: "Input", 0x9: "Output", 0xB: "Feature", 0xA: "Collection", 0xC: "End Collection"}
GLOBAL = {0x0: "Usage Page", 0x1: "Logical Minimum", 0x2: "Logical Maximum", 0x7: "Report Size",
          0x8: "Report ID", 0x9: "Report Count", 0x3: "Physical Minimum", 0x4: "Physical Maximum",
          0x5: "Unit Exponent", 0x6: "Unit"}
LOCAL = {0x0: "Usage", 0x1: "Usage Minimum", 0x2: "Usage Maximum"}
def decode(b):
    i, depth, out = 0, 0, []
    while i < len(b):
        p = b[i]; size = [0, 1, 2, 4][p & 3]; typ = (p >> 2) & 3; tag = p >> 4
        d = b[i + 1:i + 1 + size]; v = int.from_bytes(bytes(d), "little")
        name = {0: MAIN, 1: GLOBAL, 2: LOCAL}.get(typ, {}).get(tag, f"?{p:02x}")
        if name == "End Collection": depth -= 1
        sv = v - (1 << (8 * size)) if name.startswith("Logical") and size and v >> (8 * size - 1) else v
        arg = ""
        if name in ("Input", "Output", "Feature"):
            arg = ",".join(["Const" if v & 1 else "Data", "Var" if v & 2 else "Array", "Rel" if v & 4 else "Abs"])
        elif name == "Collection":
            arg = {0: "Physical", 1: "Application", 2: "Logical"}.get(v, hex(v))
        elif size:
            arg = f"0x{v:0{2 * size}x}" if name in ("Usage Page", "Usage", "Usage Minimum", "Usage Maximum", "Report ID") else str(sv)
        hexs = " ".join(f"{x:02x}" for x in b[i:i + 1 + size])
        out.append(f"{i:4d}  {hexs:<14} {'  ' * depth}{name} ({arg})" if arg else f"{i:4d}  {hexs:<14} {'  ' * depth}{name}")
        if name == "Collection": depth += 1
        i += 1 + size
    return out
cur = None; data = {}
for line in open(sys.argv[1]):
    m = re.match(r"== (\S+)", line)
    if m: cur = m.group(1); data[cur] = []; continue
    data[cur] += [int(x, 16) for x in line.split()]
for k, b in data.items():
    print(f"### {k} ({len(b)} bytes)")
    print(*decode(b), sep="\n")
