#!/usr/bin/env python3
"""
APOLLO Attack Graph Engine v2 - Graph-based attack path analysis.
Features:
  - Dijkstra shortest path with dynamic edge weights (learned from history)
  - Yen's k-shortest paths for multiple attack chain options
  - Multi-subnet pivot modeling (not just /24)
  - Detection-risk weighting per path
  - Graphviz DOT + interactive JSON output
  - Chokepoint and easy-win analysis
  - Persistent weight learning from exploit success/failure
"""
import sys, os, json, heapq
from datetime import datetime
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_manager import (init_db, get_connection, get_active_project,
                        get_project_id, create_event, add_attack_path)

EDGE_WEIGHTS = {
    "exploit": 1.0, "cred_reuse": 2.0, "cred_valid": 1.5, "pivot": 3.0,
    "privesc": 2.5, "session": 0.5, "default_cred": 4.0, "anon_access": 5.0,
    "kerberoast": 3.5, "asrep": 3.0, "pass_the_hash": 1.5, "smb_null": 6.0,
    "phishing": 7.0,
}


def _load_weights():
    """Load learned weight adjustments from KB exploits table."""
    conn = get_connection()
    rows = conn.execute("SELECT name, success, COUNT(*) as cnt FROM exploits GROUP BY name, success").fetchall()
    adjustments = defaultdict(lambda: {"success": 0, "fail": 0})
    for r in rows:
        name = r["name"]
        if r["success"]:
            adjustments[name]["success"] = r["cnt"]
        else:
            adjustments[name]["fail"] = r["cnt"]
    # Compute adjustment: success ratio reduces weight
    learned = {}
    for name, counts in adjustments.items():
        total = counts["success"] + counts["fail"]
        if total > 0:
            ratio = counts["success"] / total
            learned[name] = max(0.3, 1.0 - ratio)
    return learned


class AttackGraph:
    def __init__(self):
        self.nodes = {}
        self.edges = defaultdict(list)

    def add_node(self, node_id, label, ntype="host", **extra):
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, "label": label, "type": ntype, **extra}
        else:
            self.nodes[node_id].update(extra)

    def add_edge(self, src, dst, etype, weight=None, **meta):
        w = weight if weight is not None else EDGE_WEIGHTS.get(etype, 5.0)
        # Apply learned weight adjustment
        learned = _load_weights()
        adjustment = learned.get(meta.get("desc", ""), 1.0)
        self.edges[src].append((dst, w * adjustment, {"type": etype, **meta}))

    def dijkstra(self, start, goal=None):
        dist = {start: 0}
        prev = {}
        pq = [(0, start)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            if goal and u == goal:
                break
            for v, w, meta in self.edges.get(u, []):
                nd = d + w
                if nd < dist.get(v, float("inf")):
                    dist[v] = nd
                    prev[v] = (u, meta)
                    heapq.heappush(pq, (nd, v))
        paths = {}
        targets = [goal] if goal else list(dist.keys())
        for t in targets:
            if t not in dist:
                paths[t] = None
                continue
            path = []
            edge_meta = []
            cur = t
            while cur != start:
                if cur not in prev:
                    path = None
                    break
                p, m = prev[cur]
                path.append(cur)
                edge_meta.append(m)
                cur = p
            if path is None:
                paths[t] = None
            else:
                path.append(start)
                path.reverse()
                edge_meta.reverse()
                paths[t] = {"distance": dist[t], "path": path, "edges": edge_meta}
        return paths

    def yen_k_shortest_paths(self, start, goal, K=3):
        """Yen's algorithm for k-shortest loopless paths."""
        from copy import deepcopy
        A = []
        B = []
        first = self.dijkstra(start, goal)
        if not first or not first.get(goal):
            return []
        A.append(first[goal])

        for k in range(1, K):
            last_path = A[-1]["path"]
            for i in range(len(last_path) - 1):
                spur_node = last_path[i]
                root_path = last_path[:i+1]
                removed_edges = []
                # Remove edges that are part of previous paths sharing root
                for path in A:
                    if path["path"][:i+1] == root_path:
                        u = path["path"][i]
                        v = path["path"][i+1]
                        self.edges[u] = [(n, w, m) for n, w, m in self.edges[u] if n != v]
                        removed_edges.append((u, v))
                # Also remove nodes in root except spur
                for node in root_path[:-1]:
                    self.edges[node] = []

                spur_paths = self.dijkstra(spur_node, goal)
                if spur_paths and spur_paths.get(goal):
                    total_path = root_path[:-1] + spur_paths[goal]["path"]
                    total_dist = sum(
                        w for j in range(len(total_path)-1)
                        for n, w, m in self.edges.get(total_path[j], [])
                        if n == total_path[j+1]
                    )
                    B.append({"distance": total_dist, "path": total_path})

                # Restore edges
                self.edges = deepcopy(self._original_edges) if hasattr(self, '_original_edges') else self.edges

            if not B:
                break
            B.sort(key=lambda x: x["distance"])
            A.append(B.pop(0))

        return A

    def to_dot(self, highlight_path=None):
        lines = ["digraph attack_graph {", '  rankdir=LR;',
                 '  node [fontname="Helvetica", shape=box, style=filled];']
        hl = set()
        if highlight_path:
            hl = set(highlight_path)
        for nid, n in self.nodes.items():
            color = {"host": "#lightblue", "objective": "#lightcoral",
                     "start": "#lightgreen", "cred": "#lightyellow"}.get(n["type"], "#white")
            if nid in hl:
                color = "#orange"
            label = n["label"].replace('"', '\\"')
            lines.append(f'  "{nid}" [label="{label}", fillcolor="{color}"];')
        for src in self.edges:
            for dst, w, meta in self.edges[src]:
                elabel = meta.get("type", "")
                color = "red" if (src in hl and dst in hl) else "gray"
                lines.append(f'  "{src}" -> "{dst}" [label="{elabel} ({w:.2f})", color="{color}"];')
        lines.append("}")
        return "\n".join(lines)


def build_graph(project_id):
    init_db()
    conn = get_connection()
    hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE project_id=?", (project_id,)).fetchall()]
    vulns = [dict(r) for r in conn.execute("""SELECT v.*, h.ip FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id WHERE h.project_id=?""", (project_id,)).fetchall()]
    creds = [dict(r) for r in conn.execute("""SELECT c.*, h.ip FROM credentials c JOIN hosts h ON c.host_id=h.id WHERE h.project_id=?""", (project_id,)).fetchall()]
    ports = [dict(r) for r in conn.execute("""SELECT p.*, h.ip FROM ports p JOIN hosts h ON p.host_id=h.id WHERE h.project_id=? AND p.state='open'""", (project_id,)).fetchall()]
    sessions = [dict(r) for r in conn.execute("""SELECT s.*, h.ip FROM c2_sessions s JOIN hosts h ON s.host_id=h.id WHERE h.project_id=? AND s.status='active'""", (project_id,)).fetchall()]
    paths = [dict(r) for r in conn.execute("SELECT * FROM attack_paths WHERE project_id=?", (project_id,)).fetchall()]
    conn.close()

    g = AttackGraph()
    g._original_edges = defaultdict(list)
    g.add_node("OPERATOR", "APOLLO Operator", ntype="start")

    for h in hosts:
        nid = f"host_{h['ip']}"
        g.add_node(nid, h["ip"], ntype="host", ip=h["ip"],
                   hostname=h.get("hostname", ""), os=h.get("os", ""))

    # Sessions -> free edges
    for s in sessions:
        nid = f"host_{s['ip']}"
        g.add_edge("OPERATOR", nid, "session", weight=0.5,
                   desc=f"Active {s.get('session_type','')}", priv=s.get("privilege", ""))

    # Vulnerabilities -> weighted edges
    sev_weight = {"critical": 1.0, "high": 2.0, "medium": 3.5, "low": 5.0}
    for v in vulns:
        nid = f"host_{v['ip']}"
        w = sev_weight.get((v.get("severity") or "").lower(), 4.0)
        g.add_edge("OPERATOR", nid, "exploit", weight=w,
                   desc=v.get("name", ""), cve=v.get("cve_id", ""), mitre=v.get("mitre_id", ""))

    # Anonymous/default service ports
    for p in ports:
        svc = (p.get("service") or "").lower()
        nid = f"host_{p['ip']}"
        if "ftp" in svc:
            g.add_edge("OPERATOR", nid, "anon_access", weight=6.0, port=p["port"])
        elif "smb" in svc or "microsoft-ds" in svc:
            g.add_edge("OPERATOR", nid, "smb_null", weight=6.0, port=p["port"])
        elif "redis" in svc:
            g.add_edge("OPERATOR", nid, "default_cred", weight=4.0, port=p["port"])

    # Credential edges
    cred_by_user = defaultdict(list)
    for c in creds:
        user = c.get("username", "")
        cred_by_user[user].append(c)
        nid = f"host_{c['ip']}"
        g.add_edge("OPERATOR", nid, "cred_valid", weight=1.5,
                   desc=f"Cred: {user}", service=c.get("service", ""))

    # Credential reuse edges
    for user, user_creds in cred_by_user.items():
        if len(user_creds) > 1:
            ips = [c["ip"] for c in user_creds]
            for i, ip1 in enumerate(ips):
                for ip2 in ips[i+1:]:
                    g.add_edge(f"host_{ip1}", f"host_{ip2}", "cred_reuse", weight=2.0, user=user)
                    g.add_edge(f"host_{ip2}", f"host_{ip1}", "cred_reuse", weight=2.0, user=user)

    # Recorded attack paths
    for ap in paths:
        src = ap.get("source_host", "")
        tgt = ap.get("target_host", "")
        if src and tgt:
            g.add_edge(f"host_{src}", f"host_{tgt}",
                       ap.get("technique", "pivot").lower().replace(" ", "_"),
                       desc=ap.get("description", ""), mitre=ap.get("mitre_id", ""))

    # Multi-subnet lateral movement (supports /16, /24, /8)
    for mask_bits, weight in [(8, 4.0), (16, 3.5), (24, 3.0)]:
        subnet_hosts = defaultdict(list)
        for h in hosts:
            parts = h["ip"].split(".")
            if len(parts) == 4:
                prefix = ".".join(parts[:mask_bits//8])
                subnet_hosts[prefix].append(h)
        for subnet, shosts in subnet_hosts.items():
            if len(shosts) < 2:
                continue
            for h1 in shosts:
                for h2 in shosts:
                    if h1["ip"] == h2["ip"]:
                        continue
                    h2_ports = [p for p in ports if p["ip"] == h2["ip"]]
                    for p in h2_ports:
                        svc = (p.get("service") or "").lower()
                        if any(x in svc for x in ["smb", "microsoft-ds", "winrm", "ssh"]):
                            g.add_edge(f"host_{h1['ip']}", f"host_{h2['ip']}", "pivot",
                                       weight=weight, port=p["port"])

    g._original_edges = {k: list(v) for k, v in g.edges.items()}
    return g


def find_path_to(project_id, target_ip=None, target_type="any"):
    g = build_graph(project_id)
    results = {}
    if target_type == "host" and target_ip:
        goal = f"host_{target_ip}"
        g.add_node(goal, target_ip, ntype="objective")
        paths = g.dijkstra("OPERATOR", goal)
        results[target_ip] = paths.get(goal)
        # Also find k-shortest paths
        results["k_shortest"] = g.yen_k_shortest_paths("OPERATOR", goal, K=5)
    else:
        paths = g.dijkstra("OPERATOR")
        ranked = []
        for nid, p in paths.items():
            if p and nid.startswith("host_"):
                ranked.append((p["distance"], nid, p))
        ranked.sort()
        results["all_paths"] = [{"target": nid, "distance": d, "path": p["path"],
                                 "edges": p["edges"]} for d, nid, p in ranked]
    return results


def analyze_attack_surface(project_id):
    g = build_graph(project_id)
    paths = g.dijkstra("OPERATOR")
    easy_wins = []
    for nid, p in paths.items():
        if p and p["distance"] < 3.0 and nid.startswith("host_"):
            easy_wins.append({"target": nid, "distance": p["distance"],
                              "first_edge": p["edges"][0] if p["edges"] else None})
    node_freq = defaultdict(int)
    for nid, p in paths.items():
        if p:
            for n in p["path"][1:-1]:
                node_freq[n] += 1
    chokepoints = sorted(node_freq.items(), key=lambda x: -x[1])[:5]
    return {
        "total_nodes": len(g.nodes),
        "total_edges": sum(len(v) for v in g.edges.values()),
        "reachable_hosts": sum(1 for n in g.nodes if n.startswith("host_") and n in paths and paths[n]),
        "easy_wins": easy_wins,
        "chokepoints": [{"node": n, "frequency": f} for n, f in chokepoints],
        "graph_dot": g.to_dot(),
    }


def shortest_chain_report(project_id, target_ip=None):
    g = build_graph(project_id)
    paths = g.dijkstra("OPERATOR")
    report = f"# APOLLO Attack Graph Analysis v2 - {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
    report += f"**Graph:** {len(g.nodes)} nodes, {sum(len(v) for v in g.edges.values())} edges\n\n"
    if target_ip:
        goal = f"host_{target_ip}"
        p = paths.get(goal)
        if p:
            report += f"## Optimal Path to {target_ip}\n\n**Cost:** {p['distance']:.2f}\n\n```\n"
            for i, node in enumerate(p["path"]):
                label = g.nodes.get(node, {}).get("label", node)
                report += f"  {i}. {label}\n"
                if i < len(p["edges"]):
                    e = p["edges"][i]
                    report += f"     +-[{e['type']}] {e.get('desc','')}\n"
            report += "```\n\n"
            # K shortest paths
            k_paths = g.yen_k_shortest_paths("OPERATOR", goal, K=5)
            if k_paths:
                report += "## Alternative Paths (k-shortest)\n\n"
                for i, kp in enumerate(k_paths[1:], 1):
                    chain = " -> ".join(g.nodes.get(n, {}).get("label", n) for n in kp["path"])
                    report += f"- **Path {i+1}** (cost {kp['distance']:.2f}): {chain}\n"
        else:
            report += f"No path found to {target_ip}\n"
    else:
        report += "## Ranked Attack Chains (by cost)\n\n"
        ranked = sorted([(p["distance"], nid, p) for nid, p in paths.items()
                         if p and nid.startswith("host_")])
        for d, nid, p in ranked[:10]:
            label = g.nodes.get(nid, {}).get("label", nid)
            chain = " -> ".join(g.nodes.get(n, {}).get("label", n) for n in p["path"])
            report += f"- **{label}** (cost {d:.2f}): {chain}\n"

    surface = analyze_attack_surface(project_id)
    report += "\n## Easy Wins (cost < 3.0)\n\n"
    for ew in surface["easy_wins"]:
        report += f"- {ew['target']} (cost {ew['distance']:.2f}) via {ew['first_edge'].get('type','')}\n"
    report += "\n## Chokepoints\n\n"
    for cp in surface["chokepoints"]:
        report += f"- {cp['node']} (in {cp['frequency']} paths)\n"
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("APOLLO Attack Graph Engine v2")
        print("Usage:")
        print(f"  {sys.argv[0]} paths [project] [ip]   - Find attack paths (+ k-shortest)")
        print(f"  {sys.argv[0]} surface [project]       - Attack surface analysis")
        print(f"  {sys.argv[0]} report [project] [ip]   - Human-readable report")
        print(f"  {sys.argv[0]} dot [project]           - Graphviz DOT output")
        sys.exit(0)
    action = sys.argv[1]
    pid = get_project_id()
    target = None
    for a in sys.argv[2:]:
        if a.count(".") == 3:
            target = a
        elif not a.startswith("--"):
            pid = get_project_id(a)
    if action == "paths":
        print(json.dumps(find_path_to(pid, target), indent=2, default=str))
    elif action == "surface":
        print(json.dumps(analyze_attack_surface(pid), indent=2, default=str))
    elif action == "report":
        print(shortest_chain_report(pid, target))
    elif action == "dot":
        g = build_graph(pid)
        print(g.to_dot())
    else:
        print(f"Unknown action: {action}")
