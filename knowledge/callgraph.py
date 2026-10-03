"""Call-graph ordering: process callees before their callers."""


def bottom_up_levels(callees: dict) -> list:
    """
    `callees` maps address -> iterable of callee addresses (edges to unknown
    addresses are ignored). Returns a list of levels; level 0 holds leaf
    functions, and every function's callees sit on an earlier level, except
    within a recursive cycle, whose members share one level. Functions on
    the same level are independent and can be processed in parallel.
    """
    nodes = list(callees)
    node_set = set(nodes)
    graph = {n: [c for c in callees[n] if c in node_set and c != n] for n in nodes}

    # Iterative Tarjan SCC.
    index, low, on_stack, stack, comp_of, comps = {}, {}, set(), [], {}, []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work = [(root, iter(graph[root]))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(graph[nxt])))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp_of[w] = len(comps)
                    comp.append(w)
                    if w == node:
                        break
                comps.append(comp)

    # Tarjan emits components in reverse topological order of the
    # condensation: every component's callees are emitted before it.
    level_of = {}
    for ci, comp in enumerate(comps):
        deps = {comp_of[c] for n in comp for c in graph[n] if comp_of[c] != ci}
        level_of[ci] = 1 + max((level_of[d] for d in deps), default=-1)

    levels = [[] for _ in range(1 + max(level_of.values(), default=-1))]
    for ci, comp in enumerate(comps):
        levels[level_of[ci]].extend(sorted(comp))
    return [sorted(lv) for lv in levels]
