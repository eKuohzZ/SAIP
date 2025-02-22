def balanced_graph(ids):
    n = len(ids)  # 点的总数
    out_degrees = {id: 0 for id in ids}  # 初始化每个点的出度
    in_degrees = {id: 0 for id in ids}   # 初始化每个点的入度
    graph = {}  # 存储边的字典

    # 对于每个点，依次进行轮换，确保出度和入度尽量平衡
    for i in range(n):
        # 当前点的编号
        current_id = ids[i]
        graph[current_id] = []

        # 从当前点向其他点发送边，保证尽量平衡出度和入度
        for j in range(1, (n // 2) + 1):
            # 计算目标点的编号
            target_id = ids[(i + j) % n]
            
            # 只要出度和入度没有达到上限，就添加边
            if out_degrees[current_id] < (n - 1) // 2 and in_degrees[target_id] < (n - 1) // 2:
                graph[current_id].append(target_id)
                out_degrees[current_id] += 1
                in_degrees[target_id] += 1

    return graph

ids = [1, 2, 3, 4, 5]
graph = balanced_graph(ids)
for node, edges in graph.items():
    print(f"Node {node} -> {edges}")
