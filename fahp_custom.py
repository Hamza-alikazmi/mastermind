import numpy as np

def fahp(matrix):
    n = len(matrix)
    fuzzy_sums = [np.zeros(3) for _ in range(n)]

    for i in range(n):
        for j in range(n):
            fuzzy_sums[i] += np.array(matrix[i][j])

    total_sum = np.sum(fuzzy_sums, axis=0)

    weights = []
    for i in range(n):
        l = fuzzy_sums[i][0] / total_sum[2]
        m = fuzzy_sums[i][1] / total_sum[1]
        u = fuzzy_sums[i][2] / total_sum[0]
        weights.append((l + m + u) / 3)

    weights = np.array(weights)
    return weights / np.sum(weights)
