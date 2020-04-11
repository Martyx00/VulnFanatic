res = ""
with open('rule.txt') as f:
    for line in f:
        res += line.strip()

print(res)