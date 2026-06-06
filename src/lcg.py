#Linear congruential generators
#seed = starting value = x
#a = multiplier
#c = increment
# m =  just to keep a set range
#very easily predicted

def lcg(seed, a, c, m, n):
    x = seed
    numbers = []

    for _ in range(n):
        x = (a * x + c) % m
        numbers.append(x)

    return numbers


# print(lcg(seed=1, a=2, c=3, m=9, n=10))
# used in c/c++
print(numbers := lcg(seed=1, a=1103515245, c=12345, m=2**31, n=10000))
# print(raw_bits := lcg(seed=1, a=1103515245, c=12345, m=2, n=100000))

def lcg_research(seed, n):
    a = 1103515245
    c = 12345
    m = 2**31

    X = seed
    lsb_bits = []
    msb_bits = []

    for _ in range(n):
        X = (a * X + c) % m

        # Extract Least Significant Bit (the far right bit)
        lsb_bits.append(X % 2)

        # Extract Most Significant Bit (the far left bit of a 31-bit integer)
        msb_bits.append(X >> 30)

    return lsb_bits, msb_bits

# Generate 100,000 samples for your dataset
lsb_data, msb_data = lcg_research(seed=1, n=100000)
# print(msb_data)
# print(numbers)