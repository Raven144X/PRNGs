#%%
class MT19937:
    def __init__(self, seed):
        # Constants for MT19937
        self.w = 32
        self.n = 624
        self.m = 397
        self.r = 31

        self.a = 0x9908B0DF

        self.u = 11
        self.d = 0xFFFFFFFF

        self.s = 7
        self.b = 0x9D2C5680

        self.t = 15
        self.c = 0xEFC60000

        self.l = 18

        self.f = 1812433253

        # Create state array
        self.MT = [0] * self.n

        # Current index
        self.index = self.n

        # Lower r bits
        self.lower_mask = (1 << self.r) - 1

        # Upper w-r bits
        self.upper_mask = (~self.lower_mask) & 0xFFFFFFFF

        # Initialize generator
        self.seed_mt(seed)

    def seed_mt(self, seed):
        self.index = self.n
        self.MT[0] = seed

        for i in range(1, self.n):
            temp = self.MT[i - 1]

            self.MT[i] = (
                self.f * (temp ^ (temp >> (self.w - 2))) + i
            ) & 0xFFFFFFFF

    def extract_number(self):
        if self.index >= self.n:
            self.twist()

        y = self.MT[self.index]

        # Tempering
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)

        self.index += 1

        return y & 0xFFFFFFFF

    def twist(self):
        for i in range(self.n):

            x = (
                (self.MT[i] & self.upper_mask)
                + (self.MT[(i + 1) % self.n] & self.lower_mask)
            )

            xA = x >> 1

            if x % 2 != 0:
                xA = xA ^ self.a

            self.MT[i] = (
                self.MT[(i + self.m) % self.n] ^ xA
            )

        self.index = 0


# Example usage
mt = MT19937(1948)

for _ in range(41):
    print(mt.extract_number())