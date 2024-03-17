---
layout: post
title: Cyber Apocalypse 2024 - ROT128
date: 2024-03-17T17:22:12+10:30
summary: A mathematician’s solution to ROT128
author:	lachlan
categories:
  - ctf
  - write-ups
  - pwn
math: true
---

# Cyber Apocalypse 2024 - ROT128
> In the eerie stillness of the Bitting village, a dilapidated laboratory lies forgotten and forsaken, its ancient walls whispering secrets of unspeakable horrors. As you awaken within its confines, a shiver runs down your spine, the air thick with the weight of untold darkness. With no recollection of how you came to be here, you begin to explore the place. The dim glow of flickering lights casts long shadows across the worn floors, revealing rusted equipment and decaying machinery. The air is heavy with the scent of decay and abandonment, a tangible reminder of the atrocities that once transpired within these walls. Soon, you uncover the sinister truth lurking within the laboratory's forgotten depths. This place was a chamber of horrors, a breeding ground for abominable experiments in human cloning. The realization sends chills coursing through your veins, your mind reeling at the thought of the atrocities committed in the name of science. But there is no time to dwell on the horrors of the past, because a sinister countdown echoes through the laboratory, its ominous tones a harbinger of impending doom. Racing against the ticking clock, you discover the source of the impending catastrophe—a chemical reactor primed to unleash devastation upon the village. With the weight of the world upon your shoulders, you realize that you alone possess the knowledge to defuse the deadly device. As a chemist, you understand the delicate balance of chemical reactions, and you know that triggering a specific collision multiple times is the key to averting disaster. With steady hands and a racing heart, you get to work. As the seconds tick away, you feel the weight of the world bearing down upon you, but you refuse to falter.

In this challenge, we are provided the source code to the server running. In summary, the server is generating a random 32 byte message (`buffer`) and is hashing it with the random state $(r_1, r_2, r_3, r_4, K_1, K_2)$ using the following code;

```python
N = 128

class HashRoll:
    def __init__(self):
        self.reset_state()

    def hash_step(self, i):
        r1, r2 = self.state[2*i], self.state[2*i+1]
        return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)

    def update_state(self, state=None):
        if not state:
            self.state = [0] * 6
            self.state[:4] = [random.randint(0, N) for _ in range(4)]
            self.state[-2:] = [random.randint(0, 2**N) for _ in range(2)]
        else:
            self.state = state

    def reset_state(self):
        self.update_state()

    def digest(self, buffer):
        buffer = int.from_bytes(buffer, byteorder='big')
        m1 = buffer >> N
        m2 = buffer & (2**N - 1)
        self.h = b''
        for i in range(2):
            self.h += int.to_bytes(self.hash_step(i) ^ (m1 if not i else m2), length=N//8, byteorder='big')
        return self.h
```

Our goal is to input states $(r_1,r_2,r_3,r_4,K_1, K_2) \in \mathbb{Z}_N^4 \times \mathbb{Z}\_{2^N-1}^2$ such that we get a hash collision (same hash and plaintexts, different states). There are a total of 3 rounds, and each time, the server gives us the plaintext and the result of the hash:

> H(8a9d3871eaa65c69c88bac3aa6b821cc730383dbf0b6e124e439c82d2927b74d) = 981aa55dfa699f4970c94d08dca82cfddde61e903eba6a3d8e12f91332f15583

To solve this challenge, I first noticed that we can easily recover the results of the `hash_step` function just by splitting the resultant hash into 16 byte blocks and xoring them with the corresponding 16 byte blocks of the plain text. The following code achieves this;

```python
# Break the plaintext (pt) into 16 byte blocks
pt0 = pt >> N
pt1 = pt & (2**N - 1)

# Break the hash into 16 byte blocks
ht0 = hash >> N
ht1 = hash & (2**(N) - 1)

# Recover the hash_step results
H0 = pt0 ^^ ht0
H1 = pt1 ^^ ht1
```

As we cannot control the plaintext, our only way to get a hash collision is to pick a state that produces the same output from the `hash_step` function with the server's random state. So let us look at the `hash_step` function more closely:

## The Hash Step Function

The `hash_step` function has code
```python
def hash_step(self, i):
    r1, r2 = self.state[2*i], self.state[2*i+1]
    return _ROL_(self.state[-2], r1) ^ _ROL_(self.state[-1], r2)
```
where the `_ROL_` function is a 128-bit binary rotate left / circular bit shift. In summary, the code is giving us;
$$
H_0 = (K_1 \lll r_1)\oplus(K_2 \lll r_2)\\\
H_1 = (K_1 \lll r_3)\oplus(K_2 \lll r_4),
$$
where $H_0$ and $H_1$ are the results of `hash_step(0)` and `hash_step(1)` respectively. It is this intertwining of $K_1$ and $K_2$ which makes this challenge difficult. If it were that $H_0$ was only a function of $K_1$ and $H_1$ only a function of $K_2$, it would be much simplier. Nonetheless, we know $H_0$ and $H_1$, and thus we need to pick an appropriate $r_1, ..., r_4, K_1, K_2$ which will give us our desired values of $H_1$ and $H_2$. To do this, let us assert that $r_1, r_3 = 0$ (we can do this as rotations are relative). With some simple rearrangements, we get the equations
$$
K_1 = H_0 \oplus (K_2 \lll r_2)\\\
K_1 = H_1\oplus(K_2 \lll r_4). \tag{1}
$$
which gives
$$
H_0 \oplus (K_2 \lll r_2) = H_1\oplus(K_2 \lll r_4)\\\
\implies H_0 \oplus H_1 = (K_2 \lll r_2) \oplus (K_2 \lll r_4).
$$
Finally, if we assert $r_2 = 0$, we get
$$H_0 \oplus H_1 = K_2 \oplus (K_2 \lll r_4).$$
This equation is much simpler to solve. To solve it, we will consider $K_2$ and $H_0$ as vectors in $\mathbb{Z}_2^N$. We chose this field as XOR of two numbers becomes addition over their corresponding vectors. In otherwords,

$$(\mathbb{Z}\_{2^N-1}, \oplus) \cong (\mathbb{Z}_2^N, +)$$

through the map $f : \mathbb{Z}\_{2^N-1} \to \mathbb{Z}_2^N$ defined by

$$[f(x)]_j = \left[f\left(\sum\_{i=0}^N c_i 2^i\right)\right]_j = c_j,$$

where $c_i \in \mathbb{Z}_2$.

Additionally, we can describe a left binary rotation by one bit through transformation corresponding to the block matrix
$$R = \begin{bmatrix}
0 & 1\\\
\mathbb{I}\_{N-1} & 0
\end{bmatrix},$$
where $\mathbb{I}\_{N-1}$ is the identity matrix of size $N$. With this, we can rewrite the defining equation of $K_2$ as
$$
    (R^{r_4} + \mathbb{I}_N) f(K_2) = f(H_0 \oplus H_1) = f(H_0) + f(H_1). \tag{2}
$$
This equation can be efficently solved! To do this, we will use [SageMath](https://www.sagemath.org/). The following code sets up the equation and solve it:
```sage
# Defining N
N = 12

# Defining the Galois field (Z_2)
F = GF(2)

# Defining isomorpism maps
isoMap = lambda n: vector(F, [0 if n & 2**i == 0 else 1 for i in range(N)])
invIsoMap = lambda b: sum([b[i] * 2 ** i for i in range(len(b))])

# Creating rotation matrix and identity matrix
R = matrix(GF(2), N, N, lambda i,j: (i - 1) % N == j)
I = identity_matrix(F, N)

# Creating the matrix on the LHS of the defining equation
M = R**r4 + I

# Solving for K_2
K2 = M.solve_right(isoMap(H0) + isoMap(H1))
K2 = invIsoMap(K2)
```

This does however beg one question: what is $r_4$? While there might be some ways to calculate valid values of $r_4$, it is just easier to bruteforce a value of $r_4$ as we have to check at most $N$ (128) values of $r_4$ before we find a valid one. In fact, this value is even lower, as if the random state used on the server had an $r_4$ value of $r_4'$, then there will be
$$\frac{N}{gcd(N, r_4')}$$
valid values of $r_4$. Thus as solving *equation (2)* is very efficient, we can do this within a very short time -- short enough before the server disconnects us. From here, we can simply calculate $K_1$ via *equation (1)*.

## The Final Solution

Put all together, we have the following steps to our solution:
1. Split the hash and plaintext into 2 blocks of 16 bytes each
2. Calculate $H_1$ and $H_2$ by xoring the corresponding plaintext and hash blocks
3. Xor $H_1$ and $H_2$ and solve for $K_2$ using *equation (2)*
4. Calculate $K_1$ from $K_2$ using *equation (1)*
5. Send back the new key $(0, 0, 0, r_4, K_1, K_2)$
6. Repeat for all 3 rounds!

Putting this all together using `pwntools` and SageMath gives us the following script
> {{<details "`solution.sage`">}}
```sage
from pwn import *

# Defining N
N = 128

# Defining the Galois field (Z_2)
F = GF(2)

# Defining isomorpism maps
isoMap = lambda n: vector(F, [0 if n & 2**i == 0 else 1 for i in range(N)])
invIsoMap = lambda b: sum([int(b[i]) * 2 ** i for i in range(len(b))])

# Creating rotation matrix and identity matrix
R = matrix(GF(2), N, N, lambda i,j: (i - 1) % N == j)
I = identity_matrix(F, N)

# Connecting to server
addr = "94.237.49.166"
port = 40937
local = False

if local:
    shell = process(["python", "server.py"])
else:
    shell = remote(addr, port)

# Clearing out server intro
shell.recvline()

# Making an array for used states cannot be reused
usedStates = []

for i in range(3):
    # Getting plaintext and hash
    info = shell.recvlines(2)[-1].split(b" ")
    pt = int(info[2][2:-1], 16)
    hash = int(info[-1], 16)

    # Break the plaintext (pt) into 16 byte blocks
    pt0 = pt >> N
    pt1 = pt & (2**N - 1)

    # Break the hash into 16 byte blocks
    ht0 = hash >> N
    ht1 = hash & (2**(N) - 1)

    # Recover the hash_step results
    H0 = pt0 ^^ ht0
    H1 = pt1 ^^ ht1


    # For loop over possible r4
    for r4 in range(2,N):
        if r4 in usedStates:
            continue

        # Creating the matrix on the LHS of the defining equation
        M = R**r4 + I

        # Solving for K_2
        try:
            K2 = M.solve_right(isoMap(H0) + isoMap(H1))
        except:
            continue

        # Calculating K_1
        K1 = isoMap(H1) + (R**r4) * K2

        # Converting K1 and K2 to numbers
        K1 = invIsoMap(K1)
        K2 = invIsoMap(K2)

        # Sending state back to server
        state = [0, 0, 0, r4, K1, K2]
        usedStates.append(r4)

        response = ','.join(map(str, state))
        shell.sendline(response.encode())
        shell.recvline()
        break

print(shell.recvline().split(b" ")[-1])
shell.close()
```
{{</details>}}


This gives us the flag

`HTB{k33p_r0t4t1ng_4nd_r0t4t1ng_4nd_x0r1ng_4nd_r0t4t1ng!}`
