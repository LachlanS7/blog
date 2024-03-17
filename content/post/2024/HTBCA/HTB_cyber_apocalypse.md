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

In this write up, I aim to provide a rigorous explanation of the insane *Cyber Apocalypse 2024* challenge; *ROT128*. However, as I provide a fairly mathematical solution, I have included a very quick `background` section below.

## Background
In this background section, I do not aim to fully introduce the concepts, nor be very technical, but merely make you familiar with these concepts and aware of their notations -- so you can recognise them in future challenges. I will introducing very simple group theory, and will assume a basic understanding of sets, functions, and linear algebra.
{{<details Background Information>}}

### Groups
- A binary operation, $\cdot$, over a set $A$ is a function / map that takes in two elements of $G$ and produces another element in $G$. It also has to be associative, meaning that
$$(a \cdot b) \cdot c = a \cdot (b \cdot c).$$
- A group is a set, $G$, along with a binary operation $\cdot$. We commonly denote the group as $(G, \cdot)$. The group must have;
    - An identity $O$. This is an element in $G$ which has the property $Ox=xO=x$ for all $x \in G$,
    - Inverse elements for each element in $G$. That is, for $x \in G$, there is an element $y$ such that $x \cdot y = y \cdot x = O$,
- Common examples of groups include
    - $(\mathbb{Z}_n, +)$: The integers modulo $n$. These are **SUPER** common in cryptography, and they are just the numbers $\\{0, ..., n-1\\}$ with addition (you would have encountered these if you've some programming).
    - $D\_{2n}$: The dihedral group on $2n$ vertices. This is the group of symmetries of a regular $2n$ sided polygon.
    - The integer points on a elliptic curve over a finite field forms a group. Their group structure is more complicated, however it gives rise to elliptic curve cryptography.
- In group theory, we are often wanting to compare groups to each other. When two groups, $(G, \cdot)$ and $(Q, \ast)$, behave similarly to each other, we say that they are homomorpic to each other, or write $G \cong Q$.
    - What it means for $G$ to be homomorphic to $Q$ is that we can map objects of $G$ into $Q$. Furthermore, operating on the elements of $G$ produces the same result as if we operated on them in $Q$. Mathematically, we would write
    $$f(x \cdot y) = f(x) \ast f(y),$$
    for $x,y \in G$, where $f : G \to Q$ is the function that maps elements elements in $G$ to elements in $Q$.
    - Despite the technical definition, the concept of homomorphisms is very common. If you have ever seen two scenarios in maths that look and behave similarly, you can almost be certain they were homomorphic! An example of this is the $n$-th roots of unity and the integers modulo $n$ ($\mathbb{Z}_n$).
    - We say that a homomorpism is an isomorphism if we can also map all element in $Q$ to a unique element in $G$.
    - A field is a group, $(G, \cdot)$, with another operation $\ast$ which also has an identity and inverses (except for the $O$ of $(G, \cdot)$).
        - An example of this is rational numbers with addition and multiplication.

{{</details>}}

## The Challenge

We can now begin to look at the challenge -- in which we are provided the source code to the server. In summary, the server is generating a random 32 byte message (`buffer`) and is hashing it with the random state $(r_1, r_2, r_3, r_4, K_1, K_2)$ using the following code;

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

We first noticed that we can easily recover the results of the `hash_step` function just by splitting the resultant hash into 16 byte blocks and xoring them with the corresponding 16 byte blocks of the plain text. The following code achieves this;

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

As we cannot control the plaintext, our only way to get a hash collision is to pick a state that produces the same output from the `hash_step` function with the server's random state. Let us look at the `hash_step` function more closely:

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
where $H_0$ and $H_1$ are the results of `hash_step(0)` and `hash_step(1)` respectively. It is this intertwining of $K_1$ and $K_2$ which makes this challenge difficult. If $H_0$ was only a function of $K_1$, and $H_1$ only a function of $K_2$, it would be much simpler. Nonetheless, we know $H_0$ and $H_1$, and thus we need to pick an appropriate $r_1, ..., r_4, K_1, K_2$ which will give us our desired values of $H_1$ and $H_2$. To do this, let us assert that $r_1, r_3= 0$ (more on this shortly). Then with some simple rearrangements, we get the equations
$$
K_1 = H_0 \oplus (K_2 \lll r_2)\\\
K_1 = H_1\oplus(K_2 \lll r_4). \tag{1}
$$
which by equating them, gives the equation
$$
H_0 \oplus (K_2 \lll r_2) = H_1\oplus(K_2 \lll r_4)\\\
\implies H_0 \oplus H_1 = (K_2 \lll r_2) \oplus (K_2 \lll r_4).
$$
Finally, if we assert $r_2 = 0$, we get
$$H_0 \oplus H_1 = K_2 \oplus (K_2 \lll r_4).$$
This equation is much simpler to solve. To solve it, we will consider $K_2$ and $H_0$ as vectors in $\mathbb{Z}_2^N$. We chose this field as XOR of two numbers becomes addition over their corresponding vectors. In other words,

$$(\mathbb{Z}\_{2^N-1}, \oplus) \cong (\mathbb{Z}_2^N, +)$$

through the map $f : \mathbb{Z}\_{2^N-1} \to \mathbb{Z}_2^N$ defined by

$$[f(x)]_j = \left[f\left(\sum\_{i=0}^N c_i 2^i\right)\right]_j = c_j,$$

where $c_i \in \mathbb{Z}_2$.

Additionally, we can describe a left binary rotation by one bit through the transformation corresponding to the block matrix
$$R = \begin{bmatrix}
0 & 1\\\
\mathbb{I}\_{N-1} & 0
\end{bmatrix},$$
where $\mathbb{I}\_{N-1}$ is the identity matrix of size $N$ (for clarity, $R\_{ij} = \delta\_{i-1, j}$). With this, we can rewrite the defining equation of $K_2$ as
$$
    (R^{r_4} + \mathbb{I}_N) f(K_2) = f(H_0 \oplus H_1) = f(H_0) + f(H_1). \tag{2}
$$
This equation can be efficiently solved! To do this, we will use [SageMath](https://www.sagemath.org/). The following code sets up the equation and solve it:
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

This does however beg one question: what is $r_4$? While there might be some ways to calculate valid values of $r_4$, it is just easier to bruteforce $r_4$ as we have to check at most $N$ (128) values of $r_4$ before we find a valid one (the existance of a valid $r_4$ is guaranteed from the construction of the hash using this algorithm). From here, we can simply calculate $K_1$ via *equation (1)*.

## The Final Solution

Put all together, we have the following steps to our solution:
1. Split the hash and plaintext into 2 blocks of 16 bytes each
2. Calculate $H_1$ and $H_2$ by xoring the corresponding plaintext and hash blocks
3. Xor $H_1$ and $H_2$ and solve for $K_2$ using *equation (2)*
4. Calculate $K_1$ from $K_2$ using *equation (1)*
5. Send back the new key $(0, 0, 0, r_4, K_1, K_2)$
6. Repeat for all 3 rounds!

To fully automate this (and because the server will time us out if we take too long), we will use `pwntools` and SageMath in the following script to implement our solution.
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

## Proof of Rotational Symmetry
In this section, I will give a supplementary proof as to why we can assert that $r_1, r_2, r_3 = 0$. First, we shall start with
$$
H_0 = (K_1 \lll r_1)\oplus(K_2 \lll r_2)\\\
H_1 = (K_1 \lll r_3)\oplus(K_2 \lll r_4).
$$
From the definition of binary rotation, we can first clearly see that
$$
(A \lll B) \lll C = (A \lll C) \lll B = A \lll (B + C),
$$
for all $A, B, C \in \mathbb{Z}\_{\geq 0}$. Furthermore, recognise that binary rotation is distributive over XOR as;
$$
    \left[(A \oplus B) \lll C\right]_i = \left[A \oplus B\right]\_{i + C}\\\
    = A\_{i+C} \oplus B\_{i+C}\\\
    = [A \lll C]_i \oplus [B \lll C]_i.
$$
where $A_i$ is the $i$-th bit of $A$.

Finally, notice that binary rotation if a bijection (with inverse right binary rotate), which means that we can transform equations using binary rotations without losing solutions. With this, if we consider rotating our equations for $H_0$ and $H_1$ by $r_3$ and $r_1$ respectively, we get;
$$
H_0\lll r_3 = [K_1 \lll (r_1 + r_3)]\oplus[K_2 \lll (r_2 + r_3)]\\\
H_1 \lll r_1 = [K_1 \lll (r_1 + r_3)]\oplus[K_2 \lll (r_1 + r_4)].
$$
Then by rearranging these for $K_1 \lll (r_1 + r_2)$, we get
$$
[K_1 \lll (r_1 + r_3)] = [H_0\lll r_3]\oplus[K_2 \lll (r_2 + r_3)]\\\
[K_1 \lll (r_1 + r_3)] = [H_1 \lll r_1]\oplus[K_2 \lll (r_1 + r_4)].
$$
By equating the RHS of each equations, we get the following equation
$$
[H_0\lll r_3]\oplus[K_2 \lll (r_2 + r_3)] = [H_1 \lll r_1]\oplus[K_2 \lll (r_1 + r_4)].
$$
Like before, let us rearrange this to the following form
$$
[H_0\lll r_3] \oplus [H_1 \lll r_1]= [K_2 \lll (r_1 + r_4)] \oplus [K_2 \lll (r_2 + r_3)]
$$
Now to simplify this to the final form we desire, we have to use a little trick. Consider the expression
$$[A \lll B] \oplus [A \lll C].$$
If we let $A\rq = A \lll B$, then we get
$$[A \lll B] \oplus [A \lll C] = A\rq \oplus [A \lll C + B - B] = A\rq \oplus [A\rq \lll B-C] = A\rq \oplus [A\rq \lll D],$$
where $D = B-C$ (left rotate by a negative amount $-n$ is simply a left rotate by $N-n$ bits).

Hence, by rotating by $-r_3$ and using this trick, we get
$$
H_0 \oplus [H_1 \lll (r_1 - r_3)] = K_2 \rq \oplus [K_2 \rq \lll D],
$$
where $K_2\rq = K_2 \lll (r_2 - r_3 + r_4)$ and $D = r_1 - r_4$. Finally, we know for certain that there is one degree of freedom in our variables $r_1, r_2, r_3, r_4$ as if $(r_1, r_2, r_3, r_4, K_1, K_2)$ is a solution, then so is $(r_1+a, r_2+a, r_3+a,r_4+a,K_1\lll -a, K_2 \lll -a)$ (there is no canonical form). As such, we are allowed to set any variable to zero -- or $r_1 - r_3 = 0$ for the exact same reason -- and translate the other variables accordingly. This leaves us with the equation
$$
H_0 \oplus H_1  = K_2\rq \oplus [K_2\rq \lll D].
$$
The solution to this equation, $K_2\rq$, happens to be a valid value to our original equation for $H_1$ and $H_2$ as all of the operations we have done up until now have behaved nicely (transitive, distributive, etc.). As such, there is no need to translate $K_2\rq$ back into $K_2$ along with all the other variables. We just ought to find $(r_1\rq, r_2\rq, r_3\rq, r_4\rq, K_1\rq)$ which accompany $K_2\rq$. However, we saw before that $r_1, r_2, r_3 = 0$ along with $K_1 = H_1\oplus(K_2 \lll r_4)$ satisfied this exact condition, and so we are done!

## Conclusion
This challenge was great fun, and was a fun activity to learning how binary rotations can be achieved through linear algebra. I would like to give a massive thank you to the author of the challenge, and to all of the CTF organisers for such a great CTF!

Thanks for reading,
Lachlan
