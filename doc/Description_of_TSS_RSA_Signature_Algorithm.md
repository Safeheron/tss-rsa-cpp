# Description of TSS-RSA Signature Algorithm

Refer to [Practical Threshold Signatures](https://www.iacr.org/archive/eurocrypt2000/1807/18070209-new.pdf).

# 0 Setup

- $k$ - threshold, which means the least number of key shares needed to obtain a signature.
- $l$ - the number of participants.

# 1 Key Generation By a Trusted Dealer

- Simple $p \in_{R} \{0,1\}^*$, $p$ is a prime. $\exists p', p = 2p'+1$, and $p'$ is a prime too.
- Simple $q \in_{R} \{0,1\}^*$, $q$ is a prime. $\exists q', q = 2q'+1$, and $q'$ is a prime too.
- Compute $n=pq$
- Compute $m=p'q'$
- Sample $e \in_R \{0,1\}^*$, make sure $e >l$ and $e$ is a prime.

**Here we get the public key $PK = (n,e)$**

- Compute $d, st. de \equiv 1 \pmod m$
- Split $d$ into $l$ shares with the threshold $k$ in finite fields $Z_m$:
    - $(d,k,l) \Rightarrow (s'_1, s'_2 ... s'_l)$
- **(Protocol2)**: Transformation on $s_i$
    - $(s'_1, s'_2 ... s'_l) \Rightarrow (s_1, s_2 ... s_l)$
    - $s_i = s_i' \Delta^{-1} \pmod m$
- Sample $f \in_R Z_n$
- Compute $v = f^2 \pmod n$. Note $v \in Q_n$
- Compute the verification keys:
    - $VK = v$
    - $VK_i = v_i = v^{s_i} \pmod n$, for $1 \le i \le l$ . Note $v_i \in Q_n$.
- **(Protocol2)**: Sample integer $u$
    - Sampe $u \in_R Z_n^*$, where Jacobi symbol $(u, n) ==-1$
- Distribute $(PK, VK, VK_i, s_i, u)$ to party $i$, in which $PK = (n, e)$

**Here party i would receives his secret share along with some other data :**

- $s_i$: secret share. It's exclusive to party i.
- $VK$:verification key. It's common.
- $\{VK_i \mid i = 1, \dots, l\}$:  It's common.
- $PK$: RSA public key. It's common.
- **$u$: new element from protocol 2.** It's common.

# 2 Generating a Signature Share

Let $\hat{x}=H(M)$ where M is the message.

(Protocol2): Compute the x

$$
x = \begin{cases}
\hat{x}     & \text{ if } (\hat{x}, n) = 1 \\
\hat{x} u^e & \text{ if } (\hat{x}, n) = -1
\end{cases}
$$

The signature share of play i consists of
$$
x_i = x^{2s_i} \pmod n \\
x_i = x^{2 \Delta s_i} \pmod n （deprecated \space in \space protocol 2)
$$
along with  a proof(refer to section 5.3)
$$
Proof(s_i, VK, VK_i, l, n) = (z, c)
$$
Note $x_i \in Q_n$.

# 3 Combining Signature Shares

We compute
$$
w = x_{i_1}^{2 \lambda_{0,i_1}^S}
\dots
x_{i_k}^{2 \lambda_{0,i_k}^S}
\pmod n
$$
where the set $S = \{i_1, \dots, i_k\} \subset \{1, \dots, l\}$.

We compute $e' = 4$ instead of $e' = 4 \Delta^2$ (Deprecated in protocol2).

Note that $gcd(e', e) = 1$, so $\exists (a, b), st. e'a + eb = 1$.

We compute $a$ and $b$. The number $a$ and $b$ can be obtained from the extended Euclidean algorithm on $e$ and $e'$.

We compute the final signature
$$
y = w^a x^b \pmod n
$$

# 4 Verify Signatures

We check if
$$
y^e \equiv x \pmod n
$$

# 5 Dependency

##  5.1 Compute $\lambda_{i,j}$ (to be developed)

We compute


$$
\lambda_{i,j}^{S} =
\Delta
\frac
{ {\textstyle \prod_{j' \in S \setminus \{j\}}^{}(i-j')} }
{ {\textstyle \prod_{j' \in S \setminus \{j\}}^{}(j-j')} }
$$
where
$$
\Delta = l!
$$

## 5.2 Extended Euclidean algorithm (to be developed)
Refer to [crypto-suites-cpp](https://github.com/safeheron/crypto-suites-cpp.git).

## 5.3 Proof of Correctness on Signature Share(to be developed)

#### Input: $s_i, v=VK, v_i=VK_i, l, n$

#### Prove:

- Sample $r \in_R (0, 2^{L(n) +2 L_1-1})$

  where $L$ is the bit-length of of $n$, and $L_1$ is bit-length of the output from hash function $H'$.

- Compute $\tilde{x} = x^4$ instead of $\tilde{x} = x^{4 \Delta}$ (Deprecated in protocol2)

- Compute $v' = v^r \pmod n$

- Compute $x' = \tilde{x}^r \pmod n$

- Compute $c = H'(v, \tilde{x}, v_i, x_i^2, v', x')$

- Compute $z=s_i c + r \pmod n$

**Here we get the proof $(z, c)$**

#### Proof:

- Compute $\tilde{x} = x^4$ instead of $\tilde{x} = x^{4 \Delta}$ (Deprecated in protocol2)

- Compute $v' = v^z v_i^{-c} \pmod n$

- Compute $x' = \tilde{x}^z x_i^{-2c}  \pmod n$

- Compute $c' = H'(v, \tilde{x}, v_i, x_i^2, v', x')$

- Check  $c == c'$

## 5.4 Jacobi symbol (to be developed)
Refer to [crypto-suites-cpp](https://github.com/safeheron/crypto-suites-cpp.git).
## 5.6 Secret share scheme
Refer to [crypto-suites-cpp](https://github.com/safeheron/crypto-suites-cpp.git).
