
+ This was originally an university assignment, so the server is no longer in use
    + But the entire process and reasoning is described in detail below
    + It was split into two separete tasks, Part 1 and Part 2
+ To run part1:
    `python skel.py`
+ To run part2:
    `python diff_crypto_attack.py`


  --- from the source folders part1 and part2, respectively

  ***

## Part 1

+ The first part required the capture of a flag from a
server. To explain the attack, I first understood the
code running on the server.

### 1. The Server and What Can Be Learned from Its Code

+ The server has a simplistic interface with three options:

> 1. Get guest token
> 2. Login
> 3. Exit

+ By analyzing the server code, I found additional information:

> + GUEST_NAME = b'Anonymous'
> + The admin's name, referred to from now on as ADMIN_NAME = b'Ephvuln'
> + I don't know the integrity length
> + An encrypted message is structured as:
>>    plain xor rnd + `SERVER_PUBLIC_BANNER` + integrity,
>    + where rnd remains the same for each session
>    + `SERVER_PUBLIC_BANNER` is always identical
>    + integrity is unknown, but it ensures the token's validity.

![](/assets/image1.svg)

> + I refer to "plain xor rnd" as "message".
> + The token format helps simplify explanations.
> + The sizes of the message, banner, and integrity are unknown,
>      + but satisfy `|message| + |banner| + |integrity| <= 16`


+ The server's decryption function reveals more information, but the useful ones are:
    + It returns -1 if the `SERVER_PUBLIC_BANNER` is missing.
    + It returns None if the integrity is incorrect.
      
    + For guest tokens, the code uses GUEST_NAME as plain text in the encryption function.
    + The server's login function reveals the verification order, which will be exploitable later:
 
> 1. It ensures the token is <= 16 bytes.
>     + which means that if the message resulting from ADMIN_NAME doesn't have 16 bytes, it doesn't require padding.
> 2. It verifies if `SERVER_PUBLIC_BANNER` exists in the token.
> 3. Verifies token integrity.
> 4. Checks for guest/admin tokens or incoherent messages.

***

What I learned from the server code analysis:
+ The banner is consistent.
+ Padding is unnecessary.
+ The token's structure.
+ The verification order.

***

### 2. A Little Theory and How to Build a Token

+ To reiterate, a message looks like this:

![](/assets/image1.svg)

+ where message is "plain xor rnd", to be exact, "GUEST_NAME xor rnd" (extracted from the guest token received from the server).

+ Similarly, to construct an admin token, it must have the same structure:
> ADMIN_NAME xor rnd + `SERVER_PUBLIC_BANNER` + integrity
+ Extracting GUEST_NAME and ADMIN_NAME from the server makes creating the message straightforward.

I denote:
> GUEST_NAME xor rnd = m1
> ADMIN_NAME xor rnd = m2
> -----------------------
> m1 xor GUEST_NAME = rnd ---> m2 = ADMIN_NAME xor m1 xor GUEST_NAME


+ To find the `SERVER_PUBLIC_BANNER`, I use steps 2 and 3 of the
    server's verification process:

> 2. Verifies if `SERVER_PUBLIC_BANNER` exists in the token.
> 3. Verifies token integrity.

+ This process is divided into two parts:
    1. Determining the start of the banner.
    2. Determining the end of the banner.

#### 1) Start of the Banner

Assuming again the token looks like this, without knowing the boundaries between message, banner, and integrity:

![](/assets/image1.svg)

I construct a new payload by replacing one byte at a time from the guest token with "X", sending it to the server for login. This exploits the server's verification method.


The steps would look like this:

![](/assets/image2.svg)

+ When the server's response changes from "Incorrect Integrity" to "Wrong server secret", it means that the beginning of the banner was overwritten, thereby determining the start position of `SERVER_PUBLIC_BANNER` in the received guest token.

#### 1) Banner Ending

+ I will apply a similar method as above, but this time the payload will be in the form:  
`n bytes from the guest token + "X" padding up to 16 bytes.`

![](/assets/image3.svg)

+ When the server's response changes from "Wrong server secret" to "Incorrect Integrity", it means that enough bytes from the token have been sent to cover the entire banner, thus determining the end position of `SERVER_PUBLIC_BANNER` within the received guest token.

***

+ At this point, I know the message that needs to be sent and the banner; I only need the integrity:  
- Its length can be determined through a simple calculation:  
> |guest_token| - final_banner  
- In this case, it is one byte. To determine integrity, I simply brute-force all 256 possible values, ensuring it is represented as a single byte (Python sometimes does the conversions oddly, causing it to use 2 bytes instead of 1).

***
### 3. Implementation and Final Step

The attack follows these steps: 
1. A loop over the length of the guest token:  
   - Replace bytes in the token until the start of the banner is found.
2. Another loop over the length of the guest token:  
   - Add bytes from the token and pad up to 16 bytes until the end of the banner is found.
3. A loop through all 256 possible values (`integrity=0...255`):  
   - Construct the token and send it to the server.  
   - If I receive the CTF from the server, **SUCCESS**.

---

## Part 2
+ In the second part of the task, I attempt a differential attack, in which I know the first 8 bytes of the key and aim to find the last 4.  

> The key structure is:  
> `k = k1 | k2 | k3`,  
> where `k1, k2` are known.

+ I am targeting a simplified block cipher with a 96-bit key (12 bytes) and 64-bit messages.

![](/assets/image4.svg)

+ **Attack Point**: Marked with `X` in the third (final) round.

![](/assets/image5.svg)

***

+ I begin by generating pairs of messages `(m1, m2)` for which I receive the encryption from the server: `(c1, c2)`.  
+ A pair of messages `(m1, m2)` is defined as messages generated randomly with the property that:  
>  - `R(m1) = R(m2)`  
>  - `L(m1) XOR L(m2) = deltax`, where `deltax` is as large as possible.

***

### Small Implementation Note on `deltax`
+ Theoretically, I would take `deltax = b'11111111'`:  
  + Because I want to compare it with `deltay`, which is 8 bits, calculated in the byte-wise attack on `k3`, where S-boxes are taken sequentially.  
  + I refer to the left part when discussing `deltax`, where I want the difference. The right part can be generated separately and attached to the left part of each message since it is common.  
+ However, if I generate `m = b'00001...'`, Python might perform a conversion and return 7 bytes instead of 8, which would disrupt calculations. (I kept the verification in the attack as a safety net.)  
+ To avoid this, in the implementation, I chose to use `deltax = b'1' * 32 + b'0' * 32`, which does not affect the calculation and allows me to:  
  + Generate `m1` randomly.  
  + Calculate `m2 = m1 XOR deltax`, leading to simpler message generation.

***

+ Once I have the pairs of messages `(m1, m2)` and their encryptions `(c1, c2)`, I can attack `k3` byte by byte at point `X = E'(k3, m)` from the above scheme, using the formula: `E’(k, m) = R3 XOR S-box(k3 XOR L3)`  

+ The right part of the message XOR S-box(k3 XOR L3).  
  + `R2` from `S-box(k3 XOR R2)` is replaced with `L3`, because `Li = Ri-1` as shown in the chart.

+ For each byte in `k3`, brute-force each possible value for the byte in `k3 = 0...255`  
and iterate through the set of values `(c1, c2)` generated, calculate the value at point `X`  
using the discussed formula, and compute `deltay = X1 XOR X2`.  
+ Select `k31 | k32 | k33 | k34` where, for the value of `k3i`, the most associations satisfy `deltax == deltay`.

+ Finally, I calculate the entire key and decrypt the message.
