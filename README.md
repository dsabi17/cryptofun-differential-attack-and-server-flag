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

+ The first part requires us to capture a flag from a
server. To explain the attack, we must first understand the
code running on the server.

### 1. The Server and What We Can Learn from Its Code

+ The server has a simplistic interface with three options:
    &nbsp;&nbsp;&nbsp;&nbsp; 1. Get guest token
    2. Login
    3. Exit

- By analyzing the server code, we can find additional information:
    - GUEST_NAME = b'Anonymous'
    - The admin's name, referred to from now on as
    ADMIN_NAME = b'Ephvuln'
    - The integrity length is unknown.
    - An encrypted message is structured as:
    plain xor rnd + SERVER_PUBLIC_BANNER + integrity,
        where rnd remains the same for each session,
        SERVER_PUBLIC_BANNER is always identical and integrity is
        unknown but ensures the token's validity.

    message   SERVER_PUBLIC_BANNER    integrity
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │
└────────────────┴────────────────┴────────────────┘

        --- We refer to plain xor rnd as "message".
        --- The token format helps simplify explanations.
        --- The sizes of the message, banner, and integrity are
        unknown but satisfy |message| + |banner| + |integrity| <= 16

    - The server's decryption function reveals more information, but
    the useful ones are:
        - It returns -1 if the SERVER_PUBLIC_BANNER is missing.
        - It returns None if the integrity is incorrect.
    - For guest tokens:
    - They use GUEST_NAME as plain text in the encryption function.
    - The server's login function reveals the verification order,
    exploitable later:

        1. Ensures the token is <= 16 bytes.
            ---> If the message resulting from ADMIN_NAME doesn't have
            16 bytes, it doesn't require padding.
        2. Verifies if SERVER_PUBLIC_BANNER exists in the token.
        3. Verifies token integrity.
        4. Checks for guest/admin tokens or incoherent messages.

    Conclusions from the server code analysis:
        - The banner is consistent.
        - Padding is unnecessary.
        - The token's structure is understood.
        - We know the verification order.

____________
2. A Little Theory and How to Build a Token

    - To reiterate, a message looks like this:

    message       SERVER_PUBLIC_BANNER    integrity
┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │
└────────────────┴────────────────┴────────────────┘

where message is noted as plain xor rnd, specifically,
GUEST_NAME xor rnd (extracted from the guest token received
from the server).

    - Similarly, to construct an admin token, it must have the same
    structure:
        ADMIN_NAME xor rnd + SERVER_PUBLIC_BANNER + integrity
    - Extracting GUEST_NAME and ADMIN_NAME from the server makes
    creating the message straightforward.

We denote:
GUEST_NAME xor rnd = m1
ADMIN_NAME xor rnd = m2
-----------------------
m1 xor GUEST_NAME = rnd ---> m2 = ADMIN_NAME xor m1 xor GUEST_NAME


    - To find the SERVER_PUBLIC_BANNER, we use steps 2 and 3 of the
    server's verification process:

2. Verifies if SERVER_PUBLIC_BANNER exists in the token.
3. Verifies token integrity.

    - This process is divided into two parts:
        1) Determining the start of the banner.
        2) Determining the end of the banner.

1) Start of the Banner

Assuming again our token looks like this, without knowing the
boundaries between message, banner, and integrity:

┌────────────────┬────────────────┬────────────────┐
│ m0 m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │
└────────────────┴────────────────┴────────────────┘


We construct a new payload by replacing one byte at a time from the
guest token with "X", sending it to the server for login. This
exploits the server's verification method.


The steps would look like this:

    "TOKEN" SENT                        SERVER RESPONSE
┌────────────────┬────────────────┬────────────────┐
│ X  m1 m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │ -> Integrity error (naturally, since we
└────────────────┴────────────────┴────────────────┘    altered the message)
┌────────────────┬────────────────┬────────────────┐
│ X  X  m2 ... mn│ b0 b1 b2 ... bn│i0 i1 i2 ... in │ -> Integrity error
└────────────────┴────────────────┴────────────────┘
...


