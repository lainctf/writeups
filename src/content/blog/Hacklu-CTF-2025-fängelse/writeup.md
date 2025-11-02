---
author: cirno
title: "Hack.lu CTF 2025 / Misc / FÄNGELSE"
description: "Come on, it's only 5 chars"
pubDate: "Nov 01 2025"
heroImage: "/writeups/cirno.png"
---

## Challenge

```python
flagbuf = open("flag.txt", "r").read()

while True:
    try:
        print(f"Side-channel: {len(flagbuf) ^ 0x1337}")
    # Just in case..
    except Exception as e:
        print(f"Error: {e}") # don't want to leak anything
        exit(1337)
    code = input("Code: ")
    if len(code) > 5:
        print("nah")
        continue
    exec(code)
```

## Explanation

This challenge's name is Swedish for **Prison**, so it's pretty clear that we need to escape this somehow.

The first idea that comes to mind was to use the side-channel that the program outputs for us. The value is the **length of the flag XOR'ed with 0x1337**. Being unsure on how to use this further, I decided to play around with the other parts of the code.

The only other block of code that prints something related to a variable is the code that handles an **exception**. My first idea was to use this somehow to leak the flag. I did manage to leak it using the exception, but when tested against the live server, it didn't work out because the server closes the connection before printing the error message. It was useful later on.

Since the input length is limited to **five**, I enumerated what statements would be useful to send. The only defined variable was **flagbuf**, and that's for sure more than five characters, so I checked which of the **built-ins** could be used as an input. Most of them did nothing or resulted in an interpreter error; tried combining them with other language symbols, still nothing.

Maybe flagbuf could somehow be referred to, as **a shorter variable?** This wasn't possible, but what I did discover is that an assignment would carry on to the next iteration in the loop. This meant that this **mutability** could be used to work with another statement.

Going back to the built-ins, assuming that a single-letter variable was used for an assignment, there were only three more chars available. At this moment, I remembered that the code used **len** for the print statement. So if **len** is overwritten with something else, it would use that other object. But what to overwrite it **with?**

Being lazy, I thought about using another built-in!

First, I tried **hex** and **int**. Hex spit out an error saying that the string can't be interpreted as an integer. Int leaked the flag, but that only worked locally, as the server disconnects before showing the error.

Trying **id** was interesting, because it made the side-channel become a big number. I knew I had to work with a built-in that worked with strings, or any object.

Using **all** did the work, as I later analyzed that the code also uses **len** to check the length of the code sent, before potentially rejecting the input. If **len** is overwritten by **all**, the line that checks the length will always return true, since the output of **all(code)** would be **1**, which is always less than 5.

This had the unintended side effect of allowing a code of arbitrary length to be sent as the argument to **exec**. I used this to send a **print** statement to get the flag, and the server gladly accepted my input.

## Solution

```
cirno$ nc fängelse.solven.jetzt 1024
Side-channel: 4890
Code: a=all
Side-channel: 4890
Code: len=a
Side-channel: 4918
Code: print(flagbuf)
flag{1_2_3_4_5_6_7_8_9_10_exploit!_12_13_...}
```
