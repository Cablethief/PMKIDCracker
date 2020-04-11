# PMKIDCracker
Rust CPU based PMKID cracker

# Usage

```
./pmkidcracker -w wordlist.txt -p PMKID
```

# Example

```
./PMKIDCracker -p '2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a' -w /usr/share/dict/wordlist
```

# Theory

Calculation of hash

```
PMK = PBKDF2(HMAC−SHA1, PSK, SSID, 4096, 256)
PMKID = HMAC-SHA1-128(PMK, "PMK Name" | MAC_AP | MAC_STA)
```

Hashcat Format breakdown:

```
[PMKID]:[AP SSID]:[STA SSID]:[SSID]
2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a
```


https://briansmith.org/rustdoc/ring/