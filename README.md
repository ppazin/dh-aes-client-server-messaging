# DH AES Chat
Projekt za NMR
Jednostavna aplikacija za sigurnu razmjenu poruka koristeći Diffie–Hellman (X25519) za razmjenu ključeva i AES-GCM za simetrično šifriranje.

## Pokretanje
### Korištenje servera na udaljenom hostu
Kako je server već postavljen (na IP 207.154.210.134), dovoljno je koristiti samo klijent:
```bash
python client.py
```
Unesite svoje korisničko ime i naredbe:
- /send <user> <message> – pošalji poruku drugom korisniku
- /fetch – preuzmi nepročitane poruke
- /quit – izađi iz aplikacije

U klijentu promijenite host u IP adresu udaljenog servera:
```bash
host = "207.154.210.134"
port = 5000
```

### Pokretanje lokalno
Ako želite testirati lokalno, potrebno je pokrenuti i server i klijent na istom računalu:
```bash
# u terminalu 1
python server.py

# u terminalu 2
python client.py
```

U tom slučaju koristite host = "127.0.0.1" u klijentu.

## Preduvjeti
- Python 3.10 ili noviji
- Instalirane biblioteke: cryptography, psycopg2, python-dotenv

Za lokalno testiranje preporučuje se pokrenuti server u virtualnom okruženju (venv) i konfigurirati .env datoteku s parametrima baze podataka.
