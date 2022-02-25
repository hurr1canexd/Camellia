# Camellia
Web application that allows you to encrypt and decrypt files of any format.
It uses my implementation of the [Camellia](https://en.wikipedia.org/wiki/Camellia_(cipher)) encryption algorithm.

## How to run?
Use terminal:
```
git clone https://github.com/hurr1canexd/Camellia.git
cd Camellia
python app.py
```

## Usage
1. Go to URL: http://localhost:5000/
2. Choose a file to encode/decode
3. Choose a key size and enter him
4. Enter an initial vector if you want to use CBC/CFB/OFB mode
5. Press button "OK" to encode file. 
Put a tick in checkbox if u want to decode file