# minidns

A minimal DNS server to test SSRFs and TOCTOU bugs

## Install

```sh
pip install -r requirements.txt
```

## Usage:

You can add your records directly in dns.py's `__main__`

```sh
python3 dns.py
```

## TODO:

I plan to make this a small offensive dns framework, which can easily be extended for various scenarios, especially TOCTOU exploits, but for now it's just plain Python to edit manually
