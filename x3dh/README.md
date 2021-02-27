# X3DH

This is a rudimentary implementation of the X3DH protocol used by the
messaging app Signal. There are a few differences between the original
implementation and this one, but for the most part this version follows
the same cryptographic specifications as the ones outlined here.

The `xeddsa` library is adapted from the `python-xeddsa` package, and
has been modified to use `pynacl` instead of `libnacl`. The `xeddsa.ref10`
library is copied from the same package, where it was adapted from the
SUPERCOP library.

## Setting Up

After cloning this repository, there are a couple of things to do in order
to get the required libraries set up. First, create a Python environment.

```bash
$ python3 -m venv env
$ source env/bin/activate
```

Install the required packages.

```bash
(env) $ pip install -r requirements
```

Next, build the `ref10` library. This is a low-level library that must be
compiled on your machine, since it depends on your operating system and
architecture.

```bash
(env) $ cd xeddsa && python ref10/build.py
```

## Running the Server

To start the server, run the following command.

```bash
(env) $ python server.py
```

## Creating Clients

You need to specify a username for the client, which will be used to
determine their UID. Pick one, and then start the client.

```bash
(env) $ python client.py <username>
```

Do this for at least two clients.

## Performing an Exchange

To run the X3DH exchange between two clients, run the following request
where `<port>` is the port the sending client is running on and `<target>`
is the username of the receiving client.

```bash
(env) $ curl --location --request POST 'http://127.0.0.1:<port>/perform_handshake' \
--header 'Content-Type: application/json' \
--data-raw '{
    "send_to": "<target>"
}'
```

Alternatively, run this request using Python.

```python
import requests

port, target = "<port>", "<target>"
url = f"http://127.0.0.1:{port}/perform_handshake"

payload=f"{{\n    \"send_to\": \"{target}\"\n}}"
headers = {
  'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload)
print(response.text)
```