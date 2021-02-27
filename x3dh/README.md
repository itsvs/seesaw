# X3DH

This is a rudimentary implementation of the X3DH protocol used by the
messaging app Signal. There are a few differences between the original
implementation and this one, but for the most part this version follows
the same cryptographic specifications as the ones outlined
[here](https://signal.org/docs/specifications/x3dh/).

The `xeddsa` library is adapted from the `python-xeddsa` package, and
has been modified to use `pynacl` instead of `libnacl`. The `xeddsa.ref10`
library is copied from the same package, where it was adapted from the
SUPERCOP library.

I will add a summary of how the X3DH protocol works at some point. While
you read the Signal documentation, you might also be interested in reading
about the XEdDSA Signature Scheme. This I will not document, but you can
find the specification [here](https://signal.org/docs/specifications/xeddsa/).

## Setting Up

After cloning this repository, there are a couple of things to do in order
to get the required libraries set up. First, create a Python environment.

```bash
$ python3 -m venv env
$ source env/bin/activate
```

Install the required packages.

```bash
(env) $ pip install -r requirements.txt
```

Next, build the `ref10` library. This is a low-level library that must be
compiled on your machine, since it depends on your operating system and
architecture.

```bash
(env) $ cd xeddsa && python ref10/build.py && cd ..
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

## Viewing Data

The idea here is to create an exchange that is hard, if not impossible,
to intercept. All data is therefore made visible in this experiment.

To see all the information stored by the server, visit `http://127.0.0.1:5000/user_data`.
You will find each user's prekey bundle listed, along with the ports
they're running on and their UID.

When you request a prekey bundle (done automatically by the client
performing a handshake), the server will print out the bundle being
returned as well. When the client performing the handshake sends
information to the receiving client, the server will print the data
being forwarded as well.

You'll notice that all keypairs are being stored in `.data`. This is
entirely unnecessary, and in a real scenario, the server will not have
this information. The keypairs for every user will be stored in that
user's local storage, otherwise the entire premise of security is
compromised. The server will store only the relevant public keys.

## License

This experiment is licensed under the MIT license, though honestly
you probably shouldn't use most of this in a production environment.

See [LICENSE](LICENSE.md).