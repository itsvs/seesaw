# Double Ratchet

This is a rudimentary implementation of the Double Ratchet protocol used
by the messaging app Signal. There are a few differences between the
original implementation and this one, but for the most part this version
follows the same cryptographic specifications as the ones outlined
[here](https://signal.org/docs/specifications/doubleratchet/).

I will add a summary of how the Double Ratchet protocol works at some point.

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

## Creating Clients

In order to demo the communication protocol, you'll need to create at least
two clients. To create one client, run the following command:

```bash
(env) $ python main.py
```

Do this twice for two clients.

## Initializing the Clients

First, you need to initialize the channel between the two clients. For this,
you need to decide on a shared key and some associated data for the clients.
You also need to decide who the first sender is and who the first receiver is,
in order to set the relevant DH keys. There are many ways to do this, but you
can use the X3DH exchange to set this up as an example. See the Signal docs
[here](https://signal.org/docs/specifications/doubleratchet/#integration-with-x3dh)
for more on this.

We will initialize the clients as follows:
- both will use the same shared key `<sk>`
- both will use the same associated data `<ad>`
- the first sender will use the recipient's shared prekey public key `<pub>` from
X3DH as her initial receiving key, and will generate a new keypair for sending
- the first receiver will use his shared prekey private key `<priv>` from X3DH as
his initial sending key, and to initialize his receiving key

To initialize the sender, if her server is running on `<port_a>`:

```bash
(env) $ curl --location --request POST 'http://127.0.0.1:<port_a>/initialize' \
--header 'Content-Type: application/json' \
--data-raw '{
    "ad": "<ad>",
    "sk": "<sk>",
    "pub": "<pub>"
}'
```

To initialize the receiver, if his server is running on `<port_b>`:

```bash
(env) $ curl --location --request POST 'http://127.0.0.1:<port_b>/initialize' \
--header 'Content-Type: application/json' \
--data-raw '{
    "ad": "<ad>",
    "sk": "<sk>",
    "priv": "<priv>"
}'
```

## Sending a Message

To simulate the sender sending the first message, run the following for any
message `<msg>`:

```bash
(env) $ curl --location --request POST 'http://127.0.0.1:<port_a>/send_msg' \
--header 'Content-Type: application/json' \
--data-raw '{
    "body": "<msg>"
}'
```

This will output a message body of the following form, where `<body>` is the
result of encrypting `<msg>` and `<dh>` is the next DH key that the sender
will use to reset a KDF chain (the DH Ratchet of the Double Ratchet algorithm):

```json
{
    "dh": "<dh>",
    "pn": 0,
    "n": 0,
    "body": "<body>"
}
```

## Receiving a Message

To simulate the receiver receiving the first message, run the following, with
the same values as were returned by the previous command:

```bash
(env) $ curl --location --request GET 'http://127.0.0.1:<port_b>/receive_msg' \
--header 'Content-Type: application/json' \
--data-raw '{
    "dh": "<dh>",
    "pn": 0,
    "n": 0,
    "body": "<body>"
}'
```

This will output the decrypted message body, as desired.

## License

This experiment is licensed under the MIT license, though honestly
you probably shouldn't use most of this in a production environment.

See [LICENSE](../LICENSE.md).