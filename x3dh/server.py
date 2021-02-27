import os
import requests

from flask import Flask, abort, request

if not os.path.exists("xeddsa/_crypto_sign.o"):
    raise ModuleNotFoundError("The _crypto_sign library must be built first. Build it by running `cd xeddsa && python3 ref10/build.py`.")

app = Flask(__name__)
connections = {}

@app.before_first_request
def init_workdir():
    if not os.path.exists(".data"):
        os.mkdir(".data")


@app.route("/register_user", methods=["POST"])
def register_user():
    data = request.json
    connections[data.pop("username")] = data

    return dict(success=True)


@app.route("/")
def index():
    return "It works!"


@app.route("/user_data")
def user_data():
    return connections


@app.route("/get_prekey_bundle/<person>")
def get_prekey_bundle(person: str):
    if person not in connections:
        abort(404)

    person = connections[person]['prekey_bundle']
    opk_index = list(person["opks"].keys())[0]

    bundle = dict(
        identity=person["identity"],
        spk=person["spk"],
        signature=person["signature"],
        opk_index=opk_index,
        opk=person["opks"].pop(opk_index),
    )

    print(f"Returning bundle for {person}: {bundle}")
    return bundle


@app.route("/perform_handshake", methods=["POST"])
def perform_handshake():
    data = request.json
    print(f"Performing Handshake: {data}")
    port = connections[data.pop("send_to")]["port"]

    success = requests.post(f"http://localhost:{port}/receive_handshake", json=data).ok
    return dict(success=success)


if __name__ == "__main__":
    app.run()
