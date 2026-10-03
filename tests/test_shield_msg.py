"""The hand-built MsgShield encodes exactly as the chain's gogoproto type does."""
import json
import os

from google.protobuf import any_pb2

from services import shielded_msg

VEC = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "privacy", "zk_vectors.json")))["msg_shield"]


def test_encoding_matches_the_chain():
    msg = shielded_msg.build(VEC["sender"], 100000, "uerth", bytes.fromhex(VEC["pc"]), bytes.fromhex(VEC["ciphertext_hex"]))
    assert msg.SerializeToString(deterministic=True).hex() == VEC["encoded"]


def test_packs_under_the_chains_type_url():
    any_msg = any_pb2.Any()
    any_msg.Pack(shielded_msg.build(VEC["sender"], 1, "uerth", b"\x00" * 32, b"\x00" * 177), type_url_prefix="/")
    assert any_msg.type_url == shielded_msg.TYPE_URL


def test_reimport_reuses_the_registered_type():
    assert shielded_msg._message_class() is shielded_msg.MsgShield
