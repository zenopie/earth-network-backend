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


def test_shield_response_parses_from_simulate_json():
    # A simulate answer carries MsgShieldResponse in msg_responses; cosmpy
    # parses it by type URL, which failed on earth-1 at launch.
    from google.protobuf import json_format
    from cosmpy.protos.cosmos.tx.v1beta1 import service_pb2
    body = {"gas_info": {"gas_wanted": "0", "gas_used": "1"},
            "result": {"data": "", "log": "", "events": [],
                       "msg_responses": [{"@type": "/earth.shielded.v1.MsgShieldResponse",
                                          "position": "3", "commitment": "AA=="}]}}
    resp = json_format.ParseDict(body, service_pb2.SimulateResponse())
    assert resp.result.msg_responses[0].type_url == "/earth.shielded.v1.MsgShieldResponse"
