"""earth.shielded.v1.MsgShield, built at import time from its field list.

cosmpy only ships the SDK's own protos. Rather than vendoring the chain's
.proto tree and a protoc step for one four-field message, the descriptor is
assembled here and added to protobuf's default pool, next to the cosmos Coin
that cosmpy has already registered. cosmpy packs a message into the tx's Any
by its descriptor's full name, so the type URL comes out as
/earth.shielded.v1.MsgShield, exactly what the chain routes.

Mirrors proto/earth/shielded/v1/tx.proto:

    message MsgShield {
      string sender = 1;
      cosmos.base.v1beta1.Coin amount = 2;
      bytes pc = 3;          // H(TAG_PC, owner_pk, rho, rcm), 32 bytes
      bytes ciphertext = 4;  // required, the note's amount-blind v2 ciphertext, 177 bytes
    }

tests/test_shield_msg.py checks the encoding byte for byte against the chain's
own gogoproto Marshal.
"""
from cosmpy.protos.cosmos.base.v1beta1 import coin_pb2  # noqa: F401  registers coin.proto
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

TYPE_URL = "/earth.shielded.v1.MsgShield"
# The chain's types.MaxCiphertextBytes.
MAX_CIPHERTEXT_BYTES = 1024
# The chain's types.BlindCiphertextBytes (zk/privacy BlindNoteCiphertextBytes):
# MsgShield.ciphertext must be exactly this long.
BLIND_CIPHERTEXT_BYTES = 177

_FULL_NAME = "earth.shielded.v1.MsgShield"
_FILE = "earth/shielded/v1/backend_msg_shield.proto"


def _message_class():
    pool = descriptor_pool.Default()
    try:
        return message_factory.GetMessageClass(pool.FindMessageTypeByName(_FULL_NAME))
    except KeyError:
        pass
    F = descriptor_pb2.FieldDescriptorProto
    fdp = descriptor_pb2.FileDescriptorProto(
        name=_FILE,
        package="earth.shielded.v1",
        syntax="proto3",
        dependency=["cosmos/base/v1beta1/coin.proto"],
    )
    msg = fdp.message_type.add(name="MsgShield")
    msg.field.add(name="sender", number=1, type=F.TYPE_STRING, label=F.LABEL_OPTIONAL, json_name="sender")
    msg.field.add(name="amount", number=2, type=F.TYPE_MESSAGE, label=F.LABEL_OPTIONAL,
                  type_name=".cosmos.base.v1beta1.Coin", json_name="amount")
    msg.field.add(name="pc", number=3, type=F.TYPE_BYTES, label=F.LABEL_OPTIONAL, json_name="pc")
    msg.field.add(name="ciphertext", number=4, type=F.TYPE_BYTES, label=F.LABEL_OPTIONAL, json_name="ciphertext")
    pool.Add(fdp)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName(_FULL_NAME))


MsgShield = _message_class()


def build(sender: str, amount: int, denom: str, pc: bytes, ciphertext: bytes):
    return MsgShield(
        sender=sender,
        amount=coin_pb2.Coin(denom=denom, amount=str(amount)),
        pc=pc,
        ciphertext=ciphertext,
    )
