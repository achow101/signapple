import struct

from enum import IntEnum
from typing import BinaryIO

from .utils import sread


# The highest byte of the opcode is flags
OP_FLAG_MASK = 0xFF000000

# Requirements op codes
class ExprOp(IntEnum):
    OP_FALSE = 0  # Unconditionally false
    OP_TRUE = 1  # Unconditionally true
    OP_IDENT = 2  # Match canonical code [string]
    OP_APPLE_ANCHOR = 3  # Signed by Apple as Apple's product
    OP_ANCHOR_HASH = 4  # Match anchor [cert hash]
    OP_INFO_KEY_VALUE = 5  # Legacy - Use OP_INFO_KEY_FIELD [key; value]
    OP_AND = 6  # Binary prefix expr AND expr [expr; expr]
    OP_OR = 7  # Binary prefix expr OR expr [expr; expr]
    OP_CD_HASH = 8  # Match hash of CodeDirectory directly [cd hash]
    OP_NOT = 9  # Logical inverse [expr]
    OP_INFO_KEY_FIELD = 10  # Info.plist key field [string; match suffix]
    OP_CERT_FIELD = (
        11  # Certificate field, existence only [cert index; field name; match suffix]
    )
    OP_TRUSTED_CERT = (
        12  # Require trust settings to approve one particular cert [cert index]
    )
    OP_TRUSTED_CERTS = 13  # Require trust settings to approve the cert chain
    OP_CERT_GENERIC = 14  # Certificate component by OID [cert index; oid; match suffix]
    OP_APPLE_GENERIC_ANCHOR = 15  # Signed by Apple in any capacity
    OP_ENTITLEMENT_FIELD = 16  # Entitlement dictionary field [string; match suffix]
    OP_CERT_POLICY = 17  # Certificate policy by OID [cert index; oid; match suffix]
    OP_NAMED_ANCHOR = 18  # Named anchor type
    OP_NAMED_CODE = 19  # Named subrouting
    OP_PLATFORM = 20  # Platform constraint [integer]
    OP_NOTARIZED = 21  # Has a developer id+ ticket
    OP_CERT_FIELD_DATE = (
        22  # Extension value as timestamp [cert index; field name; match suffix]
    )
    OP_LEGACY_DEV_ID = 23  # Meets legacy (pre-notarization required) policy


# Match op codes
class MatchOP(IntEnum):
    MATCH_EXISTS = 0  # Anything but explicit "false"
    MATCH_EQUAL = 1  # Equal
    MATCH_CONTAINS = 2  # Partial match (substring)
    MATCH_BEGINS_WITH = 3  # Partial match (initial substring)
    MATCH_ENDS_WITH = 4  # Partial match (terminal substring)
    MATCH_LESS_THAN = 5  # Less than (string with numeric comparison)
    MATCH_GREATER_THAN = 6  # Greater than (string with numeric comparison)
    MATCH_LESS_EQUAL = 7  # Less or equal (string with numeric comparison)
    MATCH_GREATER_EQUAL = 8  # Greater or equal (string with numeric comparison)
    MATCH_ON = 9  # On (timestamp comparison)
    MATCH_BEFORE = 10  # Before (timestamp comparison)
    MATCH_AFTER = 11  # After (timestamp comparison)
    MATCH_ON_OR_BEFORE = 12  # On or before (timestamp comparison)
    MATCH_ON_OR_AFTER = 13  # On or after (timestamp comparision)
    MATCH_ABSENT = 14  # Not present


def _get_op_name(op: ExprOp):
    op = op & ~OP_FLAG_MASK  # type: ignore
    if op == ExprOp.OP_FALSE:
        return "False"
    elif op == ExprOp.OP_TRUE:
        return "True"
    elif op == ExprOp.OP_APPLE_ANCHOR:
        return "Apple product signed by Apple"
    elif op == ExprOp.OP_IDENT:
        return "Identity"
    elif op == ExprOp.OP_ANCHOR_HASH:
        return "Anchor hash"
    elif op == ExprOp.OP_CD_HASH:
        return "CodeDirectory hash"
    elif op == ExprOp.OP_NOT:
        return "Not"
    elif op == ExprOp.OP_INFO_KEY_VALUE:
        return "Info.plist key value"
    elif op == ExprOp.OP_AND:
        return "and"
    elif op == ExprOp.OP_OR:
        return "or"
    elif op == ExprOp.OP_INFO_KEY_FIELD:
        return "Info.plist key field"
    elif op == ExprOp.OP_CERT_FIELD:
        return "Certificate field"
    elif op == ExprOp.OP_TRUSTED_CERT:
        return "Trusted cert"
    elif op == ExprOp.OP_TRUSTED_CERTS:
        return "Trusted cert chain"
    elif op == ExprOp.OP_CERT_GENERIC:
        return "Certificate OID"
    elif op == ExprOp.OP_APPLE_GENERIC_ANCHOR:
        return "Signed by Apple"
    elif op == ExprOp.OP_ENTITLEMENT_FIELD:
        return "Entitlement field"
    elif op == ExprOp.OP_CERT_POLICY:
        return "Certificate policy OID"
    elif op == ExprOp.OP_NAMED_ANCHOR:
        return "Named Anchor"
    elif op == ExprOp.OP_NAMED_CODE:
        return "Named subroutine"
    elif op == ExprOp.OP_PLATFORM:
        return "Platform"
    elif op == ExprOp.OP_NOTARIZED:
        return "Notarized"
    elif op == ExprOp.OP_CERT_FIELD_DATE:
        return "Certificate field as timestamp"
    elif op == ExprOp.OP_LEGACY_DEV_ID:
        return "Legacy"
    else:
        raise Exception(f"Unknown requirement op code {op}")


def _get_match_op_name(op):
    if op == MatchOP.MATCH_EXISTS:
        return "exists"
    elif op == MatchOP.MATCH_EQUAL:
        return "equals"
    elif op == MatchOP.MATCH_CONTAINS:
        return "contains"
    elif op == MatchOP.MATCH_BEGINS_WITH:
        return "begins with"
    elif op == MatchOP.MATCH_ENDS_WITH:
        return "ends with"
    elif op == MatchOP.MATCH_LESS_THAN:
        return "<"
    elif op == MatchOP.MATCH_GREATER_THAN:
        return ">"
    elif op == MatchOP.MATCH_LESS_EQUAL:
        return "<="
    elif op == MatchOP.MATCH_GREATER_EQUAL:
        return ">="
    elif op == MatchOP.MATCH_ON:
        return "on"
    elif op == MatchOP.MATCH_BEFORE:
        return "before"
    elif op == MatchOP.MATCH_AFTER:
        return "after"
    elif op == MatchOP.MATCH_ON_OR_BEFORE:
        return "on or before"
    elif op == MatchOP.MATCH_ON_OR_AFTER:
        return "on or after"
    elif op == MatchOP.MATCH_ABSENT:
        return "absent"
    else:
        raise Exception(f"Unknown match op code {op}")


def _write_num(s: BinaryIO, num: int):
    s.write(struct.pack(">I", num))


def _write_timestamp(s: BinaryIO, timestamp: int):
    s.write(struct.pack(">Q", timestamp))


def _write_var_bytes(s: BinaryIO, arg: bytes):
    str_len = len(arg)

    s.write(struct.pack(">I", str_len))
    if str_len % 4 != 0:
        str_len = ((str_len // 4) + 1) * 4
    s.write(struct.pack(f"{str_len}s", arg))


# Base class for match opcode expressions
class MatchExpr(object):
    def __init__(self, opcode: MatchOP):
        self.opcode = opcode

    def __str__(self):
        return _get_match_op_name(self.opcode)

    def __repr__(self):
        return self.__str__()

    def serialize(self, s: BinaryIO):
        _write_num(s, self.opcode)


class ArgMatchExpr(MatchExpr):
    def __init__(self, opcode: MatchOP, arg: bytes):
        super().__init__(opcode)
        self.arg = arg

    def __str__(self):
        return f"{_get_match_op_name(self.opcode)} {self.arg}"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_var_bytes(s, self.arg)


class TimestampMatchExpr(MatchExpr):
    def __init__(self, opcode: MatchOP, timestamp: int):
        super().__init__(opcode)
        self.timestamp = timestamp

    def __str__(self):
        return f"{_get_match_op_name(self.opcode)} {self.timestamp}"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_timestamp(s, self.timestamp)


# Base class for opcode expressions. Also for single opcode expressions.
class Expr(object):
    def __init__(self, opcode: ExprOp):
        self.opcode = opcode

    def __str__(self):
        return _get_op_name(self.opcode)

    def __repr__(self):
        return self.__str__()

    def serialize(self, s: BinaryIO):
        _write_num(s, self.opcode)


# Class for "and" and "or" expressions
class AndOrExpr(Expr):
    def __init__(self, opcode: ExprOp, left: Expr, right: Expr):
        super().__init__(opcode)
        self.left = left
        self.right = right

    def __str__(self):
        return f"({self.left}) {_get_op_name(self.opcode)} ({self.right})"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        self.left.serialize(s)
        self.right.serialize(s)


# Class for opcodes that have a single argument
class SingleArgExpr(Expr):
    def __init__(self, opcode: ExprOp, arg: bytes):
        super().__init__(opcode)
        self.arg = arg

    def __str__(self):
        return f"{_get_op_name(self.opcode)} {self.arg}"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_var_bytes(s, self.arg)


class SingleIntExpr(Expr):
    def __init__(self, opcode: ExprOp, arg: int):
        super().__init__(opcode)
        self.arg = arg

    def __str__(self):
        return f"{_get_op_name(self.opcode)} {self.arg}"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_num(s, self.arg)


class InfoKVExpr(Expr):
    def __init__(self, opcode: ExprOp, key: bytes, value: bytes):
        super().__init__(opcode)
        self.key = key
        self.value = value

    def __str__(self):
        return f"Info.plist key {self.key} has value {self.value}"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_var_bytes(s, self.key)
        _write_var_bytes(s, self.value)


class KeyMatchExpr(Expr):
    def __init__(self, opcode: ExprOp, key: bytes, match: MatchExpr):
        super().__init__(opcode)
        self.key = key
        self.match = match

    def __str__(self):
        return f"{_get_op_name(self.opcode)} {self.key} has value {self.value}"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_var_bytes(s, self.key)
        self.match.serialize(s)


class CertificateMatch(Expr):
    def __init__(self, opcode: ExprOp, cert_index: int, field: bytes, match: MatchExpr):
        super().__init__(opcode)
        self.cert_index = cert_index
        self.field = field
        self.match = match

    def __str__(self):
        return f"{_get_op_name(self.opcode)} ({self.cert_index}, {self.field.hex()}, {self.match})"

    def serialize(self, s: BinaryIO):
        super().serialize(s)
        _write_num(s, self.cert_index)
        _write_var_bytes(s, self.field)
        self.match.serialize(s)


class Requirement(object):
    def __init__(self, expr: Expr):
        self.expr = expr

    def __str__(self):
        return str(self.expr)

    def __repr__(self):
        return self.__str__()

    def serialize(self, s):
        self.expr.serialize(s)


def _read_num(s: BinaryIO):
    (num,) = struct.unpack(">I", sread(s, 4))
    return num


def _read_timestamp(s: BinaryIO):
    (num,) = struct.unpack(">Q", sread(s, 8))
    return num


def _read_var_bytes(s: BinaryIO):
    str_len = _read_num(s)
    (data,) = struct.unpack(f"{str_len}s", sread(s, str_len))

    # Align to 4 byte multiple
    if str_len % 4 != 0:
        diff = (((str_len // 4) + 1) * 4) - str_len
        sread(s, diff)
    return data


def _deserialize_match_expr(s) -> MatchExpr:
    while True:
        op = _read_num(s)

        # Process arguments to each op code
        if op == MatchOP.MATCH_EXISTS or op == MatchOP.MATCH_ABSENT:
            return MatchExpr(op)
        elif (
            op == MatchOP.MATCH_EQUAL
            or op == MatchOP.MATCH_CONTAINS
            or op == MatchOP.MATCH_BEGINS_WITH
            or op == MatchOP.MATCH_ENDS_WITH
            or op == MatchOP.MATCH_LESS_THAN
            or op == MatchOP.MATCH_GREATER_THAN
            or op == MatchOP.MATCH_LESS_EQUAL
            or op == MatchOP.MATCH_GREATER_EQUAL
        ):
            data = _read_var_bytes(s)
            return ArgMatchExpr(op, data)
        elif (
            op == MatchOP.MATCH_ON
            or op == MatchOP.MATCH_BEFORE
            or op == MatchOP.MATCH_AFTER
            or op == MatchOP.MATCH_ON_OR_BEFORE
            or op == MatchOP.MATCH_ON_OR_AFTER,
        ):
            timestamp = _read_timestamp(s)
            return TimestampMatchExpr(op, timestamp)
        else:
            raise Exception(f"Unknown requirement op code {op}")

    raise Exception(f"Unable to parse expression")


def _deserialize_expr(s: BinaryIO) -> Expr:
    while True:
        full_op = _read_num(s)

        # Process arguments to each op code
        op = full_op & ~OP_FLAG_MASK  # type: ignore
        if (
            op == ExprOp.OP_FALSE
            or op == ExprOp.OP_TRUE
            or op == ExprOp.OP_APPLE_ANCHOR
            or op == ExprOp.OP_APPLE_GENERIC_ANCHOR
            or op == ExprOp.OP_TRUSTED_CERTS
            or op == ExprOp.OP_APPLE_GENERIC_ANCHOR
            or op == ExprOp.OP_NOTARIZED
            or op == ExprOp.OP_LEGACY_DEV_ID
        ):
            return Expr(full_op)
        elif (
            op == ExprOp.OP_IDENT
            or op == ExprOp.OP_ANCHOR_HASH
            or op == ExprOp.OP_CD_HASH
            or op == ExprOp.OP_NOT
            or op == ExprOp.OP_NAMED_ANCHOR
            or op == ExprOp.OP_NAMED_CODE
        ):
            data = _read_var_bytes(s)
            return SingleArgExpr(full_op, data)
        elif op == ExprOp.OP_INFO_KEY_VALUE:
            key = _read_var_bytes(s)
            value = _read_var_bytes(s)
            return InfoKVExpr(full_op, key, value)
        elif op == ExprOp.OP_AND or op == ExprOp.OP_OR:
            left = _deserialize_expr(s)
            right = _deserialize_expr(s)
            return AndOrExpr(full_op, left, right)
        elif op == ExprOp.OP_INFO_KEY_FIELD or op == ExprOp.OP_ENTITLEMENT_FIELD:
            key = _read_var_bytes(s)
            match = _deserialize_match_expr(s)
            return KeyMatchExpr(full_op, key, match)
        elif (
            op == ExprOp.OP_CERT_FIELD
            or op == ExprOp.OP_CERT_GENERIC
            or op == ExprOp.OP_CERT_POLICY
            or op == ExprOp.OP_CERT_FIELD_DATE
        ):
            idx = _read_num(s)
            field = _read_var_bytes(s)
            match = _deserialize_match_expr(s)
            return CertificateMatch(full_op, idx, field, match)
        elif op == ExprOp.OP_TRUSTED_CERT or op == ExprOp.OP_PLATFORM:
            idx = _read_num(s)
            return SingleIntExpr(full_op, idx)
        else:
            raise Exception(f"Unknown requirement op code {op}")

    raise Exception(f"Unable to parse expression")


def deserialize_requirement(s: BinaryIO) -> Requirement:
    return Requirement(_deserialize_expr(s))
