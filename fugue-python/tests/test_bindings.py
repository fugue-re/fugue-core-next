from pathlib import Path

import pytest

import fugue


ROOT = Path(__file__).resolve().parents[2]
LS_ELF = ROOT / "fugue-core" / "tests" / "ls.elf"


def test_map_bytes_accepts_bytes_like_inputs():
    storage = fugue.SegmentStorage.empty()
    segment = storage.map_bytes("buf", 0x1000, memoryview(b"\x90\x90\xcc"))

    assert segment.name == "buf"
    assert segment.address.offset == 0x1000
    assert segment.size == 3
    assert segment.bytes == b"\x90\x90\xcc"
    assert storage.read_bytes(0x1000, 3) == b"\x90\x90\xcc"

    storage.write_bytes(0x1001, bytearray(b"\xcc"))
    assert storage.read_bytes(0x1000, 3) == b"\x90\xcc\xcc"


def test_load_binary_and_populate_segment_storage():
    binary = fugue.Binary.from_file(LS_ELF)

    assert binary.language.id == "x86:LE:64:default"
    assert str(binary.architecture) == "x86:LE:64:default"
    assert binary.segments()

    storage = fugue.SegmentStorage.from_binary(binary)
    executable = next(segment for segment in binary.segments() if segment.properties.execute)

    assert storage.contains(executable.address)
    assert storage.read_bytes(executable.address, min(executable.size, 4))


def test_loader_attributes_are_converted_from_dict():
    binary = fugue.Binary.from_file(
        LS_ELF,
        attributes={
            "address_space": 3,
            "custom": {"name": "example", "values": [1, True, None]},
        },
    )

    executable = next(segment for segment in binary.segments() if segment.properties.execute)
    assert executable.address.space == 3

    storage = fugue.SegmentStorage.from_binary(binary, attributes={"custom_storage": 1})
    assert storage.contains(executable.address)


def test_segment_hints_preserve_structured_addresses():
    binary = fugue.Binary.from_file(LS_ELF)
    segments = binary.segments()
    function_hints = [
        address
        for segment in segments
        for address in segment.function_hints
    ]
    mapping_hints = [
        hint
        for segment in segments
        for hint in segment.mapping_hints
    ]

    assert function_hints
    assert isinstance(function_hints[0], fugue.Address)

    if mapping_hints:
        assert isinstance(mapping_hints[0].address, fugue.Address)
        assert mapping_hints[0].hint.kind in {"code", "data"}
        assert mapping_hints[0].hint.text


def test_attributes_must_be_dicts():
    with pytest.raises(ValueError):
        fugue.Binary.from_file(LS_ELF, attributes=["address_space", 3])


def test_disassemble_and_lift_from_storage():
    binary = fugue.Binary.from_file(LS_ELF)
    storage = fugue.SegmentStorage.from_binary(binary)
    executable = next(segment for segment in binary.segments() if segment.properties.execute)
    lifter = binary.lifter()

    disassembled = lifter.disassemble(executable.address, storage)
    assert disassembled.length > 0
    assert disassembled.disassembly

    address = executable.address
    lifted = None
    for _ in range(32):
        candidate = lifter.lift(address, storage)
        if candidate.pcode:
            lifted = candidate
            break
        address = candidate.next_address

    assert lifted is not None
    assert lifted.length > 0
    assert lifted.pcode
    assert lifted.pcode[0].op
    assert lifted.pcode[0].text


def test_invalid_address_raises_storage_error():
    binary = fugue.Binary.from_file(LS_ELF)
    storage = fugue.SegmentStorage.from_binary(binary)

    with pytest.raises(fugue.StorageError):
        binary.lifter().disassemble(0xffffffffffff, storage)
