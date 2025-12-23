from badlog.ring import RingBuffer


def test_ring_buffer_keeps_tail():
    ring = RingBuffer(3)
    ring.extend(["a", "b", "c", "d"])
    assert ring.snapshot() == ["b", "c", "d"]
    assert ring.tail(2) == ["c", "d"]
