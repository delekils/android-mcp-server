from badlog.reconnect import ReconnectController, ReconnectState


def test_reconnect_backoff_resets_on_connect() -> None:
    controller = ReconnectController(base_delay=1.0, max_delay=4.0)
    delay1 = controller.disconnected()
    delay2 = controller.disconnected()
    assert delay1 == 1.0
    assert delay2 == 2.0
    controller.connected()
    assert controller.state == ReconnectState.STREAMING
    delay3 = controller.disconnected()
    assert delay3 == 1.0
