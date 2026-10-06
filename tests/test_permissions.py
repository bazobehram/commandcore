from commandcore_server.permissions import allowed


def test_read_only_denies_shell_and_writes():
    assert allowed("READ_ONLY", "fs.read")
    assert not allowed("READ_ONLY", "fs.write")
    assert not allowed("READ_ONLY", "shell.exec")


def test_standard_allows_phase1_execution():
    assert allowed("STANDARD", "shell.exec")
    assert allowed("STANDARD", "process.stop")
    assert allowed("STANDARD", "transfer.upload")
