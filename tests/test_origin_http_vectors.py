import json
import pathlib

import pytest

from pubsrv import hub_path

V = json.loads((pathlib.Path(__file__).parent / "vectors" / "origin_http.json").read_text())


@pytest.mark.parametrize("o", V["accept"])
def test_accept(o):
    assert hub_path._relay_url(o)


@pytest.mark.parametrize("o", V["refuse"])
def test_refuse(o):
    assert not hub_path._relay_url(o)
