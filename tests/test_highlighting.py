from auth_server_playground.highlighting import highlight


def test_highlight_escapes_the_code():
    html = highlight('{"a": "<b>"}', "json")
    assert '<span class="s2">"&lt;b&gt;"</span>' in html
    assert "style=" not in html
    assert not html.endswith("\n")


def test_stylesheet(testapp):
    res = testapp.get("/highlight.css")
    assert res.content_type == "text/css"
    assert ".highlight .nt" in res.text
    assert "prefers-color-scheme: dark" in res.text
    testapp.get(
        "/highlight.css", headers={"If-None-Match": res.headers["ETag"]}, status=304
    )


def test_metadata_is_highlighted(testapp):
    res = testapp.get("/en/server")
    assert res.html.select_one("pre.highlight span.nt")
