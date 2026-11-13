def test_page_uses_the_default_language(testapp):
    res = testapp.get("/")
    assert '<html lang="en"' in res.text


def test_page_follows_the_browser_language(testapp):
    res = testapp.get("/", headers={"Accept-Language": "fr"})
    assert '<html lang="fr"' in res.text
