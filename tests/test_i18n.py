def test_admin_page_language_comes_from_the_url(testapp):
    assert '<html lang="en"' in testapp.get("/en/")
    assert '<html lang="fr"' in testapp.get("/fr/")


def test_interaction_page_follows_the_browser_language(testapp):
    res = testapp.get("/interaction/persona", headers={"Accept-Language": "fr"})
    assert '<html lang="fr"' in res


def test_interaction_page_follows_the_last_admin_language(testapp):
    testapp.get("/fr/")
    assert '<html lang="fr"' in testapp.get("/interaction/persona")


def test_language_links_keep_the_page(testapp):
    res = testapp.get("/en/server")
    assert res.html.select_one('footer a[href="/fr/server"]')


def test_admin_links_follow_the_browser_language(testapp):
    res = testapp.get("/interaction/persona", headers={"Accept-Language": "fr"})
    assert res.html.select_one("header h1 a")["href"] == "/fr/"
