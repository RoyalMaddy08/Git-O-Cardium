def test_streamlit_app_smoke():
    try:
        from streamlit.testing.v1 import AppTest
    except ImportError:
        return  # streamlit not installed; skipped
    at = AppTest.from_file("app.py", default_timeout=30).run()
    assert not at.exception
