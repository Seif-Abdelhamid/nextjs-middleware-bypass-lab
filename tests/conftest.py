def pytest_configure(config):
    config.addinivalue_line("markers", "integration: boots the real Next.js apps (needs node + npm install)")
