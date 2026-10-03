from fastapi.testclient import TestClient
from backend.app.main import app
client=TestClient(app)

def test_health():
    r=client.get('/api/health'); assert r.status_code==200; assert r.json()['status']=='ok'

def test_analyze():
    r=client.post('/api/analyze', json={'code':'password = "secret"\nvalue = eval(user_input)\n'})
    assert r.status_code==200
    body=r.json(); assert len(body['findings'])==2
    assert {f['cwe_id'] for f in body['findings']}=={'CWE-95','CWE-798'}

def test_invalid_python():
    r=client.post('/api/analyze', json={'code':'def x(:\n'})
    assert r.status_code==422
