
def test_list_keys_with_limit(kms_client):
    code, content = kms_client.post('ListKeys',{
        "Limit": 2,
    })

    assert code == 200
    assert isinstance(content, dict)
    assert "Keys" in content
