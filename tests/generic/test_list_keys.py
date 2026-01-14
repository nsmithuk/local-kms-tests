
def test_create_description_failure(kms_client):
    code, content = kms_client.post('ListKeys',{
        "Limit": 2,
        "Marker": 'dGVzdA=='
        # "Marker": 'YXJuOmF3czprbXM6ZXUtd2VzdC0yOjExMTEyMjIyMzMzMzprZXkvMDFhYTBhMGEtOGJlYi00ODFiLWJhOGUtNGRkMzhkMDQ5OTI2'
        #"Marker": "arn:aws:kms:eu-west-2:111122223333:key/04da46eb-40de-4aad-b0a0-9d7427d657cd"
    })

    print(content)
