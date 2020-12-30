import secrets
import sdkms
import os
import sdkms.v1
from sdkms.v1.models.cipher_mode import CipherMode
from sdkms.v1.models.object_type import ObjectType
from sdkms.v1.models.sobject_descriptor import SobjectDescriptor

api_key = ""

def login():
    config = sdkms.v1.Configuration()
    config.host = "https://apps.sdkms.fortanix.com"
    config.app_api_key = api_key
    client = sdkms.v1.ApiClient(configuration=config)
    auth_instance = sdkms.v1.AuthenticationApi(api_client=client)
    try:
        auth = auth_instance.authorize()
        config.api_key['Authorization'] = auth.access_token
        config.api_key_prefix['Authorization'] = 'Bearer'
        return client
    except sdkms.v1.configuration.ApiException as e:
        print("Exception when calling AuthenticationApi->authorize: %s\n" % e)
        return None

def get_key(kid):
    client= login()
    api_instance = sdkms.v1.SecurityObjectsApi(api_client=client)
    request = sdkms.v1.SobjectRequest("00c6d4d3-fe84-471d-a039-a76d3b117500")
    try:                
        key = api_instance.get_security_object(kid)
        return key 
    except sdkms.v1.configuration.ApiException as e:
        print("Exception when calling SecurityObjectsApi->get_security_object: %s\n" % e)
        return None

def generate_key(name):
    client= login()
    token = str(secrets.token_hex(16))
    name = name + token
    api_instance = sdkms.v1.SecurityObjectsApi(api_client=client)
    request = sdkms.v1.SobjectRequest(name=name,key_size=128,obj_type=sdkms.v1.ObjectType.AES)
    try:                
        key = api_instance.generate_security_object(request)
        return key
    except sdkms.v1.configuration.ApiException as e:
        print("Exception when calling SecurityObjectsApi->generate_security_object: %s\n" % e)
        return None

def encrypt(name,s):
    client = login()
    plain = bytearray()
    plain.extend(map(ord,s))
    api_instance = sdkms.v1.EncryptionAndDecryptionApi(api_client=client)
    sobject_descriptor = sdkms.v1.SobjectDescriptor(name=name)
    request = sdkms.v1.EncryptRequestEx(sobject_descriptor,alg=ObjectType.AES, plain=plain, mode=CipherMode.CBC)
    try:
        encryption_response = api_instance.encrypt_ex(request)
        return encryption_response
    except sdkms.v1.configuration.ApiException as e:
        print("Exception when calling EncryptionAndDecryptionApi->encrypt_ex: %s\n" % e)
        return None

def decrypt(name,s,iv):
    client = login()
    api_instance = sdkms.v1.EncryptionAndDecryptionApi(api_client=client)
    sobject_descriptor = sdkms.v1.SobjectDescriptor(name=name)
    decryption_request = sdkms.v1.DecryptRequestEx(sobject_descriptor,alg=ObjectType.AES,
            mode=CipherMode.CBC,
            cipher=s,
            iv=iv)
    try:
        decryption_response = api_instance.decrypt_ex(decryption_request)
        return decryption_response
    except sdkms.v1.configuration.ApiException as e:
        print("Exception when calling EncryptionAndDecryptionApi->decrypt_ex: %s\n" % e)

def rotate_key(name):
    client = login()
    api_instance = sdkms.v1.SecurityObjectsApi(api_client=client)
    request = sdkms.v1.SobjectRequest(name=name,key_size=128,obj_type=sdkms.v1.ObjectType.AES)
    try:                
        key = api_instance.rotate_security_object(request)
        return key
    except sdkms.v1.configuration.ApiException as e:
        print("Exception when calling SecurityObjectsApi->generate_security_object: %s\n" % e)
        return None

key=generate_key('test')

name = key.name

encryption = encrypt(name,"Hello World")
iv = encryption.iv

print(encryption.cipher)

decryption = decrypt(name,encryption.cipher,iv)

print(decryption.plain.decode())

rotation = rotate_key(name)

rotated_key = get_key(rotation.kid)

print(rotated_key)

decryption = decrypt(rotation.name,encryption.cipher,iv)

"""print(decryption.plain.decode())"""
