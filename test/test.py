from ..trustauthx import authlite

client = authlite.AuthLiteClient(api_key="f28ffe7f2e4a47d6a796b0c2df073aeeAVVQBFSSCXIQWNQIEPBI", 
                        secret_key="8ad9741c8fd5a8f286fc34eba21e0871e63dff3dd67e3ea3a1b43077db9531f7", 
                        org_id="c3621ed40ccc4fca955779fab8f776c921e8865e439211ee88069dc8f7663e88")

print(client.generate_url())