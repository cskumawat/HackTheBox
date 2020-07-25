import requests
import base64


InviteCode = requests.post("https://www.hackthebox.eu/api/invite/generate", headers={"User-Agent":"Hack The Box"})
Code = InviteCode.json()["data"]["code"]
InviteCode=base64.b64decode(Code).decode('utf-8')
print("Your Invitation Code : ", InviteCode)
