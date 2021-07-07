"""
mitmproxy addons
ROCKMAN X DiVE handshake decrypter
http://github.com/brianpow/mitmproxy-addon-rockman-x-dive
"""
from mitmproxy import contentviews, ctx
from Cryptodome.Cipher import AES
import base64, re, json

aesiv=b'=!r19kCsGHTAcr/@'
aeskey=b'cbs4/+-jDAf!?s/#cbs4/+-jDAf!?s/#'
    
class ViewAESDecrypt(contentviews.View):
    name = "ROCKMAN X DiVE decrypter"
    content_types = ["text/plain","application/octet-stream"]
    
    def unpad(self, s):
        s = s.decode('utf-8')
        offset = ord(s[-1])
        return s[:-offset].encode('utf-8')
    def strip_non_base64(self, s):
        return re.sub(b'^[^A-Za-z0-9\+\/=]+', b'', s)
    def divisible_by_four(self, s):
        return s[len(s) % 4:]
    
    def __call__(self, data, **metadata):# -> contentviews.TViewResult:

        try:
          cipher=AES.new(aeskey, AES.MODE_CBC, aesiv)
          data1=self.strip_non_base64(data)
          data1=self.divisible_by_four(data1)
          data1=base64.decodebytes(data1)
          data1=cipher.decrypt(data1)
          data1=self.unpad(data1).decode('utf-8')
          data1=json.loads(data1)
          return "ROCKMAN X DiVE decrypter", contentviews.format_text(json.dumps(data1, sort_keys=True, indent=4))

        except Exception as e:
          ctx.log.error(repr(e))
          return contentviews.view(data, **metadata)
          
        
view = ViewAESDecrypt()

def load(l):
    contentviews.add(view)

def done():
    contentviews.remove(view)