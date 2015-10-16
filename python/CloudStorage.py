# Copyright (c) 2014 Standard Clouds, Inc. All Rights Reserved.

import base64
import hmac
import json
import mimetypes
import os
import ssl
import time
import urllib
import urllib2

from Crypto.Hash import SHA, SHA256, MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

# JSON field names returned from the gatekeeper
kGatekeeperFieldResponseId = 'responseId'
kGatekeeperFieldErrorMsg = 'errorMsg'
kGatekeeperFieldHttpRequestStr = 'httpRequestStr'
kGatekeeperFieldStorageHostName = 'cloudStorageHostName'

# Response codes from the gatekeeper indicating success or failure status.
kResponseIdSuccess = "Success"
kResponseIdErrorBadSignature = "BadSignature"
kResponseIdErrorSubscribingUserDisallowedAccess = "SubscribingUserDisallowedAccess"
kResponseIdErrorNonSubscribingUser = "NonSubscribingUser"
kResponseIdErrorInvalidParams = "InvalidParams"
kResponseIdError = "Error"

kKnownResponseCodes = \
(
   kResponseIdSuccess,
   kResponseIdErrorBadSignature,
   kResponseIdErrorSubscribingUserDisallowedAccess,
   kResponseIdErrorNonSubscribingUser,
   kResponseIdErrorInvalidParams
)

class GatekeeperError(Exception):
   '''Raised when the Gatekeeper has either indicated an error or refused access.'''
   def __init__(self, authInfo):
      self.authInfo = authInfo

_lastRequestDuration = None

def Get(
 gateKeeperHostName, 
 appIdStr, 
 appPrivateKeyStr,
 userEmail,
 fileName):
   """Reads a file from cloud storage."""
   authInfo = _ValidateRequestWithGateKeeper(
    gateKeeperHostName, 
    appIdStr, 
    appPrivateKeyStr,
    "GET",
    userEmail,
    fileName)
   responseId = authInfo[kGatekeeperFieldResponseId]
   if kResponseIdSuccess == responseId:
      return authInfo, _PerformStorageRequest(
       authInfo[kGatekeeperFieldStorageHostName], 
       authInfo[kGatekeeperFieldHttpRequestStr])
   else:
      return authInfo, None

def Put(
 gateKeeperHostName, 
 appIdStr, 
 appPrivateKeyStr,
 userEmail,
 fileName,
 fileContents):
   """Writes a file to cloud storage."""
   authInfo = _ValidateRequestWithGateKeeper(
    gateKeeperHostName, 
    appIdStr, 
    appPrivateKeyStr,
    "PUT",
    userEmail,
    fileName,
    fileContents)
   responseId = authInfo[kGatekeeperFieldResponseId]
   if kResponseIdSuccess == responseId:
      _PerformStorageRequest(
       authInfo[kGatekeeperFieldStorageHostName], 
       authInfo[kGatekeeperFieldHttpRequestStr],
       fileContents)
      return authInfo
   else:
      return authInfo, None


def _SignGateKeeperRequest(requestParamsStr, privateKeyStr):
   assert requestParamsStr.endswith("sig=")
   # Hash the normalized params str
   hash = SHA256.new(requestParamsStr)

   # Sign the hash
   kUnusedK = "";
   key = RSA.importKey(privateKeyStr)
   signer = PKCS1_v1_5.new(key)
   signature = signer.sign(hash)  # trim extraneous char
   
   # Convert to base64 and urlencode so it's ready to append to params.
   sigAsBase64 = base64.b64encode(signature)
   signatureParam = urllib.quote(sigAsBase64, '')
   return requestParamsStr + signatureParam

def GetNormalizedParamsStr(
 verb, 
 appIdStr,
 userEmail,
 fileName,
 contentLengthOrNone=None,
 contentMd5OrNone=None):
   """Returns a normalized string for signing/verifying."""
   
   result = "appid=%s&filename=%s&useremail=%s" % (
    urllib.quote(appIdStr, ''),
    urllib.quote(fileName, ''),
    urllib.quote(userEmail, ''))
   if 'PUT' == verb:
      result += "&contentlen=%d&contentmd5=%s" % (
       int(contentLengthOrNone),
       urllib.quote(contentMd5OrNone, ''))
   result += "&sig="
   return result

def _Md5Encode(bytes):
   return MD5.new(bytes).digest().encode("base64")[:-1]
   
def _ValidateRequestWithGateKeeper(
 gateKeeperHostName, 
 appIdStr, 
 appPrivateKeyStr,
 verb,
 userEmail,
 fileName, 
 payloadData=None):
   """Accesses a gatekeeper host to authenticate a cloud storage operation."""
  
   startTime = time.time()
   
   # Form a URL with everything except the signature (which is of the URL 
   # itself, so we can't add it yet anyway).
   paramsStr = GetNormalizedParamsStr(
    verb,
    appIdStr,
    userEmail,
    fileName,
    None if not payloadData else len(payloadData),
    None if not payloadData else _Md5Encode(payloadData))

   paramsStr = _SignGateKeeperRequest(paramsStr, appPrivateKeyStr)
   url = "%s/api/v1/file?%s" % (gateKeeperHostName, paramsStr)
   try:
      headers = {'Authorization': 'Basic c2NkZXY6cGFzczRTQ0Q=',}
      request = urllib2.Request(url, headers=headers)
      request.get_method = lambda : verb
      responseReader = urllib2.urlopen(request)
   except urllib2.HTTPError, exc:
      responseReader = exc
   try:
      authInfo = json.loads(responseReader.read())
      responseId = authInfo[kGatekeeperFieldResponseId]
      if responseId not in kKnownResponseCodes:
         print "Unknown response code of '%s'. This may be normal, check for an updated SDK." % responseId
   except Exception, exc:
      raise GatekeeperError(
         {
            kGatekeeperFieldResponseId: kResponseIdError,
            kGatekeeperFieldErrorMsg: str(exc),
         })
   if kResponseIdSuccess != responseId:
      raise GatekeeperError(authInfo)
   return authInfo

def _PerformStorageRequest(storageHostName, sessionStr, payloadData=None):
   """Following successful authentication and authorization from the 
      gatekeeper service, gets/puts data to the remote cloud storage."""

   startTime = time.time()
   
   # parse out distinct HTTP request parts
   try:
      firstLine, remainder = sessionStr.split('\r\n', 1)
      verb, url, httpSpec = firstLine.split(' ')
      headers = [tuple(s.split(': ', 1)) for s in remainder.strip().split('\r\n')]
      url = storageHostName.rstrip("/") + '/' + url.lstrip('/')
      url = ('https://' if ':' not in storageHostName else '') + url
   except:
      raise ValueError("Parameter sessionStr not in required format.")
   if "PUT" == verb and payloadData == None:
      raise ValueError("Parameter payloadData is required for an upload or Put.")

   # disable SSL verification
   import ssl
   if hasattr(ssl, '_create_unverified_context'):
      ssl._create_default_https_context = ssl._create_unverified_context
      print "Note: disabling SSL verification (TESTING ONLY; DO NOT DEPLOY TO PRODUCTION)"

   # create http request
   request = urllib2.Request(url, data=payloadData)
   request.get_method = lambda: verb

   # perform request with customer url opener to force using only our headers
   opener = urllib2.build_opener()
   opener.addheaders = headers
   
   # add extra debug reporting, but still let exceptions propagate up
   try:
      response = opener.open(request)
      result = response.read()
      responseCode = response.getcode()
      assert responseCode >= 200 and responseCode <= 299, \
       "Unexpected HTTP response code: " + str(responseCode)
      return result
   except urllib2.HTTPError, error:
      contents = error.read()
      # S3 compatible storage service usually gives us some hints here
      if "<StringToSignBytes>" in contents:
         print "contents: " + repr(contents)
         stringToSignBytes = contents.split("<StringToSignBytes>", 1)[1]
         stringToSignBytes = stringToSignBytes.split("<", 1)[0]
         print "stringToSignBytes: " + repr(stringToSignBytes)
         stringToSignBytes = "".join([chr(int(c, 16)) for c in 
          stringToSignBytes.strip().split(' ')])
         print "Error: Required stringToSignBytes: " + repr(stringToSignBytes)
      else:
         print "Error response contents: " + repr(contents)
      print ("HTTP error: " + repr(error) + ", " + 
       str(error.code) + ", " + 
       repr(error.read()))
      raise
   finally:
      _lastRequestDuration = time.time() - startTime

