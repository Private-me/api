# Copyright (c) 2014 Standard Clouds, Inc. All Rights Reserved.
import base64
from datetime import datetime

import CloudStorage

import TestCredentials

totalTestsRun = 0
totalTestsFailed = 0

def TestPutAndGetRoundTrip(privateKey, emailAddress, fileName, payloadStr, expectedResultIds):
   """Tests a cloud storage round trip under a specific software service 
   identity, set up by Standard Clouds for testing purposes."""

   print "-" * 79
   print "Testing with email '%s'...\n" % emailAddress
   print ""
   
   isFailed = True  # cleared below on success
   responseAuthInfo = None
   try:
      responseAuthInfo = CloudStorage.Put(
       TestCredentials.kTestHost,
       TestCredentials.kTestSaaSId,
       privateKey,
       emailAddress,
       fileName,
       base64.b64encode(payloadStr))
      responseAuthInfo, roundTripResult = CloudStorage.Get(
       TestCredentials.kTestHost,
       TestCredentials.kTestSaaSId,
       privateKey,
       emailAddress,
       fileName)
      if base64.b64decode(roundTripResult) != payloadStr:
         raise Exception, "Unexpected result from round trip file put/get."
      isFailed = False
   except Exception, exc:
      if type(exc) is CloudStorage.GatekeeperError:
         responseAuthInfo = exc.authInfo
         resultId = exc.authInfo[CloudStorage.kGatekeeperFieldResponseId]
      else:
         resultId = None
      if resultId not in expectedResultIds:
         import traceback
         traceback.print_exc()
      pass
   resultId = None if not responseAuthInfo else \
    responseAuthInfo[CloudStorage.kGatekeeperFieldResponseId]
   print "Response authInfo: " + repr(responseAuthInfo)
   print "\n"
   print "Response code: " + repr(resultId)
   print "\n"
   isSuccessful = resultId in expectedResultIds
   if isSuccessful:
      print "OK: expected response"
   else:
      print "ERROR: unexpected response, should have been: %s" % \
       repr(expectedResultIds)
   print "\n\n\n"
   global totalTestsRun
   global totalTestsFailed
   totalTestsRun += 1
   totalTestsFailed += 0 if isSuccessful else 1

# You can specify any file name you want, and can have more than one for a given
# person who is a user of your service.  For example, you could have one file
# that stores the person's profile metadata, and a separate file that stores 
# their profile picture.  Just specify a different file name when performing the 
# Get and Put operations.
kTestFileName = "TestFileName"

# This can be arbitrary file content to be stored in the cloud storage.
kTestPayloadStr = "Sample text for payload string " + str(datetime.utcnow())

# The below user email addresses are provided for testing.  Note that in 
# order to simulate real world conditions with Standard Clouds, there is a
# possibility that access will fail due to the user choosing to disable access
# from their control panel.  For ease of testing, one user's access is always 
# off, another user's access is always on.  A third cycles on and off, switching
# states every 10 seconds.
kEmailAddressAlwaysOff = "alwaysoff@testing.private.me"
kEmailAddressAlwaysOn = "alwayson@testing.private.me"
kEmailAddressAutoOnOffEveryTenSeconds = "autocycle10sec@testing.private.me"
kEmailAddressNonSubscribingUser = "billg@microsoft.com"

# Run some tests and ensure that we see expected behavior.    
try:
   # always fails with "user disallowed"
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=kEmailAddressAlwaysOff,
    fileName=kTestFileName,
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdErrorSubscribingUserDisallowedAccess])

   # always succeeds
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=kEmailAddressAlwaysOn,
    fileName=kTestFileName,
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdSuccess])

   # alternately succeeds and fails
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=kEmailAddressAutoOnOffEveryTenSeconds,
    fileName=kTestFileName,
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdSuccess, CloudStorage.kResponseIdErrorSubscribingUserDisallowedAccess])

   # file name can't be blank
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=kEmailAddressAlwaysOn,
    fileName="", 
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdErrorInvalidParams])

   # filename length too long
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=kEmailAddressAlwaysOn,
    fileName="A" * 257,  
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdErrorInvalidParams])

   # bad signature
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyBad,
    emailAddress=kEmailAddressAlwaysOn,
    fileName=kTestFileName,
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdErrorBadSignature])

   # Either not a Private.me user, or not a user associated with our app.
   # The server won't reveal which, for security reasons.
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=kEmailAddressNonSubscribingUser,
    fileName=kTestFileName,
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdErrorNonSubscribingUser])

   # Either not a Private.me user, or not a user associated with our app.
   # The server won't reveal which, for security reasons.
   TestPutAndGetRoundTrip(
    privateKey=TestCredentials.kPrivateKeyGood,
    emailAddress=TestCredentials.kTestSandboxEmailAddress,
    fileName=kTestFileName,
    payloadStr=kTestPayloadStr,
    expectedResultIds=[CloudStorage.kResponseIdSuccess])

except:
   import traceback
   traceback.print_exc()
finally:
   print "=" * 79
   print "%s - Finished running tests, and %s." % \
    (("SUCCESS", ("all %d tests passed" % totalTestsRun)) if not totalTestsFailed else \
    ("ERROR", "%d of %d tests failed" % (totalTestsFailed, totalTestsRun)))
