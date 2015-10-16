# ReadMe for Private.me Cloud Storage Client Demo

# Overview

This demo code demonstrates for partners how to interact with the Standard
Clouds / Private.me privacy based cloud storage platform.

This is a sample implementation written in Python 2.7.

# How it Works

Every read and write on the cloud storage platform involves a check with the 
GateKeeper web service first, which will evaluate whether the named end user 
approves the current read or write operation.  If the operation is approved,
the gatekeeper responds with the hostname and approval signature to then
allow performing the operation directly against the storage endpoint, which is
a server that exposes a cloud storage endpoint compatible with the S3 
authentication protocol.


# Python Sample

Included in this folder are the following Python modules that should run 
standalone with a dependency only on Python 2.7:

CloudStorage.py --       A generic module we would provide to partners intended
                         for use as-is.
                   
Example.py --            A sample module to serve as a starting point for 
                         partners in developing custom solutions.  This just 
                         demonstrates some reads and writes, and should give 
                         partners enough of a start to be able to extend to 
                         their own purposes.
                   
TestCredentials.py --    The testing credentials issued to you individually, 
                         pre-filled and ready for use by the test script.
                   

