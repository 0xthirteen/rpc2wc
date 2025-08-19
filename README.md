# RPC to WebClient

The information for this code can be found at [this blog post](https://specterops.io/blog/2025/08/19/will-webclient-start/). Recommend reading before attempting to use anything here.

Code for triggering WebClient through an RPC call. Since it did not end up panning out the code was never very cleaned up and very much remained in a proof of concept state. 

These RPC calls are capable of reaching the code path to start the service:
* EfsRpcDuplicateEncryptionInfoFile_Downlevel -> EfsDuplicateEncryptionInfoRPCClient -> EfsDuplicateEncryptionInfoClient -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcEncryptFileSrv_Downlevel -> EfsEncryptFileClient -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcDecryptFileSrv_Downlevel -> EfsDecryptFileClient -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcAddUsersToFileEx_Downlevel -> EfsAddUsersClientEx -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcRemoveUsersFromFile_Downlevel -> EfsRemoveUsersClient -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcQueryRecoveryAgents_Downlevel -> EfsQueryRecoveryAgentsClient -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcQueryUsersOnFile_Downlevel -> EfsQueryUsersClient -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton
* EfsRpcFileKeyInfo_Downlevel -> EfsFileKeyInfoClient -> LocateAndConnectToService -> EfspGetFullName -> EfspAttemptToGetWebDavPath -> WNetGetResourceInformaton

Only EfsRpcEncryptFileSrv_Downlevel exists in the repo, maybe the others will be added in the future. 

WnfToWebClient is .NET code that will start the WebClient service with a WNF message. Requires NT AUTHORITY/SYSTEM privileges, so again just a proof of concept.

The RPC call and the WNF message are not really weaponizable (currently) due to the security descriptors of the ETW event consumer (UBPM) and the WNF state name. 