{

Copyright (c) 2016, Prometheus <prometheus@unterderbruecke.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of libressl-libtls-delphi nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

}

unit LibreSsl.Interfaces;

interface

uses
  System.Classes,
  System.SysUtils;

type
  ETlsError = class(Exception)

  end;

  ITlsConfig = interface
    ['{5D90A610-B1C0-415D-922D-7835043FDF23}']
    procedure ClearKeys;
    function GetContext: Pointer;
    procedure InsecureNoverifycert;
    procedure InsecureNoverifyname;
    procedure InsecureNoverifytime;
    procedure PreferCiphersClient;
    procedure PreferCiphersServer;
    procedure SetCaFile(const ACAFile: string);
    procedure SetCaMem(const ACA: TBytes);
    procedure SetCaPath(const ACAPath: string);
    procedure SetCertFile(const ACertFile: string);
    procedure SetCertMem(const ACert: TBytes);
    procedure SetCertPath(const ACertPath: string);
    procedure SetCiphers(const ACiphers: string);
    procedure SetDheparams(const AParams: string);
    procedure SetEcdhecurve(const AName: string);
    procedure SetKeyFile(const AKeyFile: string);
    procedure SetKeyMem(const AKey: TBytes);
    procedure SetProtocols(const AProtocols: UInt32);
    procedure SetVerifyDepth(const AVerifyDepth: Integer);
    procedure Verify;
    procedure VerifyClient;
    procedure VerifyClientOptional;
  end;

  ITlsPeerCert = interface
    ['{DCB8EE2B-E97E-4E97-9C11-70726644CDA2}']
    function ContainsName(const AName: string): Boolean;
    function Hash: string;
    function Issuer: string;
    function NotAfter: TDateTime;
    function NotBefore: TDateTime;
    function Provided: Boolean;
    function Subject: string;
  end;

  ITls = interface
    ['{B5BF092C-DBA9-493E-A299-FCA143F4627C}']
    function AcceptFds(const AFdRead, AFdWrite: Integer): ITls;
    function AcceptSocket(const ASocket: Integer): ITls;
    procedure Close;
    function ConnCipher: string;
    procedure Connect(const AHost, APort: string);
    procedure ConnectFds(const AFdRead, AFdWrite: Integer;
      const AServerName: string);
    procedure ConnectServerName(const AHost, APort: string;
      const AServerName: string);
    procedure ConnectSocket(const ASocket: Integer; const AServerName: string);
    function ConnVersion: string;
    function GetPeerCert: ITlsPeerCert;
    procedure Handshake;
    function Read(const ABuffer: TBytes): NativeInt;
    procedure Reset;
    function Write(const ABuffer: TBytes): NativeInt;
  end;

implementation

end.

