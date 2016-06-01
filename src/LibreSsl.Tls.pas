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

unit LibreSsl.Tls;

interface

uses
  System.Classes,
  System.SysUtils,
  LibreSsl.Interfaces;

type
  TTls = class(TInterfacedObject, ITls)
  private
    FConfig: ITlsConfig;
    FContext: Pointer;
    FPeerCert: ITlsPeerCert;
    procedure Check(const AFunctionName: string; const AReturnCode: Integer);
    procedure Configure(const AConfig: ITlsConfig);
    constructor CreateWithContext(const AContext: Pointer);
  public
    constructor Create(const AServer: Boolean; const AConfig: ITlsConfig);
    destructor Destroy; override;
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
    class function LoadFile(const AFileName, APassword: string;
      out ALength: NativeUInt): Pointer; static;
  end;

implementation

uses
  LibreSsl.TlsApi, LibreSsl.TlsPeerCert;

{ TTls }

constructor TTls.Create(const AServer: Boolean; const AConfig: ITlsConfig);
begin
  inherited Create;
  FConfig := AConfig;

  if AServer then
  begin
    FContext := tls_server;
    if FContext = nil then
    begin
      raise ETlsError.Create('TLS creation error: tls_server returned NULL');
    end;
  end
  else
  begin
    FContext := tls_client;
    if FContext = nil then
    begin
      raise ETlsError.Create('TLS creation error: tls_client returned NULL');
    end;
  end;
  FPeerCert := TTlsPeerCert.Create(FContext) as ITlsPeerCert;
  Configure(FConfig);
  Assert(FContext <> nil);
  Assert(FPeerCert <> nil);
end;

constructor TTls.CreateWithContext(const AContext: Pointer);
begin
  Assert(AContext <> nil);
  inherited Create;
  FContext := AContext;
  FPeerCert := TTlsPeerCert.Create(FContext) as ITlsPeerCert;
  Assert(FContext <> nil);
  Assert(FPeerCert <> nil);
end;

destructor TTls.Destroy;
begin
  tls_free(FContext);
  inherited;
end;

function TTls.AcceptFds(const AFdRead, AFdWrite: Integer): ITls;
var
  ConnContext: Pointer;
begin
  Check('tls_accept_fds', tls_accept_fds(FContext, ConnContext, AFdRead,
    AFdWrite));
  Result := TTls.CreateWithContext(ConnContext);
end;

function TTls.AcceptSocket(const ASocket: Integer): ITls;
var
  ConnContext: Pointer;
begin
  Check('tls_accept_socket', tls_accept_socket(FContext, ConnContext, ASocket));
  Result := TTls.CreateWithContext(ConnContext);
end;

procedure TTls.Check(const AFunctionName: string; const AReturnCode: Integer);
begin
  if AReturnCode = -1 then
  begin
    raise ETlsError.CreateFmt('TLS error: %s - %s',
      [AFunctionName, string(UTF8String(tls_error(FContext)))]);
  end;
end;

procedure TTls.Close;
begin
  Check('tls_close', tls_close(FContext));
end;

procedure TTls.Configure(const AConfig: ITlsConfig);
begin
  Check('tls_configure', tls_configure(FContext, AConfig.GetContext));
end;

function TTls.ConnCipher: string;
begin
  Result := string(UTF8String(tls_conn_cipher(FContext)));
end;

procedure TTls.Connect(const AHost, APort: string);
begin
  Check('tls_connect', tls_connect(FContext, PAnsiChar(UTF8String(AHost)),
    PAnsiChar(UTF8String(APort))));
end;

procedure TTls.ConnectFds(const AFdRead, AFdWrite: Integer;
  const AServerName: string);
begin
  Check('tls_connect_fds', tls_connect_fds(FContext, AFdRead, AFdWrite,
    PAnsiChar(UTF8String(AServerName))));
end;

procedure TTls.ConnectServerName(const AHost, APort, AServerName: string);
begin
  Check('tls_connect_servername', tls_connect_servername(FContext,
    PAnsiChar(UTF8String(AHost)), PAnsiChar(UTF8String(APort)),
    PAnsiChar(UTF8String(AServerName))));
end;

procedure TTls.ConnectSocket(const ASocket: Integer; const AServerName: string);
begin
  Check('tls_connect_socket', tls_connect_socket(FContext, ASocket,
    PAnsiChar(UTF8String(AServerName))));
end;

function TTls.ConnVersion: string;
begin
  Result := string(UTF8String(tls_conn_version(FContext)));
end;

function TTls.GetPeerCert: ITlsPeerCert;
begin
  Result := FPeerCert;
end;

procedure TTls.Handshake;
begin
  Check('tls_handshake', tls_handshake(FContext));
end;

class function TTls.LoadFile(const AFileName, APassword: string;
  out ALength: NativeUInt): Pointer;
begin
  // TODO: How to call free() from libc?
  Result := tls_load_file(PAnsiChar(UTF8String(AFileName)), ALength,
    PAnsiChar(UTF8String(APassword)));
  if Result = nil then
  begin
    raise ETlsError.Create('TLS error: tls_load_file returned NULL');
  end;
end;

function TTls.Read(const ABuffer: TBytes): NativeInt;
begin
  Result := tls_read(FContext, @ABuffer[0], Length(ABuffer));
  Check('tls_read', Result);
end;

procedure TTls.Reset;
begin
  tls_reset(FContext);
end;

function TTls.Write(const ABuffer: TBytes): NativeInt;
begin
  Result := tls_write(FContext, @ABuffer[0], Length(ABuffer));
  Check('tls_write', Result);
end;

end.

