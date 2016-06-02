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

unit LibreSsl.TlsConfig;

interface

uses
  System.Classes,
  System.SysUtils,
  LibreSsl.Interfaces;

type
  TTlsConfig = class(TInterfacedObject, ITlsConfig)
  private
    FContext: Pointer;
  public
    constructor Create;
    destructor Destroy; override;
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
    class function ParseProtocols(const AProtoStr: string): UInt32; static;
  end;

implementation

uses
  LibreSsl.TlsApi;

{ TTlsConfig }

constructor TTlsConfig.Create;
begin
  inherited Create;
  FContext := tls_config_new;
  if FContext = nil then
  begin
    raise ETlsError.Create('Could not create tls_config_new context');
  end;
end;

destructor TTlsConfig.Destroy;
begin
  tls_config_free(FContext);
  inherited;
end;

function TTlsConfig.GetContext: Pointer;
begin
  Result := FContext;
end;

procedure TTlsConfig.ClearKeys;
begin
  tls_config_clear_keys(FContext);
end;

procedure TTlsConfig.InsecureNoverifycert;
begin
  tls_config_insecure_noverifycert(FContext);
end;

procedure TTlsConfig.InsecureNoverifyname;
begin
  tls_config_insecure_noverifyname(FContext);
end;

procedure TTlsConfig.InsecureNoverifytime;
begin
  tls_config_insecure_noverifytime(FContext);
end;

class function TTlsConfig.ParseProtocols(const AProtoStr: string): UInt32;
begin
  if tls_config_parse_protocols(Result, PAnsiChar(UTF8String(AProtoStr))) = -1
  then
  begin
    raise ETlsError.Create('Invalid protostr for tls_config_parse_protocols');
  end;
end;

procedure TTlsConfig.PreferCiphersClient;
begin
  tls_config_prefer_ciphers_client(FContext);
end;

procedure TTlsConfig.PreferCiphersServer;
begin
  tls_config_prefer_ciphers_server(FContext);
end;

procedure TTlsConfig.SetCaFile(const ACAFile: string);
begin
  if tls_config_set_ca_file(FContext, PAnsiChar(UTF8String(ACAFile))) = -1 then
  begin
    raise ETlsError.Create('Invalid ca_file for tls_config_set_ca_file');
  end;
end;

procedure TTlsConfig.SetCaMem(const ACA: TBytes);
begin
  if Length(ACA) = 0 then
  begin
    if tls_config_set_ca_mem(FContext, nil, 0) = -1 then
    begin
      raise ETlsError.Create('Invalid ca for tls_config_set_ca_mem');
    end;
  end
  else
  begin
    if tls_config_set_ca_mem(FContext, @ACA[0], Length(ACA)) = -1 then
    begin
      raise ETlsError.Create('Invalid ca for tls_config_set_ca_mem');
    end;
  end;
end;

procedure TTlsConfig.SetCaPath(const ACAPath: string);
begin
  if tls_config_set_ca_path(FContext, PAnsiChar(UTF8String(ACAPath))) = -1 then
  begin
    raise ETlsError.Create('Invalid ca_path for tls_config_set_ca_path');
  end;
end;

procedure TTlsConfig.SetCertFile(const ACertFile: string);
begin
  if tls_config_set_cert_file(FContext, PAnsiChar(UTF8String(ACertFile))) = -1
  then
  begin
    raise ETlsError.Create('Invalid cert_file for tls_config_set_cert_file');
  end;
end;

procedure TTlsConfig.SetCertMem(const ACert: TBytes);
begin
  if Length(ACert) = 0 then
  begin
    if tls_config_set_cert_mem(FContext, nil, 0) = -1 then
    begin
      raise ETlsError.Create('Invalid cert for tls_config_set_cert_mem');
    end;
  end
  else
  begin
    if tls_config_set_cert_mem(FContext, @ACert[0], Length(ACert)) = -1 then
    begin
      raise ETlsError.Create('Invalid cert for tls_config_set_cert_mem');
    end;
  end;
end;

procedure TTlsConfig.SetCertPath(const ACertPath: string);
begin
{
  if tls_config_set_cert_path(FContext, PAnsiChar(UTF8String(ACertPath))) = -1
  then
  begin
    raise ETlsError.Create('Invalid cert_path for tls_config_set_cert_path');
  end;
}
end;

procedure TTlsConfig.SetCiphers(const ACiphers: string);
begin
  if tls_config_set_ciphers(FContext, PAnsiChar(UTF8String(ACiphers))) = -1 then
  begin
    raise ETlsError.Create('Invalid ciphers for tls_config_set_ciphers');
  end;
end;

procedure TTlsConfig.SetDheparams(const AParams: string);
begin
  if tls_config_set_dheparams(FContext, PAnsiChar(UTF8String(AParams))) = -1
  then
  begin
    raise ETlsError.Create('Invalid params for tls_config_set_dheparams');
  end;
end;

procedure TTlsConfig.SetEcdhecurve(const AName: string);
begin
  if tls_config_set_ecdhecurve(FContext, PAnsiChar(UTF8String(AName))) = -1 then
  begin
    raise ETlsError.Create('Invalid name for tls_config_set_ecdhecurve');
  end;
end;

procedure TTlsConfig.SetKeyFile(const AKeyFile: string);
begin
  if tls_config_set_key_file(FContext, PAnsiChar(UTF8String(AKeyFile))) = -1
  then
  begin
    raise ETlsError.Create('Invalid key_file for tls_config_set_key_file');
  end;
end;

procedure TTlsConfig.SetKeyMem(const AKey: TBytes);
begin
  if Length(AKey) = 0 then
  begin
    if tls_config_set_key_mem(FContext, nil, 0) = -1 then
    begin
      raise ETlsError.Create('Invalid key for tls_config_set_key_mem');
    end;
  end
  else
  begin
    if tls_config_set_key_mem(FContext, @AKey[0], Length(AKey)) = -1 then
    begin
      raise ETlsError.Create('Invalid key for tls_config_set_key_mem');
    end;
  end;
end;

procedure TTlsConfig.SetProtocols(const AProtocols: UInt32);
begin
  tls_config_set_protocols(FContext, AProtocols);
end;

procedure TTlsConfig.SetVerifyDepth(const AVerifyDepth: Integer);
begin
  tls_config_set_verify_depth(FContext, AVerifyDepth);
end;

procedure TTlsConfig.Verify;
begin
  tls_config_verify(FContext);
end;

procedure TTlsConfig.VerifyClient;
begin
  tls_config_verify_client(FContext);
end;

procedure TTlsConfig.VerifyClientOptional;
begin
  tls_config_verify_client_optional(FContext);
end;

end.

