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

unit LibreSsl.TlsPeerCert;

interface

uses
  LibreSsl.Interfaces;

type
  TTlsPeerCert = class(TInterfacedObject, ITlsPeerCert)
  private
    FContext: Pointer;
  public
    constructor Create(const AContext: Pointer);
    function ContainsName(const AName: string): Boolean;
    function Hash: string;
    function Issuer: string;
    function NotAfter: TDateTime;
    function NotBefore: TDateTime;
    function Provided: Boolean;
    function Subject: string;
  end;

implementation

uses
  LibreSsl.TlsApi;

{ TTlsPeerCert }

constructor TTlsPeerCert.Create(const AContext: Pointer);
begin
  Assert(AContext <> nil);
  inherited Create;
  FContext := AContext;
end;

function TTlsPeerCert.ContainsName(const AName: string): Boolean;
begin
  Result := tls_peer_cert_contains_name(FContext,
    PAnsiChar(UTF8String(AName))) = 0;
end;

function TTlsPeerCert.Hash: string;
begin
  Result := string(UTF8String(tls_peer_cert_hash(FContext)));
end;

function TTlsPeerCert.Issuer: string;
begin
  Result := string(UTF8String(tls_peer_cert_issuer(FContext)));
end;

const
  UnixStartDate: TDateTime = 25569.0;

function UnixToDateTime(const UnixTime: NativeInt): TDateTime;
begin
  Result := (UnixTime / 86400) + UnixStartDate;
end;

function TTlsPeerCert.NotAfter: TDateTime;
begin
  Result := UnixToDateTime(tls_peer_cert_notafter(FContext));
end;

function TTlsPeerCert.NotBefore: TDateTime;
begin
  Result := UnixToDateTime(tls_peer_cert_notbefore(FContext));
end;

function TTlsPeerCert.Provided: Boolean;
begin
  Result := tls_peer_cert_provided(FContext) = 0;
end;

function TTlsPeerCert.Subject: string;
begin
  Result := string(UTF8String(tls_peer_cert_subject(FContext)));
end;

end.

