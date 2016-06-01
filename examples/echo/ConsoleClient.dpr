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

program ConsoleClient;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  LibreSsl.Interfaces in 'LibreSsl.Interfaces.pas',
  LibreSsl.Tls in 'LibreSsl.Tls.pas',
  LibreSsl.TlsApi in 'LibreSsl.TlsApi.pas',
  LibreSsl.TlsConfig in 'LibreSsl.TlsConfig.pas',
  LibreSsl.TlsPeerCert in 'LibreSsl.TlsPeerCert.pas';

function ReadUtf8String(const ATls: ITls): string;
var
  Buffer: TBytes;
  Len: NativeInt;
begin
  SetLength(Buffer, 1000);
  Len := ATls.Read(Buffer);
  SetLength(Buffer, Len);
  Result := TEncoding.UTF8.GetString(Buffer);
end;

procedure WriteUtf8String(const ATls: ITls; const S: string);
begin
  ATls.Write(TEncoding.UTF8.GetBytes(S));
end;

procedure Client;
const
  GreetingMsg = 'HELLO TLS SERVER!'#10;
var
  Config: ITLsConfig;
  Tls: ITLs;
  S: string;
begin
  Config := TTlsConfig.Create as ITlsConfig;
	Config.InsecureNoverifycert;
	Config.InsecureNoverifyname;

  Tls := TTls.Create(False, Config);
  Tls.Connect('localhost', '9000');
  WriteUtf8String(Tls, GreetingMsg);
  WriteLn(Trim(ReadUtf8String(Tls)));

  while True do
  begin
    ReadLn(S);
    WriteUtf8String(Tls, S);
    WriteLn(Trim(ReadUtf8String(Tls)));
  end;

  Tls.Close;
end;

begin
  try
    Client;
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

