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

program ConsoleServer;

{$APPTYPE CONSOLE}
{$R *.res}

uses
  System.SysUtils,
  Winapi.Windows,
  Winapi.Winsock,
  Spring.Collections,
  LibreSsl.Interfaces,
  LibreSsl.Tls,
  LibreSsl.TlsConfig,
  Utils in 'Utils.pas';

procedure AcceptClient(const ATls: ITls);
const
  GreetingMsg = 'HELLO TLS CLIENT!'#10;
var
  S: string;
begin
  WriteUtf8String(ATls, GreetingMsg);
  Log('Read greeting: ' + ReadUtf8String(ATls));
  while True do
  begin
    S := ReadUtf8String(ATls);
    Log('Echoing: ' + S);
    WriteUtf8String(ATls, S);
  end;
end;

procedure Server;
const
  Protocols = 0;
var
  B: Integer;
  Ciphers: IList<string>;
  Client: sockaddr_in;
  ClientSize: Integer;
  Config: ITlsConfig;
  Opt: Integer;
  SC: TSocket;
  Server: sockaddr_in;
  Sock: TSocket;
  Tls: ITls;
begin
  Ciphers := TCollections.CreateList<string>;
  Ciphers.Add('ECDHE-ECDSA-AES256-GCM-SHA384');
  Ciphers.Add('ECDHE-ECDSA-AES256-SHA384');
  Ciphers.Add('ECDHE-RSA-AES256-GCM-SHA384');
  Ciphers.Add('ECDHE-RSA-AES256-SHA384');

  Sock := socket(AF_INET, SOCK_STREAM, 0);
  Config := TTlsConfig.Create as ITlsConfig;
  Config.SetProtocols(TTlsConfig.ParseProtocols('secure'));
  Config.SetCiphers(Intercalate(Ciphers, ':'));
  Config.SetKeyFile('key.pem');
  Config.SetCertFile('cert.pem');

  ZeroMemory(@Server, SizeOf(Server));
  Server.sin_addr.s_addr := inet_addr('127.0.0.1');
  Server.sin_port := htons(9000);
  Server.sin_family := AF_INET;

  Opt := 1;
  setsockopt(Sock, SOL_SOCKET, SO_REUSEADDR, @Opt, 4);
  B := bind(Sock, Server, SizeOf(Server));
  if B < 0 then
  begin
    raise Exception.Create('bind error');
  end;
  Log('bind');
  listen(Sock, 10);
  Log('listen');

  ClientSize := SizeOf(Client);
  while True do
  begin
    SC := accept(Sock, @Client, @ClientSize);
    if SC > 0 then
    begin
      Log('accept');
      Tls := TTls.Create(True, Config) as ITls;
      try
        AcceptClient(Tls.AcceptSocket(SC));
      except
        on E: ETlsError do
        begin
          LogFmt('Client disconnected: %s', [E.Message])
        end;
      end;
      shutdown(SC, 0);
      Log('shutdown');
      closesocket(SC);
      Log('closesocket');
    end;
  end;
end;

begin
  try
    Server;
  except
    on E: Exception do
    begin
      Writeln(E.ClassName, ': ', E.Message);
    end;
  end;
  WriteLn('Press enter to exit');
  ReadLn;

end.

