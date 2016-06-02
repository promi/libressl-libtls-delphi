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

unit Utils;

interface

uses
  System.SysUtils,
  Spring.Collections,
  LibreSsl.Interfaces;

function Intercalate(const AItems: IList<string>;
  const ADelimiter: string): string;
procedure Log(const AMsg: string);
procedure LogFmt(const AMsg: string; const AArgs: array of const);
function ReadUtf8String(const ATls: ITls): string;
procedure WriteUtf8String(const ATls: ITls; const S: string);

implementation

function ReadUtf8String(const ATls: ITls): string;
var
  Buffer: TBytes;
  Len: NativeInt;
begin
  SetLength(Buffer, 1000);
  Len := ATls.Read(Buffer);
  SetLength(Buffer, Len);
  if Len = 0 then
  begin
    raise ETlsError.Create('No more data');
  end;
  Result := TEncoding.UTF8.GetString(Buffer);
end;

procedure WriteUtf8String(const ATls: ITls; const S: string);
begin
  if S = '' then
  begin
    raise ETlsError.Create('No data to send');
  end;
  ATls.Write(TEncoding.UTF8.GetBytes(S));
end;

function Intercalate(const AItems: IList<string>;
  const ADelimiter: string): string;
var
  I: Integer;
begin
  Result := '';
  if AItems.Count <> 0 then
  begin
    Result := AItems[0];
    for I := 1 to AItems.Count - 1 do
    begin
      Result := Result + ADelimiter + AItems[I];
    end;
  end;
end;

procedure Log(const AMsg: string);
begin
  WriteLn(Trim(AMsg));
end;

procedure LogFmt(const AMsg: string; const AArgs: array of const);
begin
  Log(Format(AMsg, AArgs));
end;

end.

