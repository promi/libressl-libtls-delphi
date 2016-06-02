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

unit LibreSsl.TlsApi;

interface

type
  TTlsReturnCode = Integer;

const
  TLS_API = 20141031;

  TLS_PROTOCOL_TLSv1_0 = 1 shl 1;
  TLS_PROTOCOL_TLSv1_1 = 1 shl 2;
  TLS_PROTOCOL_TLSv1_2 = 1 shl 3;
  TLS_PROTOCOL_TLSv1 = TLS_PROTOCOL_TLSv1_0 or TLS_PROTOCOL_TLSv1_1 or
    TLS_PROTOCOL_TLSv1_2;

  TLS_PROTOCOLS_ALL = TLS_PROTOCOL_TLSv1;
  TLS_PROTOCOLS_DEFAULT = TLS_PROTOCOL_TLSv1_2;

  TLS_WANT_POLLIN = -2;
  TLS_WANT_POLLOUT = -3;

function tls_error(const ctx: Pointer): PAnsiChar; cdecl;

function tls_config_new: Pointer; cdecl;
procedure tls_config_free(const config: Pointer); cdecl;

function tls_config_set_ca_file(const config: Pointer; const ca_file: PAnsiChar)
  : TTlsReturnCode; cdecl;
function tls_config_set_ca_path(const config: Pointer; const ca_path: PAnsiChar)
  : TTlsReturnCode; cdecl;
function tls_config_set_ca_mem(const config: Pointer; const ca: PByte;
  const len: NativeUInt): TTlsReturnCode; cdecl;
function tls_config_set_cert_file(const config: Pointer;
  const cert_file: PAnsiChar): TTlsReturnCode; cdecl;
function tls_config_set_cert_mem(const config: Pointer; const cert: PByte;
  const len: NativeUInt): TTlsReturnCode; cdecl;
function tls_config_set_ciphers(const config: Pointer; const ciphers: PAnsiChar)
  : TTlsReturnCode; cdecl;
function tls_config_set_dheparams(const config: Pointer;
  const params: PAnsiChar): TTlsReturnCode; cdecl;
function tls_config_set_ecdhecurve(const config: Pointer; const name: PAnsiChar)
  : TTlsReturnCode; cdecl;
function tls_config_set_key_file(const config: Pointer;
  const key_file: PAnsiChar): TTlsReturnCode; cdecl;
function tls_config_set_key_mem(const config: Pointer; const key: PByte;
  const len: NativeUInt): TTlsReturnCode; cdecl;
procedure tls_config_set_protocols(const config: Pointer;
  const protocols: UInt32); cdecl;
procedure tls_config_set_verify_depth(const config: Pointer;
  const verify_depth: Integer); cdecl;

procedure tls_config_prefer_ciphers_client(const config: Pointer); cdecl;
procedure tls_config_prefer_ciphers_server(const config: Pointer); cdecl;

procedure tls_config_insecure_noverifycert(const config: Pointer); cdecl;
procedure tls_config_insecure_noverifyname(const config: Pointer); cdecl;
procedure tls_config_insecure_noverifytime(const config: Pointer); cdecl;
procedure tls_config_verify(const config: Pointer); cdecl;

procedure tls_config_verify_client(const config: Pointer); cdecl;
procedure tls_config_verify_client_optional(const config: Pointer); cdecl;

procedure tls_config_clear_keys(const config: Pointer); cdecl;
function tls_config_parse_protocols(out protocols: UInt32;
  const protostr: PAnsiChar): TTlsReturnCode; cdecl;

function tls_client: Pointer; cdecl;
function tls_server: Pointer; cdecl;
function tls_configure(const ctx, config: Pointer): TTlsReturnCode; cdecl;
procedure tls_reset(const ctx: Pointer); cdecl;
procedure tls_free(const ctx: Pointer); cdecl;

function tls_accept_fds(const ctx: Pointer; out cctx: Pointer;
  const fd_read: Integer; const fd_write: Integer): TTlsReturnCode; cdecl;
function tls_accept_socket(const ctx: Pointer; out cctx: Pointer;
  const socket: Integer): TTlsReturnCode; cdecl;
function tls_connect(const ctx: Pointer; const host: PAnsiChar;
  const port: PAnsiChar): TTlsReturnCode; cdecl;
function tls_connect_fds(const ctx: Pointer; const fd_read, fd_write: Integer;
  const servername: PAnsiChar): TTlsReturnCode; cdecl;
function tls_connect_servername(const ctx: Pointer;
  const host, port, servername: PAnsiChar): TTlsReturnCode; cdecl;
function tls_connect_socket(const ctx: Pointer; const s: Integer;
  const servername: PAnsiChar): TTlsReturnCode; cdecl;
function tls_handshake(const ctx: Pointer): TTlsReturnCode; cdecl;
function tls_read(const ctx: Pointer; const buf: PByte;
  const buflen: NativeUInt): NativeInt; cdecl;
function tls_write(const ctx: Pointer; const buf: PByte;
  const buflen: NativeUInt): NativeInt; cdecl;
function tls_close(const ctx: Pointer): TTlsReturnCode; cdecl;

function tls_peer_cert_provided(const ctx: Pointer): TTlsReturnCode; cdecl;
function tls_peer_cert_contains_name(const ctx: Pointer; const name: PAnsiChar)
  : TTlsReturnCode; cdecl;

function tls_peer_cert_hash(const ctx: Pointer): PAnsiChar; cdecl;
function tls_peer_cert_issuer(const ctx: Pointer): PAnsiChar; cdecl;
function tls_peer_cert_subject(const ctx: Pointer): PAnsiChar; cdecl;
function tls_peer_cert_notbefore(const ctx: Pointer): Int64; cdecl;
function tls_peer_cert_notafter(const ctx: Pointer): Int64; cdecl;

function tls_conn_version(const ctx: Pointer): PAnsiChar; cdecl;
function tls_conn_cipher(const ctx: Pointer): PAnsiChar; cdecl;

function tls_load_file(const &file: PAnsiChar; out len: NativeUInt;
  const password: PAnsiChar): PByte; cdecl;

implementation

const
  libname = 'libtls-10.dll';

function tls_init: TTlsReturnCode; cdecl; external libname;

function tls_error(const ctx: Pointer): PAnsiChar; cdecl; external libname;

function tls_config_new: Pointer; cdecl; external libname;
procedure tls_config_free(const config: Pointer); cdecl; external libname;

function tls_config_set_ca_file(const config: Pointer; const ca_file: PAnsiChar)
  : TTlsReturnCode; cdecl; external libname;
function tls_config_set_ca_path(const config: Pointer; const ca_path: PAnsiChar)
  : TTlsReturnCode; cdecl; external libname;
function tls_config_set_ca_mem(const config: Pointer; const ca: PByte;
  const len: NativeUInt): TTlsReturnCode; cdecl; external libname;
function tls_config_set_cert_file(const config: Pointer;
  const cert_file: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_config_set_cert_path(const config: Pointer;
  const cert_path: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_config_set_cert_mem(const config: Pointer; const cert: PByte;
  const len: NativeUInt): TTlsReturnCode; cdecl; external libname;
function tls_config_set_ciphers(const config: Pointer; const ciphers: PAnsiChar)
  : TTlsReturnCode; cdecl; external libname;
function tls_config_set_dheparams(const config: Pointer;
  const params: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_config_set_ecdhecurve(const config: Pointer; const name: PAnsiChar)
  : TTlsReturnCode; cdecl; external libname;
function tls_config_set_key_file(const config: Pointer;
  const key_file: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_config_set_key_mem(const config: Pointer; const key: PByte;
  const len: NativeUInt): TTlsReturnCode; cdecl; external libname;
procedure tls_config_set_protocols(const config: Pointer;
  const protocols: UInt32); cdecl; external libname;
procedure tls_config_set_verify_depth(const config: Pointer;
  const verify_depth: Integer); cdecl; external libname;

procedure tls_config_prefer_ciphers_client(const config: Pointer); cdecl;
  external libname;
procedure tls_config_prefer_ciphers_server(const config: Pointer); cdecl;
  external libname;

procedure tls_config_insecure_noverifycert(const config: Pointer); cdecl;
  external libname;
procedure tls_config_insecure_noverifyname(const config: Pointer); cdecl;
  external libname;
procedure tls_config_insecure_noverifytime(const config: Pointer); cdecl;
  external libname;
procedure tls_config_verify(const config: Pointer); cdecl; external libname;

procedure tls_config_verify_client(const config: Pointer); cdecl;
  external libname;
procedure tls_config_verify_client_optional(const config: Pointer); cdecl;
  external libname;

procedure tls_config_clear_keys(const config: Pointer); cdecl; external libname;
function tls_config_parse_protocols(out protocols: UInt32;
  const protostr: PAnsiChar): TTlsReturnCode; cdecl; external libname;

function tls_client: Pointer; cdecl; external libname;
function tls_server: Pointer; cdecl; external libname;
function tls_configure(const ctx, config: Pointer): TTlsReturnCode; cdecl;
  external libname;
procedure tls_reset(const ctx: Pointer); cdecl; external libname;
procedure tls_free(const ctx: Pointer); cdecl; external libname;

function tls_accept_fds(const ctx: Pointer; out cctx: Pointer;
  const fd_read: Integer; const fd_write: Integer): TTlsReturnCode; cdecl;
  external libname;
function tls_accept_socket(const ctx: Pointer; out cctx: Pointer;
  const socket: Integer): TTlsReturnCode; cdecl; external libname;
function tls_connect(const ctx: Pointer; const host: PAnsiChar;
  const port: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_connect_fds(const ctx: Pointer; const fd_read, fd_write: Integer;
  const servername: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_connect_servername(const ctx: Pointer;
  const host, port, servername: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_connect_socket(const ctx: Pointer; const s: Integer;
  const servername: PAnsiChar): TTlsReturnCode; cdecl; external libname;
function tls_handshake(const ctx: Pointer): TTlsReturnCode; cdecl;
  external libname;
function tls_read(const ctx: Pointer; const buf: PByte;
  const buflen: NativeUInt): NativeInt; cdecl; external libname;
function tls_write(const ctx: Pointer; const buf: PByte;
  const buflen: NativeUInt): NativeInt; cdecl; external libname;
function tls_close(const ctx: Pointer): TTlsReturnCode; cdecl; external libname;

function tls_peer_cert_provided(const ctx: Pointer): TTlsReturnCode; cdecl;
  external libname;
function tls_peer_cert_contains_name(const ctx: Pointer; const name: PAnsiChar)
  : TTlsReturnCode; cdecl; external libname;

function tls_peer_cert_hash(const ctx: Pointer): PAnsiChar; cdecl;
  external libname;
function tls_peer_cert_issuer(const ctx: Pointer): PAnsiChar; cdecl;
  external libname;
function tls_peer_cert_subject(const ctx: Pointer): PAnsiChar; cdecl;
  external libname;
function tls_peer_cert_notbefore(const ctx: Pointer): Int64; cdecl;
  external libname;
function tls_peer_cert_notafter(const ctx: Pointer): Int64; cdecl;
  external libname;

function tls_conn_version(const ctx: Pointer): PAnsiChar; cdecl;
  external libname;
function tls_conn_cipher(const ctx: Pointer): PAnsiChar; cdecl;
  external libname;

function tls_load_file(const &file: PAnsiChar; out len: NativeUInt;
  const password: PAnsiChar): PByte; cdecl; external libname;

initialization

tls_init;

end.

