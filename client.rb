#
#    reFORMer, HTTP form brute forcer
#    Copyright (C) 2010 Josh Stone (josh@josho.org)
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program; if not, write to the Free Software Foundation, Inc.,
#    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Author:  Joshua Stone
# Contact: josh@josho.org
#

require 'socket'
require 'openssl'

# ------------------------------------------------------------------------
# Client is a class that supports sending and receiving an HTTP
# request.  It's a little complex just because we need to read the
# response headers to determine how much data will be sent by the
# server.  The input comes from the Request class, but it's just a
# plain-text raw HTTP request.
# ------------------------------------------------------------------------

class Client
  def initialize(host, port, request)
    @host = host
    @port = port
    @request = request
    @ssl = false
    @record = false
  end

  def enableSSL
    @ssl = true
  end

  def enableRecord(stream)
    @record = stream
  end

  def run(content = true)
    begin
      @sock = TCPSocket.open(@host, @port)
      @sock = setupSSL if @ssl
      @sock.print @request
      return http_resp(content)
    ensure 
      @sock.close
    end
  end

  # I added this method to resubmit the request without reopening the
  # socket.  This is (initially) to support the detection and handling
  # of a "100 Continue" response -- see the comments in http_resp()
  # below for more details.

  def rerun(content = true)
    @sock.print @request
    return http_resp(content)
  end

  def http_resp(fullread)
    text = ""
    len  = nil 

    # We read headers until we get to the blank line that indicates
    # that the content is coming.  Hopefully, along the way we find a
    # Content-Length: header so we know how much to read ;-).
    while true do
      line = @sock.readline
      text += line
      if line =~ /Content-Length: (\d+)/
        len = $1
      end
      break if line =~ /^\s*$/
    end

    # I keep running into applications that respond with a "100
    # Continue".  Reading the RFC, I'm not sure why they do this --
    # perhaps it is to frustrate brute force attacks.  So we can
    # identify these, when they happen, and resubmit the request so we
    # can get the "actual" response.
    if text =~ /100 Continue/
      @record.puts("Continue:\n\n#{text}\n") if @record
      return rerun(fullread)
    else
      if fullread
        if len
          content = @sock.read(len.to_i) 
        else
          # this can be slow, but some web servers don't specify
          # the content length!
          content = @sock.read
        end
        content = "" unless content
        text += content
      end
      
      @record.puts("RESPONSE:\n\n#{text}\n") if @record
      
      return text
    end
  end

  # We want to do some things to set up the SSL context for 
  # a socket.  We assume that the socket is already opened.
  def setupSSL
    ssl_context = OpenSSL::SSL::SSLContext.new()
    ssl_socket = OpenSSL::SSL::SSLSocket.new(@sock, ssl_context)
    ssl_socket.sync_close = true
    ssl_socket.connect
    return ssl_socket
  end
end

if $0 == __FILE__
  if ARGV.length != 2
    puts "  test: client.rb <host> <port>"
    exit
  end

  req = "GET / HTTP/1.0\nHost: #{ARGV[0]}\n\n"
  c = Client.new(ARGV[0], ARGV[1], req)
  c.enableSSL
  puts c.run
end
    
