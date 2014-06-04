#!/usr/bin/env ruby 
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
#
# refproxy is a tool that allows the user to record HTTP requests to
# simplify the process of setting up a reformer attack.  The way this
# works is that you want to set up refproxy so that it listens on a
# local port and forwards HTTP requests to your target.  Each request
# will be printed to standard output.  You will want to grab the POST
# that you're interested and write it to a text file to use as the
# input request for reformer.
#
# Author:  Josh Stone
# Contact: josh@josho.org
# Date:    2010-07-30
#
#

require 'pathname'

require 'socket'
require File.dirname(Pathname.new(__FILE__).realpath) + '/client'
require 'rubygems'
require 'getopt/std'

class Proxy
  attr_accessor :reqs

  def initialize(target, port, host = nil)
    @target = target
    @port   = port
    @reqs   = []
    @host   = host
    @ssl    = false
    @lport  = 8080
  end

  def enableSSL
    @ssl = true
  end

  def setLPort(port)
    @lport = port
  end

  def fix_host(text)
    if text =~ /^(Host:\s*.*)$/
      header = $1
      if header =~ /Host:(\s*)([^:]+)/
        text.sub!(header, "Host: #{@host}")
      elsif header =~ /Host:(\s*)(.*):(.*)$/
        text.sub!(header, "Host: #{@host}:#{$3}")
      end
    else
      lines = text.split(/\n/)
      lines.insert(1, "Host: #{@host}")
      text = lines.join("\n")
    end
    return text
  end

  def run(&block)
    s = TCPServer.open(@lport)
    loop do
      c = s.accept
      text = ""
      len  = 0 

      # We read headers until we get to the blank line that indicates
      # that the content is coming.  Hopefully, along the way we find a
      # Content-Length: header so we know how much to read ;-).
      while true do
        line = c.readline
        text += line
        if line =~ /Content-Length: (\d+)/
          len = $1
        end
        break if line =~ /^\s*$/
      end

      text += c.read(len.to_i)

      text = fix_host text if @host

      break if yield(text)

      f = Client.new(@target, @port, text)
      f.enableSSL if @ssl
      resp = f.run(text[0..3] != "HEAD")
      c.write resp
      c.close
    end
  end
end

if $0 == __FILE__
  if ARGV.length < 2
    puts
    puts " usage: refproxy [options] <host> <port> [<header>]"
    puts
    puts "    <host>    DNS name or IP of target web server"
    puts "    <port>    Port of target web server"
    puts "    <header>  Value for setting Host: header in forwarded requests"
    puts
    puts "    -s        enable SSL for target"
    puts "    -p <port> local listen port (default 8080)"
    puts
    exit
  end

  options = Getopt::Std.getopts("sp:")

  p = Proxy.new(*ARGV)
  p.enableSSL if options.key? "s"
  p.setLPort(options["p"].to_i) if options.key? "p"

  p.run do |r|
    puts "-" * 72
    puts
    puts r
    puts
  end
end
