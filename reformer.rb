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
# Author:  Joshua Stone
# Contact: josh@josho.org
#

require 'pathname'

require File.dirname(Pathname.new(__FILE__).realpath) + '/request'
require File.dirname(Pathname.new(__FILE__).realpath) + '/client'
require File.dirname(Pathname.new(__FILE__).realpath) + '/dictionary'
require File.dirname(Pathname.new(__FILE__).realpath) + '/detector'

require 'rubygems'
require 'getopt/std'

puts
puts "\e[34;1mreFORMer version 0.6, Copyright (C) 2014 Josh Stone (yakovdk@gmail.com)"
puts "reFORMer comes with ABSOLUTELY NO WARRANTY; it is licensed under the"
puts "GNU Public License (GPL), version 2\e[0m"
puts

if ARGV.length < 5
  puts "usage: reformer [options] <host> <port> <request> <symbols> <detector> [parameter]"
  puts
  puts "  <host>      Hostname or IP address of target system"
  puts "  <port>      TCP port hosting target web server"
  puts "  <request>   Text file containing raw HTTP request to send"
  puts "  <symbols>   Comma delimited text file containing symbol data"
  puts "  <detector>  Detector to use for identifying success"
  puts "  [parameter] Optional parameter for success detector"
  puts 
  puts "Options:"
  puts
  puts "  -s          enable SSL for HTTP connections"
  puts "  -r <file>   record requests and responses in <file>"
  puts "  -1          stop on first success resposne from detector"
  puts
  puts "Supported detectors:"
  puts 
  puts "  reg        Use Regular Expression success detector"
  puts "  nreg       Use Regular Expression failure detector"
  puts "  size       Use response size analyzer as success detector"
  puts
  puts "Symbol file format is as follows:"
  puts
  puts "  Line 1:  comma delimited symbol names (e.g., user,password)"
  puts "  Line 2:  comma delimited substitutions (e.g., %USER%,%PASS%)"
  puts "  Rest:    comma delimited values (e.g., admin,admin)"
  puts
  puts "Note that request file should have substitution symbols inserted"
  puts "where appropriate, so they can be replaced with the values from"
  puts "each row of the symbol file.  For example, the 'content' portion"
  puts "of the request file might look like this:"
  puts
  puts "  user=%USER%&pass=%PASS%&val=something"
  puts 
  puts "Note regarding dictionaries:"
  puts "If the dictionary file is named *.rb, then it will be processed"
  puts "as a Ruby program, evaluated in the context of the DynamicDictionary"
  puts "class.  This allows the user to create dynamic dictionaries in "
  puts "the event that you need something more elaborate than a static list."
  puts
  exit
end

options = Getopt::Std.getopts("sr:1")

$SSL = options.key? "s"
$RECORD = options.key?("r") ? open(options["r"], "w") : false
$BEGIN  = Time.now()
$EXITSUCCESS = options.key? "1"

($HOST, $PORT, $REQUEST, $SYMBOLS, $DET) = ARGV

if($SYMBOLS =~ /\.rb$/) 
  dict = DynamicDictionary.new($SYMBOLS)
else
  dict = Dictionary.new($SYMBOLS)
end

text = open($REQUEST).read
req = Request.new(text)
dict.get_map.each do |k,v|
  req.set_token(k, v)
end

# These are the supported detectors.  If a new one is added, it should
# be assigned a short name for the command line and a clause added
# here.  Note also that if there is any setup to be done for the
# detector, it should be accomplished here.

case $DET
when "reg"
  det = RegDetector.new(/#{ARGV[5]}/)
when "nreg"
  det = NRegDetector.new(/#{ARGV[5]}/)
when "size"
  det = SizeDetector.new()
else
  puts "ERROR: Unknown detector #{$DET}"
  exit
end

# For each row in the dictionary, we'll run a request and have the
# detector process the result.  This reasonably decouples the four
# main portions of the code (the request generation, the HTTP client,
# the dictionary, and the analysis of results).

dict.each do |m|
  r = req.generate(m)
  $RECORD.puts("#{Time.now() - $BEGIN} seconds\n\nREQUEST\n\n#{r}\n\n") if $RECORD
  c = Client.new($HOST, $PORT, r)
  c.enableSSL if $SSL
  c.enableRecord($RECORD) if $RECORD
  if det.process(c.run, m) and $EXITSUCCESS
    break
  end
  $RECORD.puts("-" * 72 + "\n\n") if $RECORD
end

# Each detector can optionally print out a result summary.  This way,
# if the detector can track valid authentications, it can summarize
# them at the end of the output.  Another opportunity, demonstrated in
# the "size" detector, is a summary table that does a quick tally of
# different response sizes.

det.summarize
puts
