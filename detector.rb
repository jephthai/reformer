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

# ------------------------------------------------------------------------
# The superclass Detector defines the basic interface for any
# detector.  A new detector has but to subclass this (or one of the
# other subclasses) and implement slight modifications.  This is an
# effective way of reducing the difficulty of extending reformer to
# perform other types of response analysis.
# ------------------------------------------------------------------------

class Detector
  def initialize
    # set up detector's database
    @hits = []
  end

  # When a request is "successful", this method marks it in the
  # detector's internal database for future reference.
  def mark(syms)
    @hits << syms
  end

  # The root detector doesn't process anything, so this is blank.  A
  # new detector should override this method.  The intent is that a
  # response is received and processed -- necessary actions (such as
  # displaying success or failure or updating an internal database)
  # should be accomplished here.
  def process(resp, syms)
  end

  # This is a generic means for displaying a result.  It basically
  # declares success or failure and lists the parameters provided for
  # the current authentication attempt.
  def display(status, syms)
    attempt = syms_to_s(syms)
    if status
      mark(syms)
      puts "\e[32;1m-> SUCCESS\t#{attempt}\e[0m"
    else
      puts "   failure\t#{attempt}"
    end
  end

  # It's ugly to reproduce this code elsewhere -- it makes a
  # human-readable string that presents the authentication parameters.
  def syms_to_s(syms)
    return syms.to_a.collect {|i| i.join(" = ")}.join(" \t")
  end

  # At the end of the attack, we may want to summarize the results.
  # This is responsible for processing and printing any summary.
  def summarize
    puts
    puts "Success obtained with these parameters:"
    puts "-" * 72
    @hits.each do |h|
      puts syms_to_s(h)
    end
    puts
  end
end

# ------------------------------------------------------------------------
# The RegDetector uses a regular expression to match against the HTTP
# response.  A successful match means a successful authentication.
# ------------------------------------------------------------------------

class RegDetector < Detector

  # When the detector is created, we want to receive and store the
  # regular expression that will determine success.
  def initialize(reg)
    @expr = reg
    super()
  end

  def test(txt)
    return txt =~ @expr
  end

  def process(resp, syms)
    if test(resp)
      display(true, syms)
      return true
    else
      display(false, syms)
      return false
    end
  end
end

# ------------------------------------------------------------------------
# NRegDetector is the inverse of the RegDetector.  It uses a regular
# expression which, if true, indicates a failed attempt to
# authenticate.
# ------------------------------------------------------------------------

class NRegDetector < RegDetector
  def test(txt)
    return txt !~ @expr
  end
end

# ------------------------------------------------------------------------
# This is a detector that records and displays the size of the HTTP
# response for each attempt.  This is not necessarily a clear
# indicator of successful authentication in all cases.  A user will
# have to do some manual analysis to determine whether success is
# indicated.
# ------------------------------------------------------------------------

class SizeDetector < Detector
  def initialize()
    printf("%16s %16s       Parameters\n", "header len", "content length")
    puts "-" * 72
    super()
  end
  
  # We can determine the content length from the Content-Length:
  # header in the response.  From this, we can determine both the
  # header and content length.
  def process(resp, syms)
    tlen = resp.length
    resp =~ /^Content-Length: (\d+)/
    clen = $1.to_i
    attrs = [tlen - clen, clen]
    display(attrs, syms)
    mark([clen, syms])
    return false
  end

  # For each result, we just put out the two sizes (header and
  # content).
  def display(status, syms)
    printf("%10s bytes %10s bytes\t%s\n", status[0], status[1], syms_to_s(syms))
  end

  # This is a substantial summarize() method -- it collects the
  # results and does a little processing on them to give the user a
  # little hint about where to look for potential success.
  def summarize
    lens = {}
    @hits.each do |h|
      (len, syms) = h
      lens[len] = 0 unless lens[len]
      lens[len] += 1
    end
    if lens.keys.length < 10
      puts
      puts "Summary of responses received"
      puts "-" * 72

      lens.to_a.sort! {|i,j| i[1] <=> j[1]}
      lens.each do |i|
        printf("%10d bytes -> %10d responses\n", i[0], i[1])
      end
    else
      puts 
      puts "Too many response lengths to summarize -- recommend manual analysis"
    end
    puts
  end
end
