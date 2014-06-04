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

require 'pp'

class Dictionary
  def initialize(file)
    @file   = open(file)
    @names  = @file.readline.split(/,/).collect {|i| i.chomp}
    @tokens = @file.readline.split(/,/).collect {|i| i.chomp}
  end

  def get_map
    map = {}
    @tokens.each_with_index do |t,i|
      map[t] = @names[i].to_sym
    end
    return map
  end

  def each(&block)
    @file.each_line do |line|
      fields = line.chomp.split(/,/).collect {|i| i.strip}

      # This creates a hash from the zipped names and row entries
      keys = @names.collect {|i| i.to_sym}
      map = Hash[*keys.zip(fields).flatten]
      yield(map)
    end
  end
end

#
# What is a DynamicDictionary?  It is an object that provides the
# same interface as a Dictionary, but the behavior can be 
# customized.  The need for this arose when I was doing an assessment
# where I had to go through some process to generate several 
# variables for each form POST.  I needed a new cookie, as well as
# some other interdependent form fields, otherwise the server would
# not accept the sumission.
#
# This gives you the ability to define your own dictionary provider
# with all the richness of Ruby.  There are only two things you
# need to do to make it work:
#
#  (1) Define @map as a hash mapping symbols to field names. 
#      Consider something like this:
#
#      @map = { "^USER^" => :user, "^PASS^" => :pass }
#
#  (2) Define the generate() function.  This must return a
#      hash representing all the needed values for a form 
#      submission, with names corresponding to the values
#      indicated in the @map value.  Something like this 
#      should work:
#
#      def generate
#        @done = true
#        return { :user => "admin", :pass => "Password1" }
#      end
# 
#      What is @done?  That tells Reformer that the dictionary
#      has been exhausted and it's time to tabulate results.
#      Obviously, a real generate() function would probably
#      keep some state and generate more than one password
#      before calling it quits.
# 
# The rest is up to you.
# 

class DynamicDictionary
  def initialize(file)
    @map = {}
    @count = 0
    @done = false
    self.instance_eval(open(file).read)
  end
  
  def get_map
    return @map
  end

  def each(&block) 
    @count += 1
    until @done
      map = generate
      yield(map)
    end
  end
end
