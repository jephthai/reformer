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

class Request
  def initialize(text)
    @raw = text
    @syms = {}
  end

  def set_token(token, sym)
    @syms[sym] = token
  end

  def generate(syms)
    # Start with a copy of the original request
    raw = @raw.clone

    # We need to insert the symbols provided for this request
    @syms.each do |k,v|
      raw.sub!(v, syms[k] ? syms[k] : "")
    end

    # We need to fix the Content-Length header since we may have
    # changed the length of the payload.  This will only work as
    # long as the payload does not consist of multiple lines.
    len = raw.split(/\n/)[-1].length
    raw.sub!(/^Content-Length: \d+/, "Content-Length: #{len}")

    # now we've finished generating the final request
    return raw.gsub(/\r/, "")
  end
end


