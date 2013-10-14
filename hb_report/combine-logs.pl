#!/usr/bin/perl
#
# combine-logs v1.0
#
# Copyright (c) 1999 Steven J. Madsen.  All rights reserved.
#
# Combines multiple syslog-format logs into a single chronological log.  Very
# handy for syslog report generators such as cksyslog.
#
# usage: combine-logs <log file> [...]
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
# Note by Dejan Muhamedagic <dejan@suse.de>
#
# This program was downloaded from
# http://www.moonglade.com/syslog/combine-logs-1.0.tar.gz
#

$debugging = 0;

# Open all of the logs.
$handle = "fh00";
foreach $file (@ARGV)
{
    $handle++;
    open $handle, $file || die "Could not open $file: $!\n";
    push @fh, $handle;
}

# Get the first line from each of the files.
$i = 0;
foreach $handle (@fh)
{
    $current_line[$i++] = get_next_line($handle);
}

# Process the logs.
while (1)
{
    $first = 0;
    for ($i = 1; $i < @fh; $i++)
    {
	if (first_entry($current_line[$first], $current_line[$i]))
	{
	    $first = $i;
	}
    }
    # Fall out if the entry isn't defined (no more entries to print).
    last if !defined($current_line[$first]);

    # Print the entry and get the next line from that log.
    print $current_line[$first];
    $current_line[$first] = get_next_line($fh[$first]);
}

# Gets the next line from the provided file handle.
sub get_next_line()
{
    my($handle) = @_;
    my($line);
    while ($line = <$handle>)
    {
	print " read $line" if $debugging;

	# Weed out useless "last message repeated" messages.
	next if $line =~ m/last message repeated \d+ times$/;
	
	# Fall out if the line passes the above tests.
	last;
    }
    return $line;
}

# Determines which syslog-style log entry comes first.  If $a comes first,
# the function returns 0.  If $b comes first, the function returns 1.
sub first_entry()
{
    my($a, $b) = @_;
    print "  \$a=$a  \$b=$b" if $debugging;
    return 0 if !defined($b);
    return 1 if !defined($a);

    my(%month) = (Jan => 0, Feb => 1, Mar => 2, Apr => 3, May => 4, Jun => 5,
		  Jul => 6, Aug => 7, Sep => 8, Oct => 9, Nov => 10, Dec => 11);
    my($a_month, $a_day, $a_hour, $a_minute, $a_second) =
      $a =~ /^(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s/;
    my($b_month, $b_day, $b_hour, $b_minute, $b_second) =
      $b =~ /^(\w+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s/;

    print "  a: $a_month $a_day $a_hour:$a_minute:$a_second\n" if $debugging;
    print "  b: $b_month $b_day $b_hour:$b_minute:$b_second\n" if $debugging;
    
    # Strictly speaking, Jan comes before Dec, but in the case that we are
    # comparing exactly those two, we consider Jan to come later.  In the
    # context of a log, this probably means a new year.
    return 0 if $a_month eq "Dec" && $b_month eq "Jan";
    return 1 if $a_month eq "Jan" && $b_month eq "Dec";
    
    # All other comparisons are as you'd expect.
    if ($a_month ne $b_month)
    {
	return $month{$a_month} > $month{$b_month};
    }
    if ($a_day ne $b_day)
    {
	return $a_day > $b_day;
    }
    if ($a_hour ne $b_hour)
    {
	return $a_hour > $b_hour;
    }
    if ($a_minute ne $b_minute)
    {
	return $a_minute > $b_minute;
    }
    if ($a_second ne $b_second)
    {
	return $a_second > $b_second;
    }
    
    # They have identical times, so just pick the first one.
    return 0;
}
