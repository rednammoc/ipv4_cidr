#!/usr/bin/perl -w

use strict;

use Parse::RecDescent;

if (@ARGV != 1) {
	print "Usage: $0 <address>\n";
	exit 1;
}

# $::RD_TRACE = 1;

my $grammar = q {
	# Start-up Actions
	{ 
		
		my $output;

		# Convert a binary number to a decimal number
		sub bin2dec {
        		unpack("N", pack("B32", substr("0" x 32 . shift, -32)));
		}

		# Unique array
		sub uniq {
			return keys %{{ map { $_ => 1 } @_ }};
		}

		# Expands Classless Inter-Domain Routing 
		sub expand_cidr {
			my($part_1, $part_2, $part_3, $part_4, $cidr) = @_; 
			
			# if no cidr is defined, we do not need to expand.
			if(defined($cidr)) {
				my $bin, my $value;
			
				# Initialize bin with remainder
				$bin = 8 - ($cidr % 8);
			
				# $_ is part where we need to add extra values according to cidr.
				for ((int($cidr / 8)+1) .. 4) {
	
					# Calculate dec values
					$value = (bin2dec('1' x $bin));
					$value = ($value == 255) ? $value = 254 : $value;	# 255 not allowed
	
					# Add expanded values to part_x
					push @{ eval('$part_' . $_) }, 0 .. $value;
	
					# After first run, bin will ever be 8.
					$bin = 8;
				}
			}
			return ($part_1, $part_2, $part_3, $part_4);
		}

		sub add_address {
			my($part_1, $part_2, $part_3, $part_4) = @_; 
			foreach my $item_1 ( @{$part_1} ) {
				foreach my $item_2 ( @{$part_2} ) {
					foreach my $item_3 ( @{$part_3} ) {
						foreach my $item_4 ( @{$part_4} ) {
							push @{$output}, $item_1 . '.' . $item_2 . '.' . $item_3 . '.' . $item_4;
						}
					}
				}
			}
		}

		# Print address
		sub print_addresses {
			# Unique and sort part
			@{$output} = sort {
				pack('C4' => $a =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/)
				cmp
				pack('C4' => $b =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/)
			} uniq(@{$output});
			foreach my $address (@{$output}) {
				print $address . "\n";
			}	
		}
	}
	# Start	
	start		:	address
			{
				print_addresses();
			}
	# Value between 0 and 255.
	octet		:	/(\d{1,3})/
			{ 
				if ($item[1] >= 0 and $item[1] < 255) {
					$return = $item[1];
				} else {
					undef
				}
			}
	range		:	octet '-' octet
			{
				# First part of range should be less equals second.
				if ($item[1] > $item[3]) {
					undef
				}
				# Transform range into sequence.
				$return = [ $item[1] .. $item[3] ]
			}
	# List cam contain comma-separated values and ranges.
	list		:	octet ','  list
			{
				$return = [ $item[1], @{$item[3]} ]
			}
			|	range ',' list
			{
				$return = [ @{$item[1]}, @{$item[3]} ]
			}
			# Ending with range.
			|	range
			{
				$return = $item[1]
			}
			# Ending with octett.
			|	octet
			{
				$return = [ $item[1] ] 
			}
	# Classless Inter-Domain Routing.
	cidr		:	'/' /(\d{1,2})/
			{
				if ($item[2] >= 0 and $item[2] <= 32) {
					$return = $item[2];
				} else {
					undef;
				}
			}
	# Following rules are used to access parts in address correctly.
	part_1		:	list
	part_2		:	list
	part_3		:	list
	part_4		:	list
	part_4_address	:	octet ',' address
			{
				$return = [ $item[1] ]
			}
			|	range ',' address
			{
				$return = $item[1]
			}
			|	octet ',' part_4_address
			{
				$return = [ $item[1] ]
			}
	# 
	address		:	part_1 '.' part_2 '.' part_3 '.' part_4 cidr ',' address
			{ 
				add_address(expand_cidr($item{part_1}, $item{part_2}, $item{part_3}, $item{part_4}, $item{cidr}));
			}
   			|	part_1 '.' part_2 '.' part_3 '.' part_4_address		
 			{
				add_address($item{part_1}, $item{part_2}, $item{part_3}, $item{part_4_address});
			}	
			|	part_1 '.' part_2 '.' part_3 '.' part_4 cidr /$/ 
			{
				add_address(expand_cidr($item{part_1}, $item{part_2}, $item{part_3}, $item{part_4}, $item{cidr}));
			}
			|	part_1 '.' part_2 '.' part_3 '.' part_4 /$/ 
			{
				add_address($item{part_1}, $item{part_2}, $item{part_3}, $item{part_4});
			}
};

my $parser = Parse::RecDescent->new($grammar);

$parser->start(shift);
