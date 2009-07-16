#!/usr/bin/perl

if(@ARGV != 2){
    die "usage: gen <func|define|string> <file>\n"
}
my $file = $ARGV[1];
my $ins = $ARGV[0];
if($ARGV[0] eq "func"){
    &func();
}elsif($ARGV[0] eq "define"){
    &define();
}elsif($ins eq "string"){
    &string();
}

sub string{
    open(FILE, $file);
    my $lines;
    while(<FILE>) {
	$_=~s/^\s+//;
	if($_!~/^[\n#\/]/){
	    $lines.=$_;
	}
    }
    close(FILE);
    my @methods = split(";",$lines);
    my $i = 0;
    print "char *lsm_security_str[] = {\n";
    foreach my $method(@methods){
	$method=~s/[\t]//g;
	$method=~s/[\n]//g;
	$method=~s/^[\s]+//g;
	$method=~/^(\w+) \(\*(.+)\)\s*\((.+)\)/;
	my $method_type = $1;
	my $method_name = $2;
	my $method_args = $3;
	if($method_name){
	    print "\t\"$method_name\",\n";
	    $i++;
	}
    }
    print "\t0};";
}



sub func{
open(FILE, $file);
my $lines;
while(<FILE>) {
    $_=~s/^\s+//;
    if($_!~/^[\n#\/]/){
	$lines.=$_;
    }
}
close(FILE);

    my @methods = split(";",$lines);
    foreach my $method(@methods){
	$method=~s/[\t\n]//g;
	$method=~/^(\w+) \(\*(.+)\)\s*\((.+)\)/;
	my $method_type = $1;
	my $method_name = $2;
	my $method_args = $3;
	if($method_name){
	    my @args = split(",", $method_args);
	    my $arg_num = $#args + 1;
	    my $func;
	    my $type;
   
	    if($method_type eq "int"){
		$type = "INT";
	    }elsif($method_type eq "void"){
		$type = "VOID";
	    }

	    if($method_args eq "void"){
		$func = "FUNC0$type(lsm_acc, $method_name, void";
	    }else{
		$func = "FUNC$arg_num"."$type(lsm_acc, $method_name";
		foreach my $arg(@args){
		    $arg=~/(.+[\s\*])([^\s\*]+)$/;
		    my $arg_type = $1;
		    my $arg_name = $2;
		    $arg_type =~ s/^\s//;
		    $arg_type =~ s/\s$//;
		    $func .= ", $arg_type, $arg_name";
		}
	    }
	    $func .= ");";
	    print "$func\n";
	}
    }
}

sub define{

open(FILE, $file);
my $lines;
while(<FILE>) {
#    $_=~s/^\s+//;
#    if($_!~/^[\n#\/]/){
	$lines.=$_;
#   }
}
close(FILE);
    my @methods = split(";",$lines);
    my $i = 0;
    foreach my $method(@methods){
	$method=~s/[\t]//g;
	$method=~s/[\n]//g;
	$method=~s/^[\s]+//g;
	$method=~/^(\w+) \(\*(.+)\)\s*\((.+)\)/;
	my $method_type = $1;
	my $method_name = $2;
	my $method_args = $3;
	if($method_name){
	    print "#define __KA_$method_name\t$i\n";
	    $i++;
	}else{
	    print "$method\n";
	}
    }
}

