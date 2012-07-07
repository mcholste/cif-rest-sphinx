#!/usr/bin/perl
package Web;
use Moose;
use base 'Plack::Component';
use Data::Dumper;
use Plack::Request;
use JSON -convert_blessed_universally;

has 'conf' => (is => 'rw', isa => 'HashRef', required => 1);
has 'cif' => (is => 'rw', isa => 'Object', required => 1);
has 'json' => (is => 'ro', isa => 'Object', required => 1, default => sub { return JSON->new->pretty->convert_blessed });

sub call {
	my ($self, $env) = @_;
    my $req = Plack::Request->new($env);
	my $res = $req->new_response(200);
	$res->content_type('application/javascript');
	$res->header('Access-Control-Allow-Origin' => '*');
	
	my ($index, $query, $apikey) = $req->request_uri =~ /(\w+)?\/([\w\.]+)(?:\?apikey=(.+))?$/;
	$index ||= 'all';
	my $body;
	if (not exists $self->conf->{apikeys} or (exists $self->conf->{apikeys}->{$apikey} and scalar (grep $index, @{ $self->conf->{apikeys}->{$apikey} }))){
		$body = $self->json->encode( $self->cif->query($index, $query) );
	}
	else {
		$res->code(401);
		$body = 'Unauthorized';
	}
		
	$res->body($body);
	$res->finalize();
}


package CIF;
use Moose;
use Data::Dumper;
use DBI qw(:sql_types);
use Socket qw(inet_aton);

our $Timeout = 10;
our $DefaultTimeOffset = 120;
our $Description = 'Run CIF via map/reduce';
sub description { return $Description }
our $Fields = { map { $_ => 1 } qw(srcip dstip site hostname) };

has 'conf' => (is => 'rw', isa => 'HashRef', required => 1);
has 'db' => (is => 'rw', isa => 'Object', required => 1);
has 'known_subnets' => (is => 'rw', isa => 'HashRef', required => 1, default => sub { {} });
has 'known_orgs' => (is => 'rw', isa => 'HashRef', required => 1, default => sub { {} });

sub BUILDARGS {
	my $class = shift;
	my %params = @_;
	
	if ($params{conf}->{known_subnets}){
		$params{known_subnets} = $params{conf}->{known_subnets};
	}
	
	$params{db} = DBI->connect($params{conf}->{dsn}, '', '', 
		{ 
			mysql_multi_statements => 1,
			mysql_bind_type_guessing => 1,
			mysql_auto_reconnect => 1,
		}) or die($DBI::errstr);
	
	return \%params;
}

sub query {
	my $self = shift;
	my ($index, $term) = @_;
	
	my ($query, $sth, @results);
	
	if (($index eq 'all' or $index eq 'infrastructure') and $term =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/){
		$query = 'SELECT * FROM infrastructure WHERE MATCH(?) AND subnet_start <= ? AND subnet_end >= ?';
		$sth = $self->db->prepare($query);
		next if $self->_check_local($term);
		my @arr = split(//, $term);
		my $prefix = join('', @arr[0..3]);
		my $ip_int = unpack('N*', inet_aton($term));
		$sth->bind_param(1, '@address ' . $prefix . '* @description -search @alternativeid -www.alexa.com');
		$sth->bind_param(2, $ip_int, SQL_INTEGER);
		$sth->bind_param(3, $ip_int, SQL_INTEGER);
		$sth->execute;
		while (my $row = $sth->fetchrow_hashref){
			push @results, $row;
		}
	}
	if ($index eq 'all' or $index eq 'url'){
		$query = 'SELECT * FROM url WHERE MATCH(?)';
		$sth = $self->db->prepare($query);		
		$sth->execute($term . ' -@description search');
		while (my $row = $sth->fetchrow_hashref){
			push @results, $row;
		}
	}
	if ($index eq 'all' or $index eq 'domain'){
		$query = 'SELECT * FROM domain WHERE MATCH(?)';
		$sth = $self->db->prepare($query);		
		$sth->execute($term . ' -@description search');
		while (my $row = $sth->fetchrow_hashref){
			push @results, $row;
		}
	}
	
	return \@results;
}

sub _check_local {
	my $self = shift;
	my $ip = shift;
	my $ip_int = unpack('N*', inet_aton($ip));
	
	return unless $ip_int and $self->known_subnets;
	
	foreach my $start (keys %{ $self->known_subnets }){
		if (unpack('N*', inet_aton($start)) <= $ip_int 
			and unpack('N*', inet_aton($self->known_subnets->{$start}->{end})) >= $ip_int){
			return 1;
		}
	}
}

package main;

use strict;
use Plack::Builder;
use Config::JSON;

my $config_file = '/etc/cif-rest-sphinx.conf';
if ($ENV{CONF}){
	$config_file = $ENV{CONF};
}
my $conf;
if (-f $config_file){
	$conf = new Config::JSON($config_file)->get() or die('Invalid config ' . $config_file);
}
else {
	$conf = { dsn => 'dbi:mysql:host=127.0.0.1;port=9306', known_subnets => { } };
}

return builder {
	$ENV{PATH_INFO} = $ENV{REQUEST_URI}; #mod_rewrite will mangle PATH_INFO, so we'll set this manually here in case it's being used
	mount '/favicon.ico' => sub { return [ 200, [ 'Content-Type' => 'text/plain' ], [ '' ] ]; };
	mount '/' => Web->new(conf => $conf, cif => CIF->new(conf => $conf) )->to_app;
};
