package Apache::AuthenN2;

use strict;
use Apache::Constants qw/:common/;
use vars qw/%ENV/;
use Authen::Smb;
use Net::NISPlus::Table;

$Apache::AuthenN2::VERSION = '0.02';
my $self="Apache::AuthenN2";

sub handler {

  # get request object
  my $r = shift;

  # service only the first internal request
  return OK unless $r->is_initial_req;

  # get password user entered in browser
  my($res, $sent_pwd) = $r->get_basic_auth_pw;

  # decline if not basic
  return $res if $res;

  # get user name
  my $name = $r->connection->user;

  # be sure username is reasonable
  $name=~m/(\w+)/; $name=$1;

  # blank user name would cause problems
  unless($name){
    $r->note_basic_auth_failure;
    $r->log_reason("$self: no username supplied", $r->uri);
    return AUTH_REQUIRED;
  }

  # load apache config vars
  my $dir_config = $r->dir_config;   

  # try nt domain

  # what is the primary domain controller?
  my $nt_pdc = $r->dir_config('NT_PDC');
  unless($nt_pdc){
    $r->log_reason(
      "$self: configuration error - no NT_PDC", $r->uri
    );
  }

  # what is the backup domain controller?
  my $nt_bdc = $r->dir_config('NT_BDC');
  unless($nt_bdc){
    $r->log_reason(
      "$self: configuration error - no NT_BDC", $r->uri
    );
  }

  # how about the domain name?
  my $nt_domain = $r->dir_config('NT_Domain');
  unless($nt_domain){
    $r->log_reason(
      "$self: configuration error - no NT_Domain", $r->uri
    );
  }

  # call the domain controller
  my $auth_result = Authen::Smb::authen(
    $name, $sent_pwd, $nt_pdc, $nt_bdc, $nt_domain
  );

  if($auth_result == 0){
    # username/password match
    $r->push_handlers(PerlAuthzHandler => \&authz);
    return OK;
  }

  if($auth_result == 1){
    # obscure domain controller error
    $r->log_reason("$self: NT_SERVER_ERROR", $r->uri);
  }

  elsif($auth_result == 2){
    # more obscure domain controller error
    $r->log_reason("$self: NT_PROTOCOL_ERROR", $r->uri);
  }

  # ignore auth_result 3 because it just means the user failed to
  # supply the correct password, and we are going to fall through to
  # a nis+ attempt anyway

  # try nis+

  # get passwd table name
  my $passwd_table = $dir_config->get("NISPlus_Passwd_Table");

  # get user password entry
  my $pwd_table = Net::NISPlus::Table->new($passwd_table);
  unless ($pwd_table){
    $r->note_basic_auth_failure;
    $r->log_reason("$self: cannot get nis+ passwd table", $r->uri);
    return AUTH_REQUIRED;
  }
  my $pwd = "";
  my $group = "";
  foreach ($pwd_table->list()){
    if(@{$_}[0] eq $name){
      $pwd = @{$_}[1];
      $group = @{$_}[3];
      last;
    }
  }

  unless($pwd){
    $r->note_basic_auth_failure;
    $r->log_reason(
      "$self: user $name failed to authenticate in the $nt_domain, and is not in $passwd_table, either", $r->uri
    );
    return AUTH_REQUIRED;
  }

  #stash group id lookup for authorization check 
  $r->notes($name."Group", $group);
  unless(crypt($sent_pwd, $pwd) eq $pwd) {
    $r->note_basic_auth_failure;
    $r->log_reason(
      "$self: user $name failed to authenticate in the $nt_domain or $passwd_table", $r->uri
    );
    return AUTH_REQUIRED;
  }
  $r->push_handlers(PerlAuthzHandler => \&authz);
  return OK;
}

sub authz {
 
 # get request object
  my $r = shift;
  my $requires = $r->requires;
  return OK unless $requires;

  # get user name
  my $name = $r->connection->user;

  # get group table name
  my $dir_config = $r->dir_config;   
  my $group_table=$dir_config->get("NISPlus_Group_Table");

  for my $req (@$requires) {
    my($require, @rest) = split /\s+/, $req->{requirement};

    #ok if user is simply authenticated
    if($require eq "valid-user"){return OK}

    # ok if user is one of these users
    elsif($require eq "user") {return OK if grep $name eq $_, @rest}

    # ok if user is member of a required group. warning: this will fail 
    # if user is not in the nis+ domain, because there is no current
    # concept of nt domain groups in Authen::Smb
    elsif($require eq "group") {
      my $group_table = Net::NISPlus::Table->new($group_table);
      unless ($group_table){
        $r->note_basic_auth_failure;
        $r->log_reason("$self: cannot get nis+ group table", $r->uri);
        return AUTH_REQUIRED;
      }
      my %groups_to_gids;
      foreach ($group_table->list()){$groups_to_gids{@{$_}[0]} = @{$_}[2]}
      for my $group (@rest) {
        next unless exists $groups_to_gids{$group};
        return OK if $r->notes($name."Group") == $groups_to_gids{$group};
      }
    }
  }

  $r->note_basic_auth_failure;
  $r->log_reason(
    "$self: user $name not member of required group in $group_table", $r->uri
  );
  return AUTH_REQUIRED;

}

1;

__END__

=pod

=head1 NAME

Apache::AuthenN2 - Authenticate into the NT and NIS+ domains

=head1 SYNOPSIS

 #httpd.conf
 <Location>
   AuthName "your nt or nis+ account"
   AuthType Basic
   PerlSetVar NISPlus_Passwd_Table passwd.org_dir.yoyodyne.com
   PerlSetVar NISPlus_Group_Table group.org_dir.yoyodyne.com
   PerlSetVar NT_Domain domain_name
   PerlSetVar NT_PDC primary_server
   PerlSetVar NT_BDC backup_server
   PerlAuthenHandler Apache::AuthenN2
   require group eng
   require user john larry
 </Location>

=head1 DESCRIPTION

A quick fix to allow two otherwise incompatible populations in the
enterprise (windows users and unix users) authenticated access to
restricted applications offered via apache.

Authenticate to an nt domain; failing that, try a nis+ domain.

Note that this scheme is quite permissive.  Either a valid nt
username/password, or a valid nis+ username/password will allow
access.  This causes double exposure to poorly selected passwords.

The nt part requires the Authen::Smb module.  When Authen::Smb
supports group authentication, I will add it to this module.

The nis+ part requires the Net::NISPlus module.

=head1 AUTHOR

valerie at savina dot com (Valerie Delane), originally based more or
less on code shamelessly lifted from Doug MacEachern's
Apache::AuthNIS and Micheal Parkers's Apache::AuthenSMB.

=head1 COPYRIGHT

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

mod_perl(3), Apache(3)

=cut
