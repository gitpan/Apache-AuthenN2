package Apache::AuthenN2;

use strict;
use Apache::Constants qw/:common/;
use vars qw/%ENV/;
use Authen::Smb;

$Apache::AuthenN2::VERSION = '0.01';
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

  # taint allowance
  $ENV{PATH}="/bin";

  # if this module is to be exposed to an unruly user base, it would
  # be safer to gather the nismatch output via an underprivileged child
  # instead of letting the shell get involved

  # construct nismatch command
  my $command = "/usr/bin/nismatch $name $passwd_table";

  # get passwd entry
  my $out = `$command`;
  if($?){
    $r->note_basic_auth_failure;
    $r->log_reason(
      "$self: user $name failed to authenticate in the $nt_domain, and is not in $passwd_table, either", $r->uri
    );
    return AUTH_REQUIRED;
  }

  # get password, group from password entry
  my($pwd, $group) = (split ":", $out)[1,3];
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

  # construct nismatch command
  my $command = "/usr/bin/nismatch $name $group_table";

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
      for my $group (@rest) {
        my $out = `$command`;
        next if $?;
        my($gname, $gid) = (split ":", $out)[0,2];
        return OK if $r->notes($name."Group") == $gid;
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

The nis+ part is pretty lame in that it simply executes
"/usr/bin/nismatch" with the appropriate arguments.  If exposed to an
unruly user base, that part should be rewritten to gather output from
an underprivileged child instead of letting the shell get involved.
An even better answer would probably be to hook into Net::NISPlus,
but I could not figure out how to do that in the few hours I had
available.

=head1 AUTHOR

valerie at savina dot com (Valerie Delane), based more or less on
code shamelessly lifted from Doug MacEachern's Apache::AuthNIS and
Micheal Parkers's Apache::AuthenSMB.

=head1 COPYRIGHT

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 SEE ALSO

mod_perl(3), Apache(3), nismatch(1)

=cut
