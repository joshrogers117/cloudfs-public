#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run concurrently on the host and disposable VM. Bundled macOS Perl only.
# All writes are confined to a fresh run directory in the approved fixture.
# See --plan for the sequence. This does not remount, clear caches, or sign in.
use strict;
use warnings;
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use IO::Socket::UNIX;
use IO::Handle;
use IPC::Open3;
use Symbol qw(gensym);
use Getopt::Long qw(GetOptions);
use Cwd qw(abs_path);
use POSIX qw(WNOHANG);
use Fcntl qw(S_ISREG);
use Time::HiRes qw(time sleep);

$| = 1;
my ($role, $root, $helper, $run_id, $plan, $self_test, $host_mount, $host_control_socket, $diagnose_replace_gap, $gateway_url);
my $timeout = 120;
GetOptions('role=s'=>\$role, 'root=s'=>\$root, 'helper=s'=>\$helper,
    'run-id=s'=>\$run_id, 'timeout=i'=>\$timeout, 'plan'=>\$plan,
    'self-test'=>\$self_test, 'host-mount=s'=>\$host_mount,
    'host-control-socket=s'=>\$host_control_socket, 'gateway-url=s'=>\$gateway_url,
    'diagnose-posix-replace-gap'=>\$diagnose_replace_gap) or die "Invalid options\n";
die "Unexpected positional arguments\n" if @ARGV;
$gateway_url //= $ENV{CLOUDFS_TEST_GATEWAY_URL};
die "Guest role requires --gateway-url or CLOUDFS_TEST_GATEWAY_URL (HTTPS origin only)\n"
    if ($role // '') eq 'guest' && (!defined($gateway_url) || $gateway_url !~ m{^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/?$});
$gateway_url =~ s{/$}{} if defined $gateway_url;
diagnostic_scope($role, $diagnose_replace_gap);
my $diagnostic_active = $diagnose_replace_gap ? 1 : 0;
my %replace_gap = (missingOpenCount=>0, firstMissingAtEpochSeconds=>undef,
    lastMissingAtEpochSeconds=>undef, maxObservedGapMs=>0);
my $gap_started;
my $json = JSON::PP->new->canonical;
my $home = $ENV{HOME} // die "HOME is required\n";
my $mount = "$home/cloudfs/edit1";
my $control_socket = "$home/Library/Application Support/cloudfs/d.sock";
my $isolation_base = isolation_scope($role, $host_mount, $host_control_socket);
if (defined $isolation_base) { $mount=$host_mount; $control_socket=$host_control_socket; }
my $approved_root = "$mount/cloudfs-editor-validation-20261015";
$root //= $approved_root;
my @checks;
my %children;
my $run;
my $role_claimed = 0;
my $started = time;
my $limitation = 'Apple SMB rejects POSIX fcntl range locks with ENOTSUP before contacting the server. '
    . 'Apple ByteRangeLockPB2 supports exclusive ranges only; shared-range coexistence is untested by this kernel harness. '
    . 'Exclusive probes use read-only descriptors, avoiding the conservative whole-inode publication lease of writable opens. '
    . 'Disjoint writable opens, stream-specific locks and shared flock semantics are not claimed.';
my $replace_limitation = 'Opt-in POSIX replacement diagnostic permits only target OPEN ENOENT and measures its sampled gap. '
    . 'Complete old/new contents and a validated guest completion marker remain required. Strict atomicity is not established, even if no gap is observed.';

sub emit { print $json->encode($_[0]), "\n"; }
sub check {
    my ($name, $status, $details) = @_;
    push @checks, {name=>$name, status=>$status, details=>$details};
    emit({event=>'check', role=>$role, %{$checks[-1]}});
    die "Check failed: $name\n" if $status eq 'fail';
}

# Classification is deliberately independent of the helper's --expect exit code.
# An open error must never become a successful byte-range-lock assertion.
sub classify {
    my ($result, $expected, $permit_conservative_limit) = @_;
    return 'fail' unless ref($result) eq 'HASH';
    my $phase = $result->{phase} // '';
    return 'limited' if $expected eq 'unsupported' && $phase eq 'unsupported'
        && ($result->{api} // '') eq 'fcntl' && ($result->{errno} // 0) == 45 && !$result->{acquired};
    return 'limited' if $permit_conservative_limit && $phase eq 'open_failed'
        && ($result->{errno} // 0) =~ /^(?:13|16|35)$/; # EACCES, EBUSY, EAGAIN (Darwin)
    return 'pass' if $expected eq 'acquired' && $phase eq 'probed' && $result->{acquired};
    return 'pass' if $expected eq 'blocked' && $phase eq 'blocked' && !$result->{acquired};
    return 'limited' if $permit_conservative_limit && $expected eq 'acquired'
        && $phase eq 'blocked' && !$result->{acquired};
    return 'fail';
}

sub decode_marker {
    my ($bytes, $expected_run) = @_;
    return (undef, {state=>'empty', bytes=>0}) unless length $bytes;
    my $value = eval { $json->decode($bytes) };
    return (undef, {state=>'invalid_json', bytes=>length($bytes)}) unless ref($value) eq 'HASH';
    return (undef, {state=>'wrong_run_id', bytes=>length($bytes)}) unless ($value->{runId} // '') eq $expected_run;
    return ($value, {state=>'ready', bytes=>length($bytes)});
}

sub diagnostic_scope {
    my ($which, $enabled) = @_;
    die "POSIX replacement diagnostic option is host-only\n" if $enabled && ($which // '') ne 'host';
}
sub observation_config {
    return {mode=>$diagnostic_active ? 'diagnose-posix-replace-gap' : 'strict',
        strictAtomicityRequired=>$diagnostic_active ? JSON::PP::false : JSON::PP::true,
        observationTimeoutSeconds=>$diagnostic_active ? 180 : $timeout};
}
sub completion_marker_valid {
    my ($value, $expected_run) = @_;
    return ref($value) eq 'HASH' && ($value->{runId} // '') eq $expected_run
        && ($value->{role} // '') eq 'guest';
}
sub classify_replace_read {
    my ($observed, $old_hash, $new_hash, $old_bytes, $new_bytes, $allow_gap) = @_;
    return 'fail' unless ref($observed) eq 'HASH';
    return 'gap' if $allow_gap && ($observed->{phase} // '') eq 'open_failed'
        && defined($observed->{errno}) && "$observed->{errno}" eq '2';
    return 'fail' unless ($observed->{phase} // '') eq 'read_complete' && defined($observed->{bytes});
    return 'old' if ($observed->{sha256} // '') eq $old_hash && $observed->{bytes} == $old_bytes;
    return 'new' if ($observed->{sha256} // '') eq $new_hash && $observed->{bytes} == $new_bytes;
    return 'fail';
}
sub observe_missing_open {
    my ($stats, $start_ref, $at) = @_;
    ++$stats->{missingOpenCount};
    $stats->{firstMissingAtEpochSeconds} //= $at;
    $stats->{lastMissingAtEpochSeconds} = $at;
    $$start_ref //= $at;
    close_observed_gap($stats, $start_ref, $at, 0);
}
sub close_observed_gap {
    my ($stats, $start_ref, $at, $finished) = @_;
    return unless defined $$start_ref;
    my $elapsed = int(($at-$$start_ref)*1000 + .5);
    $stats->{maxObservedGapMs} = $elapsed if $elapsed > $stats->{maxObservedGapMs};
    undef $$start_ref if $finished;
}

# Loop deadlines alone cannot bound a blocked SMB stat/read. Used outside
# RPC/wait_for, which manage their own alarms. A nested eval cannot hide expiry.
sub bounded_io {
    my ($deadline, $phase, $operation) = @_;
    my $remaining = $deadline - time;
    die "$phase timed out\n" unless $remaining > 0;
    my ($result, $error, $expired);
    {
        local $SIG{ALRM} = sub { $expired=1; die "$phase timed out\n"; };
        Time::HiRes::alarm($remaining);
        $result = eval { $operation->() };
        $error = $@;
        Time::HiRes::alarm(0);
    }
    die "$phase timed out\n" if $expired || time >= $deadline;
    die $error if length($error);
    return $result;
}

sub idle_storage_sample {
    my ($previous, $current) = @_;
    return ref($current) eq 'HASH' && defined($current->{requests})
        && "$current->{requests}" =~ /^[0-9]+$/ && defined($current->{activeRequests})
        && $current->{activeRequests} == 0 && defined($previous)
        && $current->{requests} == $previous;
}

# Pure lexical checks run even for --plan. Actual filesystem/socket checks run
# only before a live invocation, so self-tests never contact a daemon or mount.
sub isolation_scope {
    my ($which, $at, $socket) = @_;
    return undef unless defined($at) || defined($socket);
    die "Both isolated host options are required\n" unless defined($at) && defined($socket);
    die "Isolated overrides are host-only\n" unless ($which // '') eq 'host';
    die "Isolated mount must use a unique canonical private temporary directory\n"
        unless $at =~ m{\A(/private/tmp/cloudfs-collaboration-[A-Za-z0-9][A-Za-z0-9_-]{5,63})/mount\z};
    my $base=$1;
    die "Isolated socket must share the exact private mount directory\n"
        unless $socket eq "$base/control.sock" || $socket eq "$base/d.sock";
    return $base;
}
sub status_matches_mount {
    my ($status, $expected) = @_;
    return ref($status) eq 'HASH' && ($status->{filespace} // '') eq 'edit1'
        && ($status->{mountPath} // '') eq $expected && ($status->{connection} // '') eq 'connected';
}
sub terminal_peer_report_valid {
    my ($report, $expected_run, $expected_role) = @_;
    return 0 unless ref($report) eq 'HASH' && ($report->{runId} // '') eq $expected_run
        && ($report->{role} // '') eq $expected_role
        && ($report->{result} // '') =~ /\A(?:PASS|PASS_WITH_LIMITATIONS)\z/
        && !defined($report->{error}) && ref($report->{checks}) eq 'ARRAY' && @{$report->{checks}};
    for my $entry (@{$report->{checks}}) {
        return 0 unless ref($entry) eq 'HASH' && !ref($entry->{name}) && length($entry->{name} // '')
            && ($entry->{status} // '') =~ /\A(?:pass|limited)\z/;
    }
    return 1;
}
sub validate_isolated_filesystem {
    return unless defined $isolation_base;
    my @parent=lstat($isolation_base);
    die "Isolated parent must be a private directory owned by this user\n"
        unless @parent && -d $isolation_base && !-l $isolation_base && $parent[4] == $>
        && ($parent[2] & 0077) == 0 && (abs_path($isolation_base) // '') eq $isolation_base;
    die "Isolated mount must be a canonical directory without symlinks\n"
        unless -d $mount && !-l $mount && (abs_path($mount) // '') eq $mount;
    my @socket=lstat($control_socket);
    die "Isolated control socket must be private, canonical and owned by this user\n"
        unless @socket && -S $control_socket && !-l $control_socket && $socket[4] == $>
        && ($socket[2] & 0077) == 0 && (abs_path($control_socket) // '') eq $control_socket;
}
sub target_scope {
    return {mode=>defined($isolation_base) ? 'isolated-signed-release-daemon' : 'standard-app-daemon',
        mountPath=>$mount, controlSocket=>$control_socket,
        installedNativeAppRestorationVerified=>JSON::PP::false,
        (defined($isolation_base) ? (signatureVerification=>'Required separately by launch orchestration; not inferred from socket status') : ())};
}

if ($self_test) {
    my @cases = (
        ['POSIX SMB limitation explicit', {phase=>'unsupported', api=>'fcntl', errno=>45, acquired=>0}, 'unsupported', 0, 'limited'],
        ['wrong API unsupported fails', {phase=>'unsupported', api=>'smbfs', errno=>45, acquired=>0}, 'unsupported', 0, 'fail'],
        ['unsupported is not lock denial', {phase=>'unsupported', api=>'fcntl', errno=>45, acquired=>0}, 'blocked', 1, 'fail'],
        ['actual acquired', {phase=>'probed', acquired=>1}, 'acquired', 0, 'pass'],
        ['actual denied', {phase=>'blocked', acquired=>0}, 'blocked', 0, 'pass'],
        ['open denied never a lock pass', {phase=>'open_failed', errno=>13}, 'blocked', 1, 'limited'],
        ['open denied without a holder fails', {phase=>'open_failed', errno=>13}, 'acquired', 0, 'fail'],
        ['missing file fails', {phase=>'open_failed', errno=>2}, 'blocked', 1, 'fail'],
        ['unexpected lock error fails', {phase=>'lock_failed', errno=>5}, 'blocked', 1, 'fail'],
        ['overlap unexpectedly acquired fails', {phase=>'probed', acquired=>1}, 'blocked', 1, 'fail'],
        ['conservative disjoint denial limited', {phase=>'blocked', acquired=>0}, 'acquired', 1, 'limited'],
        ['nonconservative disjoint denial fails', {phase=>'blocked', acquired=>0}, 'acquired', 0, 'fail'],
        ['missing output fails', undef, 'blocked', 1, 'fail'],
    );
    for (@cases) { die "Classification failure: $_->[0]\n" unless classify($_->[1], $_->[2], $_->[3]) eq $_->[4]; }
    my @markers = (['', 'empty'], ['{', 'invalid_json'], ['[]', 'invalid_json'],
        ['{}', 'wrong_run_id'], ['{"runId":"different"}', 'wrong_run_id'], ['{"runId":"test"}', 'ready']);
    for (@markers) { my (undef, $diagnostic) = decode_marker($_->[0], 'test'); die "Marker classification failure\n" unless $diagnostic->{state} eq $_->[1]; }
    my $extra=0;
    die "Bounded operation lost result\n" unless bounded_io(time+1,'test',sub {42})==42; ++$extra;
    eval { bounded_io(time+1,'test',sub {die "original failure\n"}) };
    die "Bounded operation swallowed error\n" unless $@ =~ /original failure/; ++$extra;
    my $called=0; eval { bounded_io(time-1,'test',sub {$called=1}) };
    die "Expired operation ran\n" unless $@ =~ /timed out/ && !$called; ++$extra;
    eval { bounded_io(time+.02,'test',sub {eval {sleep .2}; return 'incorrect pass'}) };
    die "Nested eval swallowed timeout\n" unless $@ =~ /timed out/; ++$extra;
    die "Active prefetch counted as idle\n" if idle_storage_sample(7,{requests=>7,activeRequests=>1}); ++$extra;
    die "New object request counted as stable\n" if idle_storage_sample(7,{requests=>8,activeRequests=>0}); ++$extra;
    die "Missing request telemetry accepted\n" if idle_storage_sample(7,{activeRequests=>0}); ++$extra;
    die "Idle object counter rejected\n" unless idle_storage_sample(7,{requests=>7,activeRequests=>0}); ++$extra;
    my $base='/private/tmp/cloudfs-collaboration-ABC123';
    die "Default path behavior changed\n" if defined isolation_scope('guest',undef,undef); ++$extra;
    for my $socket ("$base/control.sock", "$base/d.sock") {
        die "Valid isolation pair rejected\n" unless isolation_scope('host',"$base/mount",$socket) eq $base; ++$extra;
    }
    my @invalid_isolation=(
        ['guest',"$base/mount","$base/control.sock"], [undef,"$base/mount","$base/control.sock"],
        ['host',"$base/mount",undef], ['host',undef,"$base/control.sock"],
        ['host','/tmp/cloudfs-collaboration-ABC123/mount',"$base/control.sock"],
        ['host','/private/tmp/cloudfs-collaboration-x/mount','/private/tmp/cloudfs-collaboration-x/d.sock'],
        ['host',"$base/../mount","$base/control.sock"], ['host',"$base/mount/","$base/control.sock"],
        ['host',"$base/mount",'/private/tmp/cloudfs-collaboration-OTHER1/d.sock'],
        ['host',"$base/mount","$base/../control.sock"],
        ['host',"$base/mount","$home/Library/Application Support/cloudfs/d.sock"],
        ['host',"$home/cloudfs/edit1","$base/d.sock"]);
    for (@invalid_isolation) { eval { isolation_scope(@$_) }; die "Unsafe isolation pair accepted\n" unless $@; ++$extra; }
    my $mounted={filespace=>'edit1',connection=>'connected',mountPath=>"$base/mount"};
    die "Exact status rejected\n" unless status_matches_mount($mounted,"$base/mount"); ++$extra;
    for my $bad ({%$mounted,filespace=>'other'}, {%$mounted,connection=>'disconnected'},
        {%$mounted,mountPath=>"$home/cloudfs/edit1"}, {}, []) {
        die "Mismatched daemon status accepted\n" if status_matches_mount($bad,"$base/mount"); ++$extra;
    }
    my $peer={runId=>'test',role=>'guest',result=>'PASS',error=>undef,checks=>[{name=>'checksum',status=>'pass'}]};
    die "Valid terminal peer rejected\n" unless terminal_peer_report_valid($peer,'test','guest'); ++$extra;
    die "Explicit limited peer rejected\n" unless terminal_peer_report_valid({%$peer,result=>'PASS_WITH_LIMITATIONS',checks=>[{name=>'API unavailable',status=>'limited'}]},'test','guest'); ++$extra;
    for my $bad ({%$peer,result=>'FAIL'}, {%$peer,result=>'RUNNING'}, {%$peer,role=>'host'},
        {%$peer,runId=>'old'}, {%$peer,error=>'late failure'}, {%$peer,checks=>[]}, {%$peer,checks=>{}},
        {%$peer,checks=>[{name=>'checksum',status=>'fail'}]}, {%$peer,checks=>[{name=>'checksum',status=>'unknown'}]},
        {%$peer,checks=>[{status=>'pass'}]}, {}, []) {
        die "Failed/malformed terminal peer accepted\n" if terminal_peer_report_valid($bad,'test','guest'); ++$extra;
    }
    diagnostic_scope('host',1); ++$extra;
    diagnostic_scope('guest',0); ++$extra;
    for my $wrong ('guest', undef) { eval { diagnostic_scope($wrong,1) }; die "Nonhost diagnostic option accepted\n" unless $@; ++$extra; }
    my @replace_cases=(
        [{phase=>'open_failed',errno=>2},1,'gap'], [{phase=>'open_failed',errno=>2},0,'fail'],
        [{phase=>'open_failed',errno=>5},1,'fail'], [{phase=>'read_failed',errno=>2},1,'fail'],
        [{phase=>'close_failed',errno=>2},1,'fail'], [{phase=>'open_failed',error=>'No such file'},1,'fail'],
        [{phase=>'read_complete',bytes=>3,sha256=>'old'},1,'old'],
        [{phase=>'read_complete',bytes=>5,sha256=>'new'},1,'new'],
        [{phase=>'read_complete',bytes=>2,sha256=>'old'},1,'fail'],
        [{phase=>'read_complete',bytes=>6,sha256=>'new'},1,'fail'],
        [{phase=>'read_complete',bytes=>5,sha256=>'wrong'},1,'fail'],
        [{phase=>'read_complete',bytes=>0,sha256=>'new'},1,'fail'], [undef,1,'fail']);
    for (@replace_cases) {
        die "Replacement read classification failure\n" unless classify_replace_read($_->[0],'old','new',3,5,$_->[1]) eq $_->[2]; ++$extra;
    }
    die "Valid guest completion rejected\n" unless completion_marker_valid({runId=>'test',role=>'guest'},'test'); ++$extra;
    for my $bad ({runId=>'other',role=>'guest'}, {runId=>'test',role=>'host'}, {runId=>'test'}, {}, []) {
        die "Unvalidated completion accepted\n" if completion_marker_valid($bad,'test'); ++$extra;
    }
    my %samples=(missingOpenCount=>0,maxObservedGapMs=>0); my $sample_start;
    observe_missing_open(\%samples,\$sample_start,10);
    observe_missing_open(\%samples,\$sample_start,10.25);
    close_observed_gap(\%samples,\$sample_start,10.5,1);
    die "Missing-open sample interval incorrect\n" unless $samples{missingOpenCount}==2
        && $samples{firstMissingAtEpochSeconds}==10 && $samples{lastMissingAtEpochSeconds}==10.25
        && $samples{maxObservedGapMs}==500 && !defined($sample_start); ++$extra;
    observe_missing_open(\%samples,\$sample_start,12);
    close_observed_gap(\%samples,\$sample_start,12.1,1);
    die "Missing-open maximum interval lost\n" unless $samples{missingOpenCount}==3
        && $samples{firstMissingAtEpochSeconds}==10 && $samples{lastMissingAtEpochSeconds}==12
        && $samples{maxObservedGapMs}==500; ++$extra;
    emit({result=>'PASS', scope=>'pure classification/deadline self-test; no filesystem or network operations', checks=>scalar(@cases)+scalar(@markers)+$extra});
    exit 0;
}

my @sequence = (
    'Read daemon status and require an already mounted, synchronized Edit 1 on both Macs.',
    'Host creates a unique run directory, deterministic data and old atomic-replace target; guest verifies hashes.',
    'Each Mac records the POSIX fcntl ENOTSUP limitation; shared range coexistence is not claimed.',
    'Host holds an exclusive Apple BRL range on a read-only descriptor; guest must fail an overlapping exclusive range and acquire a disjoint range.',
    'Host releases; guest reacquires and holds exclusive while host must fail overlap and acquire disjoint.',
    'Guest releases its holder; host must reacquire the formerly locked range.',
    'Guest rewrites the previously read data; host waits for the expected checksum without remounting or clearing its cache.',
    $diagnostic_active
        ? 'Host diagnostic observes POSIX replacement: only OPEN ENOENT is limited; every successful read must be complete old/new bytes and a valid guest done marker plus new bytes must appear within 180 seconds. Strict atomicity is not claimed.'
        : 'Guest atomically replaces a file while host repeatedly opens/reads it; every read must be the complete old or complete new bytes.',
    'Guest uses its existing token through curl stdin for one permitted read and six read-only admin API denial probes.',
    'Both roles save JSON reports. Host combines them into summary.json and reports explicit limitations.'
);
if ($plan) {
    emit({scope=>'host + disposable macOS VM', root=>$root, sequence=>\@sequence,
        target=>target_scope(), observationConfig=>observation_config(),
        ($diagnostic_active?(strictAtomicity=>JSON::PP::false):()),
        limitations=>[$limitation, ($diagnostic_active?$replace_limitation:()), 'No open-unlinked handle survival, blocking F_SETLKW fairness, hard links, remount, app-update or UI assertion is made.'],
        mutations=>'Only a new multi-mac-RUN_ID directory under the approved fixture. Daemon flush is filespace-wide; both clients must begin in sync.'});
    exit 0;
}
die "Use --role host|guest --helper /absolute/helper --run-id UNIQUE_ID [--gateway-url https://gateway.example.invalid] [--timeout 120]\n"
    unless defined($role) && $role =~ /^(?:host|guest)$/ && defined($run_id)
    && $run_id =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/ && defined($helper)
    && $helper =~ m{^/} && -f $helper && -x $helper && $timeout >= 30 && $timeout <= 600;
die "Only $approved_root is approved\n" unless $root eq $approved_root;
validate_isolated_filesystem();
die "Approved fixture must already exist and must not be a symlink\n"
    unless -d $root && !-l $root && (abs_path($root) // '') eq $root;
$run = "$root/multi-mac-$run_id";
$SIG{ALRM} = sub { die "Operation timed out\n" };
$SIG{TERM} = $SIG{INT} = sub { die "Interrupted\n" };

sub read_file {
    my ($path) = @_;
    open my $f, '<:raw', $path or die "Read $path: $!\n";
    local $/; my $bytes = <$f>; close $f or die "Close $path: $!\n";
    return $bytes // '';
}
sub read_replace_target {
    my ($path, $max_bytes) = @_;
    my $f;
    if (!open($f, '<:raw', $path)) {
        my $number=0+$!; # capture the actual OPEN errno before any other operation
        return {phase=>'open_failed',errno=>$number};
    }
    my $hash=Digest::SHA->new(256); my $bytes=0;
    for (;;) {
        my $count=sysread($f,my $chunk,65536);
        die "POSIX replacement read failed (errno ".(0+$!).")\n" unless defined $count;
        last unless $count;
        $bytes+=$count;
        die "POSIX replacement read exceeds both complete expected lengths\n" if $bytes>$max_bytes;
        $hash->add($chunk);
    }
    close($f) or die "POSIX replacement close failed (errno ".(0+$!).")\n";
    return {phase=>'read_complete',bytes=>$bytes,sha256=>$hash->hexdigest};
}
sub write_file {
    my ($path, $bytes) = @_;
    die "Write escaped run directory\n" unless index($path, "$run/") == 0 && $path !~ m{(?:^|/)\.\.(?:/|$)};
    die "Refusing symlink destination\n" if -l $path;
    open my $f, '>:raw', $path or die "Write $path: $!\n";
    print $f $bytes or die "Write contents: $!\n";
    $f->sync or die "fsync $path: $!\n";
    close $f or die "Close $path: $!\n";
}
sub rpc {
    my ($method, $params) = @_;
    alarm($timeout + 5);
    my $s = IO::Socket::UNIX->new(Peer=>$control_socket)
        or die "Connect to local daemon: $!\n";
    print $s $json->encode({jsonrpc=>'2.0', id=>1, method=>$method,
        params=>$params // {filespace=>'edit1'}}), "\n" or die "RPC write: $!\n";
    my $line = <$s>; close $s; alarm(0);
    die "Daemon closed RPC\n" unless defined $line;
    my $reply = $json->decode($line);
    die "Daemon $method failed (code ".($reply->{error}{code} // 'unknown').")\n" if $reply->{error};
    return $reply->{result};
}
sub flush {
    rpc('flush', {filespace=>'edit1', path=>'/', wait=>JSON::PP::true, timeoutMs=>$timeout * 1000});
}
sub save_json {
    my ($name, $value) = @_;
    my $dest = "$run/$name.json";
    my $tmp = "$dest.tmp-$role-$$";
    write_file($tmp, $json->encode($value)."\n");
    rename($tmp, $dest) or die "Publish $name: $!\n";
    flush();
}
sub marker { save_json($_[0], {runId=>$run_id, role=>$role, at=>time, %{$_[1] // {}}}); }
sub peer_failed {
    my $peer = $role eq 'host' ? 'guest' : 'host';
    my $path = "$run/$peer.report.json";
    if (-f $path) {
        my $report = eval { $json->decode(read_file($path)) };
        die "Peer reported failure; inspect $peer.report.json\n" if $report && $report->{result} eq 'FAIL';
    }
}
sub wait_for {
    my ($name) = @_;
    my $began = time;
    my $until = $began + $timeout;
    my $last = {state=>'not_yet_checked'};
    my ($last_state, $last_emitted) = ('', 0);
    my $expired = 0;
    my $fail_timeout = sub { die "Timed out waiting for $name; last observation: ".$json->encode($last)."\n" };
    emit({event=>'marker_wait_started', role=>$role, marker=>$name, timeoutSeconds=>$timeout});
    local $SIG{ALRM} = sub { $expired=1; $fail_timeout->(); };
    alarm($timeout + 1); # also bound a stuck stat/read, not just the polling sleeps
    while (time < $until) {
        peer_failed();
        $fail_timeout->() if $expired; # a peer read must not swallow the alarm
        my $path = "$run/$name.json";
        my @info = stat($path);
        if (!@info) {
            my ($number, $message) = (0+$!, "$!");
            $last = {state=>$number == 2 ? 'absent' : 'stat_failed', errno=>$number, error=>$message};
        } elsif (!S_ISREG($info[2])) {
            $last = {state=>'not_regular_file'};
        } else {
            $last = {state=>'read_in_progress', statBytes=>$info[7]};
            my $bytes = eval { read_file($path) };
            $fail_timeout->() if $expired;
            if (defined $bytes) {
                my ($value, $diagnostic) = decode_marker($bytes, $run_id);
                $last = {%$diagnostic, statBytes=>$info[7]};
                if ($value) {
                    alarm(0);
                    emit({event=>'marker_observed', role=>$role, marker=>$name,
                        elapsedMs=>int((time-$began)*1000), %$last});
                    return $value;
                }
            } else {
                my $error = $@; $error =~ s/[\r\n]+/ /g;
                $last = {state=>'read_failed', statBytes=>$info[7], error=>substr($error,0,240)};
            }
        }
        if ($last->{state} ne $last_state || time-$last_emitted >= 10) {
            emit({event=>'marker_waiting', role=>$role, marker=>$name,
                elapsedMs=>int((time-$began)*1000), %$last});
            $last_state=$last->{state}; $last_emitted=time;
        }
        sleep 0.2;
    }
    alarm(0);
    $fail_timeout->();
}
sub hash_file { return sha256_hex(read_file($_[0])); }
sub wait_hash {
    my ($path, $expected) = @_;
    my $began = time;
    my $until = $began + $timeout;
    while (time < $until) {
        bounded_io($until, 'Waiting for remote checksum', sub {peer_failed()});
        my $hash = eval { bounded_io($until, 'Reading remote checksum', sub {hash_file($path)}) };
        return int((time - $began) * 1000) if defined($hash) && $hash eq $expected;
        sleep 0.1;
    }
    die "Timed out waiting for expected checksum of $path\n";
}
sub helper_result {
    my ($path) = @_;
    my @lines = split /\n/, read_file($path);
    return @lines ? eval { $json->decode($lines[-1]) } : undef;
}
sub start_helper {
    my ($name, @args) = @_;
    my $out = "$run/$role.$name.helper.jsonl";
    my $err = "$run/$role.$name.helper.stderr";
    my $pid = fork(); die "fork: $!\n" unless defined $pid;
    if (!$pid) {
        open STDOUT, '>:raw', $out or POSIX::_exit(126);
        open STDERR, '>:raw', $err or POSIX::_exit(126);
        exec {$helper} $helper, @args or POSIX::_exit(127);
    }
    $children{$pid} = {name=>$name, out=>$out};
    return $pid;
}
sub finish_helper {
    my ($pid) = @_;
    my $until = time + $timeout;
    while (time < $until) {
        my $done = waitpid($pid, WNOHANG);
        if ($done == $pid) {
            my $exit = $?;
            my $info = delete $children{$pid};
            return {exit=>($exit >> 8), signal=>($exit & 127),
                result=>bounded_io($until, 'Reading helper result', sub {helper_result($info->{out})})};
        }
        die "Helper process disappeared\n" if $done == -1;
        sleep 0.05;
    }
    die "Helper timed out\n";
}
sub probe {
    my ($name, $mode, $offset, $expected, $limited) = @_;
    my $pid = start_helper($name, 'probe', "$run/ranges.bin", $mode, $offset, 4096, '--expect', $expected, '--api', 'smbfs', '--open', 'read');
    my $result = finish_helper($pid);
    my $status = classify($result->{result}, $expected, $limited);
    $status = 'fail' if $result->{signal} || $result->{exit} != 0
        || ($result->{result}{api} // '') ne 'smbfs' || ($result->{result}{openMode} // '') ne 'read';
    check($name, $status, $result);
    return $result;
}
sub posix_limitation {
    my $pid = start_helper('posix-api-limitation', 'probe', "$run/ranges.bin", 'shared', 0, 4096,
        '--api', 'fcntl', '--open', 'read', '--expect', 'unsupported');
    my $result = finish_helper($pid);
    my $status = classify($result->{result}, 'unsupported', 0);
    $status = 'fail' if $result->{signal} || $result->{exit} != 0;
    check('Apple SMB POSIX shared-range API unavailable; shared coexistence not claimed', $status, $result);
}
sub acquire_after_release {
    my ($name, $mode) = @_;
    my $began = time;
    my @attempts;
    while (time - $began < $timeout) {
        my $pid = start_helper("$name-".scalar(@attempts), 'probe', "$run/ranges.bin", $mode, 0, 4096, '--expect', 'acquired', '--api', 'smbfs', '--open', 'read');
        my $result = finish_helper($pid); push @attempts, $result;
        if (!$result->{signal} && !$result->{exit} && ($result->{result}{api} // '') eq 'smbfs'
            && ($result->{result}{openMode} // '') eq 'read' && classify($result->{result}, 'acquired', 0) eq 'pass') {
            check($name, 'pass', {elapsedMs=>int((time-$began)*1000), attempts=>\@attempts});
            return;
        }
        bounded_io($began+$timeout, 'Waiting for released lock', sub {peer_failed()}); sleep 0.25;
    }
    check($name, 'fail', {attempts=>\@attempts});
}
sub holder {
    my ($name, $mode) = @_;
    my $ready = "$run/$role.$name.ready";
    my $release = "$run/$role.$name.release";
    my $pid = start_helper($name, 'hold', "$run/ranges.bin", $mode, 0, 4096,
        '--seconds', $timeout * 3, '--ready', $ready, '--release', $release, '--api', 'smbfs', '--open', 'read');
    my $until = time + $timeout;
    while (time < $until) {
        if (bounded_io($until, 'Waiting for holder', sub {-f $ready})) {
            my $bytes = bounded_io($until, 'Reading holder readiness', sub {read_file($ready)});
            my $value = eval {$json->decode($bytes)};
            if ($value && $value->{phase} eq 'held' && ($value->{api} // '') eq 'smbfs'
                && ($value->{openMode} // '') eq 'read' && ($value->{mode} // '') eq 'exclusive') {
                check("$name acquired", 'pass', $value);
                return {pid=>$pid, release=>$release, ready=>$ready};
            }
        }
        if (waitpid($pid, WNOHANG) == $pid) {
            my $info = delete $children{$pid};
            check("$name acquired", 'fail', bounded_io($until, 'Reading failed holder', sub {helper_result($info->{out})}));
        }
        bounded_io($until, 'Waiting for holder peer', sub {peer_failed()}); sleep 0.1;
    }
    die "Holder failed to become ready\n";
}
sub release_holder {
    my ($holder, $name) = @_;
    write_file($holder->{release}, "release\n");
    my $result = finish_helper($holder->{pid});
    check($name, (($result->{exit} == 0 && !$result->{signal}
        && ($result->{result}{phase} // '') eq 'released') ? 'pass' : 'fail'), $result);
}
sub api_status {
    my ($path, $token) = @_;
    my ($in, $out); my $err = gensym;
    my $pid = open3($in, $out, $err, '/usr/bin/curl', '-sS', '--max-time', '30',
        '--proto', '=https', '--config', '-', '-o', '/dev/null', '-w', '%{http_code}',
        "$gateway_url$path");
    print $in qq(header = "Authorization: Bearer $token"\n); close $in;
    local $/; my $status = <$out> // ''; my $ignored_error = <$err>; waitpid($pid, 0);
    return {httpStatus=>$status =~ /^\d{3}$/ ? 0+$status : 0, curlExit=>($? >> 8)};
}
sub admin_probes {
    my $token = read_file("$home/Library/Application Support/cloudfs/token.txt");
    $token =~ s/[\r\n]+$//;
    die "Invalid credential shape (contents withheld)\n" unless $token =~ /^[A-Za-z0-9._~-]{20,8192}$/;
    my $allowed = api_status('/v1/filespaces/edit1/items/root', $token);
    check('guest credential permits normal metadata read', $allowed->{httpStatus} == 200 && !$allowed->{curlExit} ? 'pass' : 'fail', $allowed);
    for my $path ('/v1/filespaces/edit1/schedules', '/v1/filespaces/edit1/grants',
        '/v1/filespaces/edit1/audit', '/v1/orgs/example-org/storage-credentials',
        '/v1/orgs/example-org/auth-config', '/v1/orgs/example-org/email-config') {
        my $response = api_status($path, $token);
        check("nonadmin GET denied $path", $response->{httpStatus} == 403 && !$response->{curlExit} ? 'pass' : 'fail', $response);
    }
    undef $token;
}
sub role_report {
    my ($result, $error) = @_;
    $result = 'PASS_WITH_LIMITATIONS' if $result eq 'PASS' && ($diagnostic_active || grep {$_->{status} eq 'limited'} @checks);
    close_observed_gap(\%replace_gap,\$gap_started,time,0) if $diagnostic_active && $role eq 'host';
    return {runId=>$run_id, role=>$role, result=>$result, checks=>\@checks,
        target=>target_scope(), observationConfig=>observation_config(),
        ($diagnostic_active ? (strictAtomicity=>JSON::PP::false,
            ($role eq 'host' ? (posixReplaceGap=>{%replace_gap}) : ())) : ()),
        error=>$error, elapsedMs=>int((time-$started)*1000), limitations=>[$limitation,($diagnostic_active?$replace_limitation:())],
        scope=>'Two mounted clients; per-open checksums and exclusive Apple SMB ByteRangeLockPB2 tests on read-only descriptors. No shared-range, remount/update, retained-open-inode or blocking-waiter claim.'};
}

sub settled_storage {
    my ($phase) = @_;
    my $until=time+$timeout;
    my ($previous,$stable_since);
    while (time<$until) {
        my $storage=rpc('status')->{storage};
        die "Object-request telemetry unavailable during $phase\n" unless ref($storage) eq 'HASH'
            && defined($storage->{requests}) && "$storage->{requests}" =~ /^[0-9]+$/
            && defined($storage->{activeRequests});
        die "Object-request counter reset during $phase\n" if defined($previous) && $storage->{requests}<$previous;
        if (idle_storage_sample($previous,$storage)) {
            $stable_since//=time;
            return $storage if time-$stable_since>=2;
        } else { undef $stable_since; }
        $previous=$storage->{requests}; sleep .2;
    }
    die "Object requests did not settle during $phase\n";
}

my $success = eval {
    my $status = rpc('status');
    die "Expected connected Edit 1 at the exact selected mount\n" unless status_matches_mount($status,$mount);
    my $sync = rpc('sync.state', {filespace=>'edit1', path=>'/'});
    die "Pre-existing writes are pending; finish them before running this fixture\n"
        unless $sync->{inSync} && !$sync->{pendingUploads} && !$sync->{pendingBytes};
    open my $mounts, '-|', '/sbin/mount' or die "Read mount inventory: $!\n";
    my @mount_lines = <$mounts>; close $mounts;
    die "Expected an SMB filesystem at $mount\n" unless grep { / on \Q$mount\E \(smbfs[,)]/ } @mount_lines;
    check('preflight connected SMB mount has no pending writes', 'pass', {mountPath=>$mount});

    if ($role eq 'host') {
        die "Run directory already exists; choose a fresh --run-id\n" if -e $run || -l $run;
        mkdir($run, 0700) or die "Create run directory: $!\n";
        $role_claimed = 1;
        write_file("$run/ranges.bin", join('', map {chr($_)} 0..255) x 64);
        my $payload = "host-initial-$run_id\0" x 65536;
        my $old_atomic = "old-atomic-$run_id\n" x 2048;
        write_file("$run/payload.bin", $payload);
        write_file("$run/atomic.bin", $old_atomic);
        marker('host.ready', {initialHash=>sha256_hex($payload), oldAtomicHash=>sha256_hex($old_atomic),
            observationConfig=>observation_config()});
        wait_for('guest.ready');
        check('host warms payload before remote overwrite', hash_file("$run/payload.bin") eq sha256_hex($payload) ? 'pass' : 'fail');
        posix_limitation();
        my $hold = holder('exclusive', 'exclusive'); marker('host.exclusive');
        wait_for('guest.host-lock.probes');
        release_holder($hold, 'host exclusive BRL holder released'); marker('host.exclusive.released');
        wait_for('guest.exclusive');
        probe('remote exclusive BRL denies overlapping exclusive', 'exclusive', 0, 'blocked', 0);
        probe('exclusive BRL disjoint from remote exclusive acquires', 'exclusive', 8192, 'acquired', 0);
        marker('host.exclusive.probes'); wait_for('guest.exclusive.released');
        acquire_after_release('exclusive BRL succeeds after remote release', 'exclusive');
        marker('host.lock.done');
        my $change = wait_for('guest.changed');
        my $elapsed = wait_hash("$run/payload.bin", $change->{hash});
        check('cached host sees guest overwrite without remount', 'pass', {sha256=>$change->{hash}, visibilityMs=>$elapsed});
        my $ready = wait_for('guest.atomic.prepared');
        check('old atomic target is readable before replacement', hash_file("$run/atomic.bin") eq $ready->{oldHash} ? 'pass' : 'fail');
        marker('host.atomic.observing');
        my ($reads, $old_reads, $new_reads) = (0, 0, 0);
        my ($done_marker, $new_visible_ms, $replacement_complete);
        my $marker_observation = {state=>'not_yet_checked'};
        my $atomic_started = time;
        my $last_progress = $atomic_started;
        my $until = $atomic_started + ($diagnostic_active ? 180 : $timeout);
        my $old_bytes=length($old_atomic);
        my $new_bytes=length("new-atomic-$run_id\n")*2053;
        while (time < $until) {
            bounded_io($until, 'Waiting for atomic replacement peer', sub {peer_failed()});
            my $observed;
            if ($diagnostic_active) {
                my $sample=bounded_io($until, 'Reading POSIX replacement diagnostic', sub {
                    read_replace_target("$run/atomic.bin",$old_bytes>$new_bytes?$old_bytes:$new_bytes)
                });
                $observed=classify_replace_read($sample,$ready->{oldHash},$ready->{newHash},$old_bytes,$new_bytes,1);
                if ($observed eq 'gap') {
                    observe_missing_open(\%replace_gap,\$gap_started,time);
                    emit({event=>'posix_replace_open_missing',role=>$role,errno=>2,
                        elapsedMs=>int((time-$atomic_started)*1000),%replace_gap})
                        if $replace_gap{missingOpenCount}==1 || time-$last_progress>=10;
                } elsif ($observed eq 'fail') {
                    die "POSIX replacement diagnostic observed an unexpected open error, short read or checksum\n";
                } else { close_observed_gap(\%replace_gap,\$gap_started,time,1); }
            } else {
                # Strict behavior is unchanged: any OPEN or read error is fatal.
                my $hash = bounded_io($until, 'Reading atomic replacement', sub {hash_file("$run/atomic.bin")});
                $observed=$hash eq $ready->{oldHash}?'old':$hash eq $ready->{newHash}?'new':'fail';
                die "Atomic reader observed a partial or unexpected checksum\n" if $observed eq 'fail';
            }
            ++$reads unless $observed eq 'gap';
            if ($observed eq 'old') { ++$old_reads; }
            elsif ($observed eq 'new') {
                ++$new_reads;
                if (!defined $new_visible_ms) {
                    $new_visible_ms = int((time-$atomic_started)*1000);
                    emit({event=>'atomic_new_contents_visible', role=>$role, elapsedMs=>$new_visible_ms, reads=>$reads});
                }
            }
            if ($new_reads) {
                bounded_io($until, 'Waiting for atomic replacement marker', sub {
                    my $path = "$run/guest.atomic.done.json";
                    my @info = stat($path);
                    if (!@info) { $marker_observation = {state=>0+$! == 2 ? 'absent' : 'stat_failed', errno=>0+$!}; }
                    elsif (!S_ISREG($info[2])) { $marker_observation = {state=>'not_regular_file'}; }
                    else {
                        ($done_marker, $marker_observation) = decode_marker(read_file($path), $run_id);
                        if ($diagnostic_active && $done_marker && !completion_marker_valid($done_marker,$run_id)) {
                            undef $done_marker; $marker_observation={state=>'invalid_guest_completion_marker'};
                        }
                    }
                });
                if ($done_marker && (!$diagnostic_active || $observed eq 'new')) {
                    $replacement_complete=1; last;
                }
            }
            if (time-$last_progress >= 10) {
                emit({event=>'atomic_observation_progress', role=>$role, elapsedMs=>int((time-$atomic_started)*1000),
                    reads=>$reads, oldReads=>$old_reads, newReads=>$new_reads, marker=>$marker_observation,
                    ($diagnostic_active?(posixReplaceGap=>{%replace_gap}):())});
                $last_progress=time;
            }
            sleep 0.02;
        }
        check($diagnostic_active
                ? 'POSIX replacement diagnostic observes complete contents and validated guest completion; strict atomicity is not established'
                : 'atomic replacement has complete old/new reads and completion marker becomes visible',
            $new_reads && $done_marker && $replacement_complete ? ($diagnostic_active?'limited':'pass') : 'fail',
            {reads=>$reads, oldReads=>$old_reads, newReads=>$new_reads, sha256=>$ready->{newHash},
                newContentsVisibilityMs=>$new_visible_ms, marker=>$marker_observation, elapsedMs=>int((time-$atomic_started)*1000),
                ($diagnostic_active?(strictAtomicity=>JSON::PP::false,posixReplaceGap=>{%replace_gap},
                    gapMeasurement=>'Sampled interval from first OPEN ENOENT through the next complete successful read; not exact namespace timing.'):())});
        check('range fixture checksum preserved', hash_file("$run/ranges.bin") eq sha256_hex(join('', map {chr($_)} 0..255) x 64) ? 'pass' : 'fail');
        marker('host.data.observed');
        my $guest = wait_for('guest.report');
        # The peer may publish failure after wait_for's peer_failed() check but
        # before that same iteration reads its marker. Validate the returned
        # terminal report itself before constructing a successful summary.
        die "Guest terminal report is failed, stale or malformed\n"
            unless terminal_peer_report_valid($guest,$run_id,'guest');
        my $host = role_report('PASS', undef);
        save_json('host.report', $host);
        my $limited = scalar grep {$_->{status} eq 'limited'} (@checks, @{$guest->{checks}});
        my $summary = {runId=>$run_id, result=>$limited ? 'PASS_WITH_LIMITATIONS' : 'PASS',
            host=>$host, guest=>$guest, limitedChecks=>$limited, limitations=>[$limitation,($diagnostic_active?$replace_limitation:())],
            observationConfig=>observation_config(),
            ($diagnostic_active?(strictAtomicity=>JSON::PP::false):())};
        save_json('summary', $summary); emit({event=>'finished', role=>$role, result=>$summary->{result}, report=>"$run/summary.json"});
    } else {
        my $initial = wait_for('host.ready');
        # Report the host's diagnostic configuration; guest operations are unchanged.
        $diagnostic_active=1 if ref($initial->{observationConfig}) eq 'HASH'
            && ($initial->{observationConfig}{mode} // '') eq 'diagnose-posix-replace-gap';
        die "Host run is stale; use the same fresh run ID on both Macs\n"
            if time - ($initial->{at} // 0) > $timeout;
        die "Guest run directory is a symlink\n" if -l $run;
        mkdir("$run/guest.claim", 0700) or die "Guest role already started or run directory unavailable: $!\n";
        $role_claimed = 1;
        check('guest verifies host upload checksum', hash_file("$run/payload.bin") eq $initial->{initialHash} ? 'pass' : 'fail');
        # Directory-aware prefetch can outlive the first read. Settle it before
        # measuring, retaining the strict zero-new-object-request assertion.
        my $before_repeat = settled_storage('before guest repeated read');
        check('guest repeated cached read preserves checksum', hash_file("$run/payload.bin") eq $initial->{initialHash} ? 'pass' : 'fail');
        my $after_repeat = settled_storage('after guest repeated read');
        check('guest repeated read issues no new object requests',
            defined($before_repeat->{requests}) && defined($after_repeat->{requests})
            && $before_repeat->{requests} == $after_repeat->{requests} ? 'pass' : 'fail',
            {beforeRequests=>$before_repeat->{requests}, afterRequests=>$after_repeat->{requests}});
        posix_limitation();
        marker('guest.ready'); wait_for('host.exclusive');
        probe('remote exclusive BRL denies overlapping exclusive', 'exclusive', 0, 'blocked', 0);
        probe('exclusive BRL disjoint from remote exclusive acquires', 'exclusive', 8192, 'acquired', 0);
        marker('guest.host-lock.probes'); wait_for('host.exclusive.released');
        acquire_after_release('exclusive BRL succeeds after remote release', 'exclusive');
        my $exclusive = holder('exclusive', 'exclusive'); marker('guest.exclusive');
        wait_for('host.exclusive.probes');
        release_holder($exclusive, 'guest exclusive holder released'); marker('guest.exclusive.released');
        wait_for('host.lock.done');
        my $new_payload = "guest-rewrite-$run_id\xff" x 65539;
        write_file("$run/payload.bin", $new_payload);
        marker('guest.changed', {hash=>sha256_hex($new_payload)});
        my $new_atomic = "new-atomic-$run_id\n" x 2053;
        write_file("$run/atomic.stage", $new_atomic);
        marker('guest.atomic.prepared', {oldHash=>$initial->{oldAtomicHash}, newHash=>sha256_hex($new_atomic)});
        wait_for('host.atomic.observing');
        rename("$run/atomic.stage", "$run/atomic.bin") or die "Atomic replacement: $!\n";
        check('guest POSIX rename replacement syscall succeeded', 'pass');
        marker('guest.atomic.done'); wait_for('host.data.observed');
        admin_probes();
        my $guest = role_report('PASS', undef);
        save_json('guest.report', $guest);
        emit({event=>'finished', role=>$role, result=>$guest->{result}, report=>"$run/guest.report.json"});
    }
    1;
};
if (!$success) {
    my $error = $@ || 'Unknown failure';
    alarm(0);
    # Stop only helpers that this process spawned. Never signal an app/daemon.
    for my $pid (keys %children) { kill 'TERM', $pid; }
    for (1..40) {
        for my $pid (keys %children) { delete $children{$pid} if waitpid($pid, WNOHANG) == $pid; }
        last unless %children; sleep 0.05;
    }
    for my $pid (keys %children) { kill 'KILL', $pid; waitpid($pid, 0); }
    eval { save_json("$role.report", role_report('FAIL', $error)) } if $role_claimed && defined($run) && -d $run;
    emit({event=>'finished', role=>$role, result=>'FAIL', error=>$error, report=>defined($run) ? "$run/$role.report.json" : undef});
    exit 1;
}
exit 0;
