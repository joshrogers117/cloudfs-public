#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# Strict concurrent pathname replacement probe. Perl core modules only.
# Mutations are confined to one newly-created UUID fixture directory, which is
# deliberately retained (including on failure).
use strict;
use warnings;
use Cwd qw(abs_path);
use Digest::SHA qw(sha256_hex);
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_EXCL O_NOFOLLOW);
use Getopt::Long qw(GetOptions);
use IO::Handle;
use IO::Select;
use JSON::PP;
use POSIX qw(:sys_wait_h);
use Time::HiRes qw(time alarm sleep clock_gettime CLOCK_MONOTONIC);

my ($mount, $report, $label, $allow_local);
$allow_local = 0;
GetOptions('mount=s' => \$mount, 'report=s' => \$report, 'label=s' => \$label,
           'allow-local!' => \$allow_local) or die usage();
die usage() if @ARGV || !defined($mount) || !defined($report) || !defined($label);

my $json = JSON::PP->new->canonical->pretty;
my $started = clock_gettime(CLOCK_MONOTONIC);
my $started_at = int(time);
my ($fixture_dir, $fixture_name, $observer_counts, $observer_pid);
my @operations;
my @checks;
my $report_path;
my $result = 'FAIL';
my $error;
my $mount_path;

sub usage {
    return "Usage: validate-rapid-replacement.pl --label NAME --mount ABS_PATH --report ABS_PATH [--allow-local]\n".
        "The report must be new and outside the mounted volume. --allow-local is for isolated filesystem self-tests only.\n";
}

sub check {
    my ($name, $ok, $details) = @_;
    push @checks, {name => $name, pass => $ok ? JSON::PP::true : JSON::PP::false, details => $details};
    die "Check failed: $name\n" unless $ok;
}

sub bounded {
    my ($label, $seconds, $callback) = @_;
    local $SIG{ALRM} = sub { die "$label exceeded ${seconds}s\n" };
    alarm($seconds);
    my (@result, $result);
    my $ok = eval { $result = $callback->(); 1 };
    my $failure = $@;
    alarm(0);
    die $failure unless $ok;
    return $result;
}

sub path_identity {
    my ($path) = @_;
    my @st = lstat($path);
    die "Cannot stat fixture path: $!\n" unless @st;
    die "Fixture path is not a regular file\n" unless -f _ && !-l _;
    return {device => 0 + $st[0], inode => 0 + $st[1], size => 0 + $st[7]};
}

sub create_payload {
    my ($path, $byte) = @_;
    return bounded('fixture create/fsync/stat', 30, sub {
        return create_payload_inner($path, $byte);
    });
}

sub create_payload_inner {
    my ($path, $byte) = @_;
    my $data = $byte x 4096;
    sysopen(my $fh, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
        or die "Cannot exclusively create fixture file: $!\n";
    binmode($fh);
    my $offset = 0;
    while ($offset < length($data)) {
        my $count = syswrite($fh, $data, length($data) - $offset, $offset);
        die "Fixture write failed: $!\n" unless defined($count) && $count > 0;
        $offset += $count;
    }
    $fh->sync or die "Fixture fsync failed: $!\n";
    close($fh) or die "Fixture close failed: $!\n";
    my $identity = path_identity($path);
    die "Fixture payload has unexpected size\n" unless $identity->{size} == 4096;
    return {%$identity, sha256 => sha256_hex($data), byte => $byte};
}

sub mounted_path {
    my ($path) = @_;
    open(my $fh, '-|', '/sbin/mount') or die "Cannot inspect mounted volumes: $!\n";
    my $found = 0;
    while (my $line = <$fh>) {
        chomp($line);
        if ($line =~ /\bon \Q$path\E \(/) { $found = 1; last }
    }
    close($fh);
    return $found;
}

sub random_run_id {
    sysopen(my $random, '/dev/urandom', O_RDONLY) or die "Cannot read UUID entropy: $!\n";
    my $bytes = '';
    while (length($bytes) < 16) {
        my $n = sysread($random, my $part, 16 - length($bytes));
        die "Cannot read UUID entropy: $!\n" unless defined($n) && $n > 0;
        $bytes .= $part;
    }
    close($random);
    return unpack('H*', $bytes);
}

sub preflight {
    die "--mount must be an absolute, existing directory and not a symlink\n"
        unless $mount =~ m{\A/} && -d $mount && !-l $mount;
    $mount_path = abs_path($mount);
    die "--mount must be canonical and cannot be /\n"
        unless defined($mount_path) && $mount_path eq $mount && $mount_path ne '/';
    die "--mount must be a mounted volume (use --allow-local only for isolated self-tests)\n"
        unless $allow_local || mounted_path($mount_path);

    my $report_parent = $report;
    $report_parent =~ s{/[^/]+\z}{};
    $report_parent = '/' if $report_parent eq '';
    my $report_name = $report;
    $report_name =~ s{\A.*/}{};
    die "--report must be an absolute path\n" unless $report =~ m{\A/};
    die "Report parent must be an existing canonical directory\n"
        unless -d $report_parent && !-l $report_parent && abs_path($report_parent) eq $report_parent;
    $report_path = "$report_parent/$report_name";
    die "--report must be outside the supplied volume\n"
        if $report_path eq $mount_path || index($report_path, "$mount_path/") == 0;
    die "--report already exists; refusing to overwrite\n" if -e $report_path || -l $report_path;
    die "--label must be 1-80 safe characters\n" unless $label =~ /\A[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\z/;
}

sub pipe_line {
    my ($fh, $timeout, $what) = @_;
    my $select = IO::Select->new($fh);
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $timeout;
    my $line = '';
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $left = $deadline - clock_gettime(CLOCK_MONOTONIC);
        next unless $select->can_read($left);
        my $n = sysread($fh, my $chunk, 4096);
        die "$what pipe closed before response\n" unless defined($n) && $n > 0;
        $line .= $chunk;
        return $1 if $line =~ s/\A(.*?\n)//s;
    }
    die "$what timed out\n";
}

sub observer_child {
    my ($target, $command_read, $result_write) = @_;
    $| = 1;
    my $observer_started = clock_gettime(CLOCK_MONOTONIC);
    my $ready = "READY\n";
    syswrite($result_write, $ready);
    my $select = IO::Select->new($command_read);
    my %counts = (observations => 0, old => 0, new => 0, enoent => 0, other => 0, errors => 0);
    $counts{errorSamples} = [];
    $counts{errorSamplesOmitted} = 0;
    my $stop = 0;
    while (!$stop) {
        if ($select->can_read(0)) {
            my $n = sysread($command_read, my $command, 64);
            last if !defined($n) || $n == 0;
            $stop = 1 if index($command, 'STOP') >= 0;
            next if $stop;
        }
        $counts{observations}++;
        my $class = 'errors';
        my $phase = 'open';
        my ($error_errno, $error_message);
        my $attempt_started = clock_gettime(CLOCK_MONOTONIC);
        my $ok = eval {
            bounded('observer open/read', 8, sub {
                sysopen(my $fh, $target, O_RDONLY | O_NOFOLLOW) or do {
                    $error_errno = 0 + $!;
                    $error_message = "$!";
                    $class = ($!{ENOENT} || $!{ENOTDIR}) ? 'enoent' : 'errors';
                    return;
                };
                binmode($fh);
                my $data = '';
                $phase = 'read';
                while (length($data) <= 4096) {
                    my $n = sysread($fh, my $chunk, 4097 - length($data));
                    unless (defined($n)) {
                        $error_errno = 0 + $!;
                        $error_message = "$!";
                        die "observer read failed";
                    }
                    last if $n == 0;
                    $data .= $chunk;
                }
                $phase = 'close';
                unless (close($fh)) {
                    $error_errno = 0 + $!;
                    $error_message = "$!";
                    die "observer close failed";
                }
                $phase = 'classify';
                $class = length($data) == 4096 && $data eq ('A' x 4096) ? 'old'
                    : length($data) == 4096 && $data eq ('B' x 4096) ? 'new' : 'other';
            });
            1;
        };
        if (!$ok) {
            $class = 'errors';
            $error_message //= $@;
            # A timeout has no relevant syscall errno; do not report stale $!.
            $error_errno //= 0;
        }
        if ($class eq 'errors' || $class eq 'enoent') {
            my $message = $error_message // 'observer operation failed';
            $message =~ s/[\r\n\x00-\x1f\x7f]+/ /g;
            $message =~ s/\s+/ /g;
            $message = substr($message, 0, 160);
            my $sample = {
                phase => $phase,
                errno => 0 + ($error_errno // 0),
                message => $message,
                elapsedMs => int((clock_gettime(CLOCK_MONOTONIC) - $observer_started) * 1000 + 0.5),
                attemptElapsedMs => int((clock_gettime(CLOCK_MONOTONIC) - $attempt_started) * 1000 + 0.5),
                unixTimestamp => time,
            };
            if (@{$counts{errorSamples}} < 8) {
                push @{$counts{errorSamples}}, $sample;
            } else {
                $counts{errorSamplesOmitted}++;
            }
        }
        $counts{$class}++;
    }
    my $line = JSON::PP->new->canonical->encode(\%counts)."\n";
    syswrite($result_write, $line);
    close($command_read); close($result_write);
    POSIX::_exit(0);
}

sub start_observer {
    my ($target) = @_;
    pipe(my $command_read, my $command_write) or die "Cannot create observer command pipe: $!\n";
    pipe(my $result_read, my $result_write) or die "Cannot create observer result pipe: $!\n";
    my $pid = fork();
    die "Cannot fork independent pathname observer: $!\n" unless defined $pid;
    if ($pid == 0) {
        close($command_write); close($result_read);
        observer_child($target, $command_read, $result_write);
    }
    close($command_read); close($result_write);
    $observer_pid = $pid;
    my $ready = pipe_line($result_read, 5, 'Observer readiness');
    die "Observer did not report READY\n" unless $ready eq "READY\n";
    return ($command_write, $result_read, $pid);
}

sub stop_observer {
    my ($command_write, $result_read, $pid) = @_;
    if (defined($command_write)) {
        eval { syswrite($command_write, "STOP\n"); close($command_write); };
    }
    my $line;
    eval { $line = pipe_line($result_read, 10, 'Observer summary'); };
    my $read_error = $@;
    close($result_read) if defined $result_read;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 10;
    my $waited = 0;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        $waited = waitpid($pid, WNOHANG);
        if ($waited == -1) {
            next if $!{EINTR};
            $observer_pid = undef if $!{ECHILD};
            last;
        }
        last if $waited == $pid;
        sleep(0.02);
    }
    if ($waited == 0) {
        kill 'TERM', $pid;
        sleep(0.1);
        $waited = waitpid($pid, WNOHANG);
        if ($waited == 0) {
            kill 'KILL', $pid;
            my $kill_deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
            while (clock_gettime(CLOCK_MONOTONIC) < $kill_deadline) {
                $waited = waitpid($pid, WNOHANG);
                last if $waited == $pid || $waited == -1;
                sleep(0.02);
            }
        }
        die "Observer did not stop after bounded waits\n" if $waited == 0;
    }
    # Once waitpid says the child is gone, never signal this numeric PID again:
    # the OS may reuse it while summary validation below is still running.
    $observer_pid = undef if $waited == $pid;
    die "Observer could not be reaped\n" if $waited != $pid;
    my $child_status = $?;
    die "Observer exited unsuccessfully (wait status $child_status)\n" if $child_status != 0;
    die $read_error if $read_error;
    my $counts = eval { JSON::PP->new->decode($line) };
    die "Observer summary was invalid JSON\n" unless ref($counts) eq 'HASH';
    $observer_pid = undef;
    return $counts;
}

sub write_report {
    my ($path, $data) = @_;
    sysopen(my $fh, $path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
        or die "Cannot create report outside volume: $!\n";
    binmode($fh);
    my $bytes = $json->encode($data)."\n";
    my $offset = 0;
    while ($offset < length($bytes)) {
        my $n = syswrite($fh, $bytes, length($bytes) - $offset, $offset);
        die "Report write failed: $!\n" unless defined($n) && $n > 0;
        $offset += $n;
    }
    $fh->sync or die "Report fsync failed: $!\n";
    close($fh) or die "Report close failed: $!\n";
}

eval {
    bounded('mount/report preflight', 10, \&preflight);
    my $mount_stat_ref = bounded('mounted root stat', 8, sub { [stat($mount_path)] });
    my @mount_stat = @$mount_stat_ref;
    my $run_id = random_run_id();
    $fixture_name = "cloudfs-rapid-replacement-$run_id";
    $fixture_dir = "$mount_path/$fixture_name";
    bounded('exclusive UUID fixture directory create', 8, sub {
        mkdir($fixture_dir, 0700) or die "Cannot create exclusive UUID fixture: $!\n";
    });
    my $fixture_stat_ref = bounded('fixture directory stat', 8, sub { [lstat($fixture_dir)] });
    my @fixture_stat = @$fixture_stat_ref;
    die "Fixture directory escaped volume or changed type\n"
        unless @fixture_stat && -d _ && !-l _ && $fixture_stat[0] == $mount_stat[0]
            && abs_path($fixture_dir) eq $fixture_dir;

    my $old = 'A' x 4096;
    my @sources;
    my %identities;
    $identities{'target.bin'} = create_payload("$fixture_dir/target.bin", 'A');
    for my $index (0..23) {
        my $name = sprintf('source-%02d.bin', $index);
        my $byte = $index % 2 == 0 ? 'B' : 'A';
        $identities{$name} = create_payload("$fixture_dir/$name", $byte);
        push @sources, $name;
    }
    check('fixture contains target plus exactly 24 pre-created alternating sources',
        scalar(@sources) == 24 && $identities{$sources[0]}{byte} eq 'B'
            && $identities{$sources[-1]}{byte} eq 'A',
        {sourceCount => scalar(@sources), sourceBytes => 4096,
         initialTargetSHA256 => $identities{'target.bin'}{sha256}});

    my ($command_write, $result_read, $pid) = start_observer("$fixture_dir/target.bin");
    my $operation_error;
    for my $name (@sources) {
        my $source = "$fixture_dir/$name";
        my $target = "$fixture_dir/target.bin";
        my $entry = {source => $name, expectedByte => $identities{$name}{byte},
                     sourceIdentity => {device => $identities{$name}{device}, inode => $identities{$name}{inode}}};
        my $before = clock_gettime(CLOCK_MONOTONIC);
        $entry->{startedAtEpoch} = time;
        my $ok = eval { bounded('same-directory replacement', 8, sub {
            rename($source, $target) or die "rename failed: $!\n";
        }); 1 };
        $entry->{completedAtEpoch} = time;
        $entry->{elapsedUs} = int((clock_gettime(CLOCK_MONOTONIC) - $before) * 1_000_000 + 0.5);
        $entry->{elapsedMs} = $entry->{elapsedUs} / 1000;
        $entry->{completed} = $ok ? JSON::PP::true : JSON::PP::false;
        if (!$ok) {
            $entry->{error} = "$@";
            push @operations, $entry;
            $operation_error = $@;
            last;
        }
        my $identity = eval { bounded('post-rename identity check', 8, sub { path_identity($target) }) };
        if (!$identity) {
            $entry->{identityError} = "$@";
            $operation_error = $@;
            push @operations, $entry;
            last;
        }
        $entry->{targetIdentityAfter} = $identity;
        $entry->{identityMatchesSource} = ($identity->{device} == $identities{$name}{device}
            && $identity->{inode} == $identities{$name}{inode}) ? JSON::PP::true : JSON::PP::false;
        push @operations, $entry;
        last if $entry->{elapsedUs} >= 8_000_000;
    }
    $observer_counts = eval { stop_observer($command_write, $result_read, $pid) };
    if (!$observer_counts) { $operation_error //= $@; }
    die $operation_error if $operation_error;

    my $total = $observer_counts->{old} + $observer_counts->{new} + $observer_counts->{enoent}
        + $observer_counts->{other} + $observer_counts->{errors};
    check('all 24 replacements completed within the strict 8,000 ms bound',
        @operations == 24 && !grep({ !$_->{completed} || $_->{elapsedUs} >= 8_000_000 } @operations),
        {requiredOperations => 24, completedOperations => scalar(@operations),
         limitMs => 8000, timingsMs => [map { $_->{elapsedMs} } @operations]});
    check('observer sampled the target during the replacement sequence',
        $total == $observer_counts->{observations} && $total > 0,
        {observations => $total, counts => $observer_counts});
    check('observer saw only complete A/B payloads with no missing path or read errors',
        $observer_counts->{enoent} == 0 && $observer_counts->{other} == 0
            && $observer_counts->{errors} == 0 && $observer_counts->{old} > 0
            && $observer_counts->{new} > 0,
        {counts => $observer_counts,
         bothStatesRequired => JSON::PP::true,
         finiteSamplingLimit => 'Finite concurrent sampling cannot prove every replacement was atomic.'});
    check('every replacement identity matches its pre-created source inode',
        !grep({ !$_->{identityMatchesSource} } @operations),
        {identityChecks => scalar(@operations), operations => \@operations});
    $result = 'PASS';
    1;
} or do { $error = $@ || 'Unknown validation error'; };

if (defined $observer_pid) {
    kill 'TERM', $observer_pid;
    sleep(0.1);
    kill 'KILL', $observer_pid if waitpid($observer_pid, WNOHANG) == 0;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline && waitpid($observer_pid, WNOHANG) == 0) { sleep(0.02); }
}

my $value = {
    result => $result, validationClass => 'strict-rapid-replacement', label => $label,
    mount => $mount_path // $mount, strictRenameLimitMs => 8000,
    replacementCountRequired => 24, replacementOperations => \@operations,
    observerCounts => $observer_counts,
    observerLimit => 'Finite concurrent sampling can find missing, mixed, or erroneous reads but cannot prove every replacement atomic.',
    checks => \@checks, startedAtEpoch => $started_at,
    elapsedMs => int((clock_gettime(CLOCK_MONOTONIC) - $started) * 1000 + 0.5),
};
$value->{error} = "$error" if defined $error;
$value->{fixture} = defined($fixture_dir)
    ? {directory => $fixture_name, path => $fixture_dir,
       retention => 'fixture retained, including on failure'}
    : undef;
if (defined $report_path) {
    my $written = eval { write_report($report_path, $value); 1 };
    if (!$written) {
        warn "Report could not be written: $@";
        $result = 'FAIL';
    }
}
print JSON::PP->new->canonical->encode({result => $result,
    report => $report_path, fixture => $fixture_dir, error => $error}), "\n";
exit($result eq 'PASS' ? 0 : 1);
