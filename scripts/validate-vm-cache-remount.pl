#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# Disposable macOS VM check for replacement visibility after clearing local caches.
# Perl core only. Reads one prior failure report and talks only to the local daemon
# control socket; it does not contact the gateway or read credentials.
#
# Usage: perl validate-vm-cache-remount.pl --fixture-report report38d.json \
#   --socket PATH --filespace ID --mount PATH --report new-report.json
use strict;
use warnings;
use JSON::PP;
use Digest::SHA;
use IO::Socket::UNIX;
use IO::Handle;
use Getopt::Long qw(GetOptions);
use Cwd qw(abs_path);
use File::Basename qw(dirname basename);
use File::Spec;
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_EXCL O_NOFOLLOW S_ISREG);
use Time::HiRes qw(time sleep);

$|=1;
my ($fixture_report,$socket,$filespace,$mount,$report);
my $timeout=180;
GetOptions('fixture-report=s'=>\$fixture_report,'socket=s'=>\$socket,
    'filespace=s'=>\$filespace,'mount=s'=>\$mount,'report=s'=>\$report,
    'timeout=i'=>\$timeout) or die "Invalid options\n";
die "Unexpected positional arguments\n" if @ARGV;
die "Required: --fixture-report PATH --socket PATH --filespace ID --mount PATH --report PATH\n"
    unless defined($fixture_report) && defined($socket) && defined($filespace)
        && defined($mount) && defined($report);
die "Invalid timeout\n" unless $timeout>=30 && $timeout<=600;
die "Invalid filespace ID\n" unless $filespace =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
my $json=JSON::PP->new->canonical;
my $started=time;
my (@checks,$fixture,$unmounted);
my $cold_details;

sub emit { print $json->encode($_[0]),"\n"; }
sub check {
    my ($name,$ok,$details)=@_;
    push @checks,{name=>$name,pass=>$ok?JSON::PP::true:JSON::PP::false,details=>$details};
    emit({event=>'check',%{$checks[-1]}});
    die "Check failed: $name\n" unless $ok;
}
sub write_report {
    my ($result,$error,$restored)=@_;
    my $value={result=>$result,fixtureReport=>$fixture_report,filespace=>$filespace,
        mount=>$mount,fixtureDetails=>$fixture,checks=>\@checks,
        elapsedMs=>int((time-$started)*1000),scope=>'Cold and warm remount cache validation only; this does not establish open-handle lifetime.',
        (defined($error)?(error=>substr($error,0,500)):()),
        (defined($restored)?(mountRestored=>$restored?JSON::PP::true:JSON::PP::false):()),
        (defined($cold_details)?(coldObservation=>$cold_details):())};
    # Exclusive creation prevents a typo or race from overwriting existing evidence.
    sysopen(my $fh,$report,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600)
        or die "Cannot create new report without replacing existing output: $!\n";
    binmode($fh);print $fh $json->encode($value),"\n" or die "Report write failed: $!\n";
    $fh->sync or die "Report fsync failed: $!\n";
    close($fh) or die "Report close failed: $!\n";
    return $value;
}
sub rpc {
    my ($method,$params)=@_;
    local $SIG{ALRM}=sub {die "RPC timed out\n"};
    alarm($timeout+5);
    my $s=IO::Socket::UNIX->new(Peer=>$socket) or die "Cannot connect to daemon control socket: $!\n";
    print $s $json->encode({jsonrpc=>'2.0',id=>1,method=>$method,params=>$params//{filespace=>$filespace}}),"\n"
        or die "RPC write failed: $!\n";
    my $line=<$s>;close($s);alarm(0);
    die "Daemon closed RPC\n" unless defined($line);
    my $reply=$json->decode($line);
    die "Daemon $method failed (code ".($reply->{error}{code}//'unknown').")\n" if $reply->{error};
    return $reply->{result};
}
sub status { rpc('status',{filespace=>$filespace}); }
sub mounted {
    my ($s)=@_;
    return ref($s) eq 'HASH' && ($s->{connection}//'') eq 'connected'
        && ($s->{mountPath}//'') eq $mount;
}
sub synced {
    my ($s)=@_;
    return ref($s) eq 'HASH' && defined($s->{pendingUploads}) && defined($s->{pendingBytes})
        && $s->{pendingUploads}==0 && $s->{pendingBytes}==0;
}
sub counter {
    my ($s)=@_;my $storage=$s->{storage};
    die "Object-storage telemetry unavailable\n" unless ref($storage) eq 'HASH'
        && defined($storage->{requests}) && "$storage->{requests}" =~ /^[0-9]+$/
        && defined($storage->{activeRequests}) && "$storage->{activeRequests}" =~ /^[0-9]+$/;
    return 0+$storage->{requests};
}
sub delta {
    my ($before,$after)=@_;
    die "Object-request counter reset; cannot prove cold fetch or warm reuse\n" if $after<$before;
    return $after-$before;
}
sub flush_filespace {
    my $s=rpc('flush',{filespace=>$filespace,path=>'/',wait=>JSON::PP::true,
        timeoutMs=>$timeout*1000});
    die "Flush did not reach in-sync state\n" unless ref($s) eq 'HASH' && $s->{inSync} && synced($s);
    die "Pending writes remain after flush\n" unless synced(status());
    return $s;
}
sub quiet_storage {
    my ($phase)=@_;my $until=time+30;my ($last,$stable);
    while (time<$until) {
        my $s=status();
        die "Volume became unmounted during $phase\n" unless mounted($s);
        die "Pending writes appeared during $phase\n" unless synced($s);
        my $requests=counter($s);
        if ($s->{storage}{activeRequests}==0 && defined($last) && $requests==$last) {
            $stable//=time;
            return 0+$requests if time-$stable>=1.5;
        } else {undef $stable;}
        $last=$requests;sleep(.2);
    }
    die "Object requests did not settle during $phase\n";
}
sub unmount {
    my $s=status();
    die "Refusing to unmount a different or unsynchronized filespace\n" unless mounted($s) && synced($s);
    rpc('unmount',{filespace=>$filespace,force=>JSON::PP::false});$unmounted=1;
    die "Daemon still reports the volume mounted\n" if defined(status()->{mountPath});
}
sub remount {
    my $result=rpc('mount',{filespace=>$filespace,at=>$mount,name=>'CloudFS replacement cache validation'});
    die "Daemon mounted at an unexpected path\n" unless ref($result) eq 'HASH'
        && ($result->{mountPath}//'') eq $mount && mounted(status());
    $unmounted=0;
    die "Fixture folder missing or redirected after remount\n" unless -d "$mount/$fixture->{folder}"
        && !-l "$mount/$fixture->{folder}"
        && (abs_path("$mount/$fixture->{folder}")//"") eq "$mount/$fixture->{folder}";
}
sub hash_file {
    my ($path)=@_;
    local $SIG{ALRM}=sub {die "Mounted file read timed out\n"};alarm($timeout);
    sysopen(my $fh,$path,O_RDONLY|O_NOFOLLOW) or die "Cannot open mounted fixture: $!\n";
    binmode($fh);my @before=stat($fh);
    die "Mounted fixture is not a regular file\n" unless @before && S_ISREG($before[2]);
    my $hash=Digest::SHA->new(256);my $bytes=0;
    while (1) {
        my $n=sysread($fh,my $buffer,1024*1024);
        die "Mounted fixture read failed: $!\n" unless defined($n);
        last unless $n;$bytes+=$n;$hash->add($buffer);
    }
    my @after=stat($fh);close($fh) or die "Mounted fixture close failed: $!\n";alarm(0);
    die "Mounted fixture changed during checksum\n" unless @after && $before[7]==$after[7]
        && $before[9]==$after[9] && $bytes==$after[7];
    return {bytes=>$bytes,sha256=>$hash->hexdigest,device=>$before[0],inode=>$before[1]};
}
sub safe_fixture_report {
    my ($path)=@_;
    die "Fixture report must be a regular file without symlink redirection\n" unless -f $path && !-l $path;
    my $real=abs_path($path)//die "Cannot resolve fixture report\n";
    die "Fixture report must be outside the mounted volume\n" if index($real,"$mount/")==0;
    open my $fh,'<',$real or die "Cannot read fixture report: $!\n";
    local $/;my $raw=<$fh>;close($fh) or die "Cannot close fixture report: $!\n";
    my $input=eval {$json->decode($raw)};
    die "Fixture report is not valid JSON\n" if $@ || ref($input) ne 'HASH';
    die "Expected a prior FAIL report with fixtureDetails\n" unless ($input->{result}//'') eq 'FAIL'
        && ref($input->{fixtureDetails}) eq 'HASH';
    die "Fixture report belongs to a different filespace\n" unless ($input->{filespace}//'') eq $filespace;
    die "Fixture report belongs to a different mount\n" unless ($input->{mount}//'') eq $mount;
    my $d=$input->{fixtureDetails};
    my $folder=$d->{folder};
    die "Unsafe fixture folder name\n" unless defined($folder) && !ref($folder)
        && $folder =~ /\Acloudfs-open-lifetime-vm-[A-Za-z0-9_-]{1,80}\z/;
    my $target="$folder/vm-source.bin";my $source="$folder/vm-replacement.bin";
    die "Fixture report paths do not match expected source/replacement paths\n"
        unless ($d->{replaceTargetPath}//'') eq $target && ($d->{replaceSourcePath}//'') eq $source;
    my $replacement=$d->{replacementFile};
    die "Fixture report replacement checksum is invalid\n" unless ref($replacement) eq 'HASH'
        && ($replacement->{name}//'') eq 'vm-replacement.bin'
        && defined($replacement->{bytes}) && !ref($replacement->{bytes})
        && "$replacement->{bytes}" =~ /^[1-9][0-9]*$/ && $replacement->{bytes}<2**40
        && ($replacement->{sha256}//'') =~ /\A[0-9a-f]{64}\z/;
    return {folder=>$folder,targetRelativePath=>$target,sourceRelativePath=>$source,
        expectedBytes=>0+$replacement->{bytes},expectedSHA256=>$replacement->{sha256},
        replacementPrefixSHA256=>Digest::SHA::sha256_hex($replacement->{prefix}//'')};
}

my $ok=eval {
    die "--mount must be an existing canonical directory without symlink redirection\n"
        unless -d $mount && !-l $mount && (abs_path($mount)//'') eq $mount;
    die "--socket must be a Unix socket path without symlink redirection\n" unless -S $socket && !-l $socket;
    my $report_dir=abs_path(dirname($report))//die "Report directory must exist\n";
    $report=File::Spec->catfile($report_dir,basename($report));
    die "Report path must be outside the mounted volume\n" if index($report,"$mount/")==0;
    die "Report output already exists\n" if -e $report || -l $report;
    $fixture=safe_fixture_report($fixture_report);
    die "Fixture folder is missing or redirected\n" unless -d "$mount/$fixture->{folder}"
        && !-l "$mount/$fixture->{folder}"
        && (abs_path("$mount/$fixture->{folder}")//"") eq "$mount/$fixture->{folder}";
    die "Fixture source path is unsafe or absent\n" unless -f "$mount/$fixture->{targetRelativePath}"
        && !-l "$mount/$fixture->{targetRelativePath}";
    die "Fixture replacement source should have been moved away\n" if -e "$mount/$fixture->{sourceRelativePath}"
        || -l "$mount/$fixture->{sourceRelativePath}";
    my $initial=status();
    check('same filespace begins mounted and synchronized',mounted($initial) && synced($initial),
        {connection=>$initial->{connection},mountPath=>$initial->{mountPath},pendingUploads=>$initial->{pendingUploads},pendingBytes=>$initial->{pendingBytes}});

    # Capture the still-mounted behavior as evidence. It is allowed to observe old
    # bytes: this run specifically checks the cold and warm remount behaviors below.
    my $pre=hash_file("$mount/$fixture->{targetRelativePath}");
    $fixture->{preClearPathObservation}=$pre;
    emit({event=>'preclear_path_observation',%$pre,expectedSHA256=>$fixture->{expectedSHA256}});

    flush_filespace();
    check('pending writes are zero before unmount',synced(status()),{});
    unmount();
    my $cleared=rpc('cache.clear',{filespace=>$filespace});
    check('unmounted guest cache is empty',ref($cleared) eq 'HASH'
        && defined($cleared->{usedBytes}) && $cleared->{usedBytes}==0
        && defined($cleared->{pinnedBytes}) && $cleared->{pinnedBytes}==0,
        {usedBytes=>$cleared->{usedBytes},pinnedBytes=>$cleared->{pinnedBytes}});
    remount();

    my $cold_before=quiet_storage('before cold checksum');
    my $cold=hash_file("$mount/$fixture->{targetRelativePath}");
    my $cold_after=quiet_storage('after cold checksum');
    my $cold_match=$cold->{bytes}==$fixture->{expectedBytes}
        && $cold->{sha256} eq $fixture->{expectedSHA256};
    $cold_details={beforeRequests=>$cold_before,afterRequests=>$cold_after,
        additionalRequests=>delta($cold_before,$cold_after),observation=>$cold,
        expectedBytes=>$fixture->{expectedBytes},expectedSHA256=>$fixture->{expectedSHA256}};
    check('cold remount reads the replacement source exactly',$cold_match,$cold_details);
    check('cold remount fetches replacement objects',delta($cold_before,$cold_after)>0,$cold_details);

    unmount();remount();
    my $warm_before=quiet_storage('before warm checksum');
    my $warm=hash_file("$mount/$fixture->{targetRelativePath}");
    my $warm_after=quiet_storage('after warm checksum');
    my $warm_match=$warm->{bytes}==$fixture->{expectedBytes}
        && $warm->{sha256} eq $fixture->{expectedSHA256};
    my $warm_details={beforeRequests=>$warm_before,afterRequests=>$warm_after,
        additionalRequests=>delta($warm_before,$warm_after),observation=>$warm,
        expectedBytes=>$fixture->{expectedBytes},expectedSHA256=>$fixture->{expectedSHA256}};
    check('warm remount still reads replacement source exactly',$warm_match,$warm_details);
    check('warm remount checksum adds no object-storage requests',delta($warm_before,$warm_after)==0,$warm_details);
    flush_filespace();
    my $value=write_report('PASS',undef,undef);
    emit({event=>'finished',result=>'PASS',report=>$report,checks=>scalar(@checks),
        note=>'Cache-remount checks passed; this is not an open-handle-lifetime pass.'});
    1;
};

if (!$ok) {
    my $error=$@||'Validation failed';alarm(0);$error =~ s/[\r\n]+/ /g;
    my $restored;
    if ($unmounted) {
        $restored=eval {
            my $s=status();
            die "A different mount is active; refusing to restore over it\n" if defined($s->{mountPath});
            remount();1;
        } ? 1 : 0;
    }
    my $written=eval {write_report('FAIL',substr($error,0,500),$restored);1};
    emit({event=>'finished',result=>'FAIL',error=>substr($error,0,500),mountRestored=>$restored,
        reportWritten=>$written?JSON::PP::true:JSON::PP::false,report=>$report});
    exit 1;
}
exit 0;
