#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# Disposable VM participant for backend-driven atomic replacement validation.
# Perl core modules only; this script makes no gateway/API requests and reads no credentials.
# Run with --socket PATH --filespace ID --mount PATH --report PATH
# and optionally --report-url http://10.x.x.x:PORT/vm-report for the host collector.
use strict;
use warnings;
use JSON::PP;
use Digest::SHA;
use IO::Socket::UNIX;
use IO::Handle;
use Getopt::Long qw(GetOptions);
use Cwd qw(abs_path);
use Fcntl qw(O_RDONLY O_RDWR O_WRONLY O_CREAT O_EXCL O_NOFOLLOW S_ISREG);
use Time::HiRes qw(time sleep);

$|=1;
my ($socket,$filespace,$mount,$report,$report_url,$timeout,$allow_remote_presentation_id_change,$read_only_target);
$timeout=300;
$allow_remote_presentation_id_change=0;
$read_only_target=0;
GetOptions('socket=s'=>\$socket,'filespace=s'=>\$filespace,'mount=s'=>\$mount,
    'report=s'=>\$report,'report-url=s'=>\$report_url,'timeout=i'=>\$timeout,
    'allow-remote-presentation-id-change!'=>\$allow_remote_presentation_id_change,
    'read-only-target!'=>\$read_only_target) or die "Invalid options\n";
die "Unexpected positional arguments\n" if @ARGV;
die "Required: --socket PATH --filespace ID --mount PATH --report PATH\n"
    unless defined($socket) && defined($filespace) && defined($mount) && defined($report);
die "Invalid timeout\n" unless $timeout>=30 && $timeout<=600;
die "Invalid filespace ID\n" unless $filespace =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
my $json=JSON::PP->new->canonical;
if (defined $report_url) {
    die "--report-url must be a host-collector HTTP URL on 10/8 without credentials or query\n"
        unless $report_url =~ m{\Ahttp://10\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}):(\d{1,5})/[A-Za-z0-9/_-]*\z};
    my ($b,$c,$d,$port)=($1,$2,$3,$4);
    die "Invalid --report-url address or port\n" if $b>255 || $c>255 || $d>255 || $port<1 || $port>65535;
}
my $started=time;
my $run_id=sprintf('%08x%08x',int(time*1000),int(rand(0xffffffff)));
my $folder_name="cloudfs-open-lifetime-vm-$run_id";
my @checks;
my @compatibility_limitations;
push @compatibility_limitations,'diagnostic read-only target descriptor; target write lifetime was not tested'
    if $read_only_target;
my $unmounted=0;
my $held;
my $source_held;
my $fixture_details;
my $replacement_poll = {
    startedAt => undef,
    opensAttempted => 0,
    opensSucceeded => 0,
    openFailures => 0,
    statFailures => 0,
    readsAttempted => 0,
    shortReads => 0,
    readFailures => 0,
    closeFailures => 0,
    observations => 0,
    oldPrefixCount => 0,
    newPrefixCount => 0,
    otherPrefixCount => 0,
    lastObserved => undef,
    lastError => undef,
};
my $poll_io_timeout = 8;
my $report_path=abs_path((do { require File::Basename; File::Basename::dirname($report) }))
    // die "Report directory must exist\n";
$report="$report_path/".(do { require File::Basename; File::Basename::basename($report) });

sub emit { print $json->encode($_[0]),"\n"; }
sub post_collector {
    my ($value)=@_;
    return unless defined $report_url;
    open my $http,'|-','/usr/bin/curl','--silent','--show-error','--fail','--max-time','10',
        '--request','POST','--header','Content-Type: application/json','--data-binary','@-',
        '--output','/dev/null',$report_url or die "Cannot start host report collector client\n";
    print $http $json->encode($value) or die "Cannot send report to host collector\n";
    close($http) or die "Host report collector rejected the report\n";
}
sub check {
    my ($name,$ok,$details)=@_;
    push @checks,{name=>$name,pass=>$ok?JSON::PP::true:JSON::PP::false,details=>$details};
    emit({event=>'check',%{$checks[-1]}});
    die "Check failed: $name\n" unless $ok;
}
sub write_report {
    my ($state,$extra,$post)=@_;
    my $result=$state eq 'failed'?'FAIL':$state eq 'complete'
        ? (@compatibility_limitations?'PASS_WITH_LIMITATIONS':'PASS') : 'RUNNING';
    my $value={result=>$result,state=>$state,runId=>$run_id,
        filespace=>$filespace,mount=>$mount,fixture=>$folder_name,checks=>\@checks,
        compatibilityLimitations=>\@compatibility_limitations,
        targetDescriptorAccess=>$read_only_target?'read-only':'read-write',
        targetWriteLifetime=>$read_only_target?'not tested':'pending',
        validationScope=>$read_only_target
            ? 'Read-only diagnostic replacement probe; target write lifetime was not tested.'
            : 'Strict replacement probe with a read/write held target descriptor.',
        elapsedMs=>int((time-$started)*1000),($extra?%$extra:())};
    my $tmp="$report.tmp-$$";
    sysopen(my $fh,$tmp,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600) or die "Cannot create report update: $!\n";
    binmode($fh); print $fh $json->encode($value),"\n" or die "Report write failed: $!\n";
    $fh->sync or die "Report fsync failed: $!\n";
    close($fh) or die "Report close failed: $!\n";
    rename($tmp,$report) or die "Cannot publish report update: $!\n";
    $post=1 unless defined $post;
    post_collector($value) if $post && ($state eq 'waiting_for_host_replace' || $state eq 'complete' || $state eq 'failed');
}
sub rpc {
    my ($method,$params)=@_;
    local $SIG{ALRM}=sub {die "RPC timed out\n"};
    alarm($timeout+5);
    my $s=IO::Socket::UNIX->new(Peer=>$socket) or die "Cannot connect to daemon control socket: $!\n";
    print $s $json->encode({jsonrpc=>'2.0',id=>1,method=>$method,
        params=>$params//{filespace=>$filespace}}),"\n" or die "RPC write failed: $!\n";
    my $line=<$s>;close($s);alarm(0);
    die "Daemon closed RPC\n" unless defined($line);
    my $reply=$json->decode($line);
    die "Daemon $method failed (code ".($reply->{error}{code}//'unknown').")\n" if $reply->{error};
    return $reply->{result};
}
sub status { rpc('status',{filespace=>$filespace}); }
sub mounted {
    my ($s)=@_;
    return ref($s) eq 'HASH' && ($s->{connection}//'') eq 'connected' && ($s->{mountPath}//'') eq $mount;
}
sub synced {
    my ($s)=@_;
    return ref($s) eq 'HASH' && defined($s->{pendingUploads}) && defined($s->{pendingBytes})
        && $s->{pendingUploads}==0 && $s->{pendingBytes}==0;
}
sub flush_filespace {
    my $s=rpc('flush',{filespace=>$filespace,path=>'/',wait=>JSON::PP::true,timeoutMs=>$timeout*1000});
    die "Flush did not reach in-sync state\n" unless $s->{inSync} && synced($s) && synced(status());
    return $s;
}
sub make_payload {
    my ($path,$pattern,$size)=@_;
    sysopen(my $fh,$path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600) or die "Cannot create synthetic payload: $!\n";
    binmode($fh);
    my $hash=Digest::SHA->new(256); my $written=0;
    while ($written<$size) {
        my $count=$size-$written; $count=65536 if $count>65536;
        my $phase=$written%length($pattern);
        my $chunk=substr($pattern x int(($phase+$count+length($pattern)-1)/length($pattern)),$phase,$count);
        my $offset=0;
        while ($offset<length($chunk)) {
            my $n=syswrite($fh,$chunk,length($chunk)-$offset,$offset);
            die "Synthetic payload write failed: $!\n" unless defined($n) && $n>0;
            $offset+=$n;
        }
        $hash->add($chunk);$written+=length($chunk);
    }
    $fh->sync or die "Synthetic payload fsync failed: $!\n";
    close($fh) or die "Synthetic payload close failed: $!\n";
    return {name=>File::Basename::basename($path),bytes=>$written,sha256=>$hash->hexdigest,
        prefix=>substr($pattern x int((64+length($pattern)-1)/length($pattern)),0,64)};
}
sub read_exact {
    my ($fh,$want)=@_; my $buffer='';
    while (length($buffer)<$want) {
        my $n=sysread($fh,my $piece,$want-length($buffer));
        die "Descriptor read failed: $!\n" unless defined($n);
        last if $n==0;
        $buffer.=$piece;
    }
    return $buffer;
}
sub bounded_call {
    my ($seconds,$label,$callback,$stage_ref)=@_;
    my $timed_out=0;
    local $SIG{ALRM}=sub {$timed_out=1;die "$label timed out\n"};
    alarm($seconds);
    my (@result,$error);
    my $ok=eval {@result=$callback->();1};
    $error=$@ unless $ok;
    alarm(0);
    return ($ok?1:0,\@result,$error,$timed_out,($stage_ref?$$stage_ref:undef));
}
sub hash_file {
    my ($path)=@_;
    local $SIG{ALRM}=sub {die "Mounted file read timed out\n"};alarm($timeout);
    sysopen(my $fh,$path,O_RDONLY|O_NOFOLLOW) or die "Cannot open mounted file: $!\n";
    binmode($fh);my @before=stat($fh);
    die "Mounted path is not a regular file\n" unless @before && S_ISREG($before[2]);
    my $hash=Digest::SHA->new(256);my $bytes=0;
    while (1) {
        my $n=sysread($fh,my $buffer,1024*1024);
        die "Mounted file read failed: $!\n" unless defined($n);
        last unless $n;
        $bytes+=$n;$hash->add($buffer);
    }
    my @after=stat($fh);close($fh) or die "Mounted file close failed: $!\n";alarm(0);
    die "Mounted file changed during checksum\n" unless @after && $before[7]==$after[7] && $before[9]==$after[9] && $bytes==$after[7];
    return {bytes=>$bytes,sha256=>$hash->hexdigest};
}
sub wait_for_replacement {
    my ($path,$old_prefix,$new_prefix,$fixture)=@_;my $deadline=time+$timeout;
    my $next_log=time+5;
    my $next_report=time+15;
    $replacement_poll->{startedAt}=time;
    $replacement_poll->{oldPrefixSHA256}=Digest::SHA::sha256_hex($old_prefix);
    $replacement_poll->{newPrefixSHA256}=Digest::SHA::sha256_hex($new_prefix);
    while (time<$deadline) {
        $replacement_poll->{opensAttempted}++;
        my $stage='open';
        my $current_stat;
        my ($attempt_ok,$attempt_result,$attempt_error,$timed_out,$failed_stage)=
            bounded_call($poll_io_timeout,'Replacement pathname operation',sub {
                sysopen(my $fh,$path,O_RDONLY|O_NOFOLLOW) or return ({stage=>'open',error=>"$!"});
                $replacement_poll->{opensSucceeded}++;
                binmode($fh);
                $stage='stat';
                my @st=stat($fh);
                unless (@st) {
                    my $stat_error="$!";
                    $replacement_poll->{statFailures}++;
                    $stage='close';
                    unless (close($fh)) {
                        my $close_error="$!";
                        $replacement_poll->{closeFailures}++;
                        return ({stage=>'stat',error=>"stat: $stat_error; close: $close_error"});
                    }
                    return ({stage=>'stat',error=>$stat_error});
                }
                $current_stat={dev=>$st[0],inode=>$st[1],size=>$st[7]};
                $replacement_poll->{readsAttempted}++;
                $stage='read';
                my ($value,$read_error);
                my $read_ok=eval {$value=read_exact($fh,length($new_prefix));1};
                $read_error=$@ unless $read_ok;
                die $read_error if !$read_ok && $read_error =~ /timed out\n\z/;
                $stage='close';
                my $close_ok=close($fh);
                my $close_error=$close_ok ? undef : "$!";
                $replacement_poll->{closeFailures}++ unless $close_ok;
                if (!$read_ok) {
                    $replacement_poll->{readFailures}++;
                    return ({stage=>'read',error=>"$read_error",closeError=>$close_error,
                        dev=>$st[0],inode=>$st[1],size=>$st[7]});
                }
                my $classification=$value eq $new_prefix ? 'new'
                    : $value eq $old_prefix ? 'old' : 'other';
                return ({stage=>'close',closeError=>$close_error,dev=>$st[0],inode=>$st[1],size=>$st[7],
                    value=>$value,classification=>$classification});
            },\$stage);
        if (!$attempt_ok) {
            $failed_stage //= $stage;
            $replacement_poll->{openFailures}++ if $failed_stage eq 'open';
            $replacement_poll->{statFailures}++ if $failed_stage eq 'stat';
            $replacement_poll->{readFailures}++ if $failed_stage eq 'read';
            $replacement_poll->{closeFailures}++ if $failed_stage eq 'close';
            $replacement_poll->{lastError}=$attempt_error;
            $replacement_poll->{lastObserved}={observedAt=>time,%{$current_stat//{}},classification=>'operation_failed',stage=>$failed_stage,
                error=>substr($attempt_error//'',0,160)};
            die "Replacement pathname operation timed out at $failed_stage\n" if $timed_out;
        } else {
            my $observation=$attempt_result->[0];
            if ($observation->{stage} eq 'open') {
                $replacement_poll->{openFailures}++;
                $replacement_poll->{lastError}=$observation->{error};
            } elsif ($observation->{stage} eq 'stat') {
                $replacement_poll->{lastError}=$observation->{error};
                $replacement_poll->{lastObserved}={observedAt=>time,classification=>'stat_failed',error=>$observation->{error}};
            } else {
                $replacement_poll->{lastError}=$observation->{closeError} if defined $observation->{closeError};
                if ($observation->{stage} eq 'read') {
                    $replacement_poll->{lastError}=$observation->{error};
                    $replacement_poll->{lastError}.="; close: $observation->{closeError}" if defined $observation->{closeError};
                    $replacement_poll->{lastObserved}={observedAt=>time,dev=>$observation->{dev},inode=>$observation->{inode},
                        size=>$observation->{size},classification=>'read_failed',error=>substr($observation->{error}//'',0,160)};
                } else {
                    my $value=$observation->{value}//'';
                    my $classification=$observation->{classification};
                    $replacement_poll->{shortReads}++ if length($value)<length($new_prefix);
                    $replacement_poll->{observations}++;
                    $replacement_poll->{$classification eq 'old' ? 'oldPrefixCount'
                        : $classification eq 'new' ? 'newPrefixCount' : 'otherPrefixCount'}++;
                    $replacement_poll->{lastObserved}={observedAt=>time,dev=>$observation->{dev},inode=>$observation->{inode},
                        size=>$observation->{size},readBytes=>length($value),prefixSHA256=>Digest::SHA::sha256_hex($value),
                        classification=>$classification,closeFailed=>defined($observation->{closeError})?JSON::PP::true:JSON::PP::false};
                    return $replacement_poll if $classification eq 'new' && !defined($observation->{closeError});
                }
            }
        }
        if (time >= $next_log) {
            emit({event=>'replacement_poll',elapsedMs=>int((time-$replacement_poll->{startedAt})*1000),
                diagnostics=>$replacement_poll});
            $next_log=time+5;
        }
        if (time >= $next_report) {
            write_report('waiting_for_host_replace',{fixtureDetails=>$fixture,
                replacementPoll=>$replacement_poll},0);
            $next_report=time+15;
        }
        sleep(.2);
    }
    die "Timed out waiting for backend replacement at vm-source.bin; poll diagnostics: ".$json->encode($replacement_poll)."\n";
}
sub unmount {
    die "Cannot unmount a different or unsynchronized filespace\n" unless mounted(status()) && synced(status());
    rpc('unmount',{filespace=>$filespace,force=>JSON::PP::false});$unmounted=1;
    die "Daemon still reports the volume mounted\n" if defined(status()->{mountPath});
}
sub mount_again {
    my $result=rpc('mount',{filespace=>$filespace,at=>$mount,name=>'VM open lifetime validation'});
    die "Daemon mounted at an unexpected path\n" unless ($result->{mountPath}//'') eq $mount && mounted(status());
    $unmounted=0;
}
sub quiet_storage {
    my $deadline=time+30;my $previous;
    while (time<$deadline) {
        my $s=status();my $storage=$s->{storage};
        die "Object-storage telemetry unavailable\n" unless ref($storage) eq 'HASH' && defined($storage->{requests}) && defined($storage->{activeRequests});
        if ($storage->{activeRequests}==0) {
            if (defined($previous) && $storage->{requests}==$previous) {return 0+$storage->{requests};}
            $previous=$storage->{requests};
        }
        sleep(.2);
    }
    die "Object transfers did not settle\n";
}
sub cleanup_owned_fixture {
    my ($root)=@_;
    opendir(my $dir,$root) or die "Cannot inspect owned fixture before cleanup: $!\n";
    my @entries=sort grep {$_ ne '.' && $_ ne '..'} readdir($dir);
    closedir($dir) or die "Cannot close owned fixture listing: $!\n";
    my %owned=map {$_=>1} qw(vm-source.bin vm-after-edit.bin vm-nested);
    die "Owned fixture contains unexpected entries; preserving it\n"
        if grep {!$owned{$_}} @entries;
    for my $name (@entries) {
        my $path="$root/$name";
        if ($name eq 'vm-nested') {
            die "Owned nested fixture changed type; preserving it\n" if -l $path || !-d $path;
            opendir(my $nested,$path) or die "Cannot inspect nested fixture before cleanup: $!\n";
            my @children=grep {$_ ne '.' && $_ ne '..'} readdir($nested);
            closedir($nested) or die "Cannot close nested fixture listing: $!\n";
            die "Nested fixture contains unexpected entries; preserving it\n"
                if grep {$_ ne 'vm-replacement.bin' || -l "$path/$_" || !-f "$path/$_"} @children;
        } else {
            die "Owned fixture entry changed type; preserving it\n" if -l $path || !-f $path;
        }
    }
    my $removed=0;
    for my $name (@entries) {
        my $path="$root/$name";
        if ($name eq 'vm-nested') {
            opendir(my $nested,$path) or die "Cannot reopen nested fixture before cleanup: $!\n";
            my @children=grep {$_ ne '.' && $_ ne '..'} readdir($nested);
            closedir($nested) or die "Cannot close nested fixture listing: $!\n";
            for my $child (@children) {
                unlink("$path/$child") or die "Cannot remove owned nested fixture file: $!\n";
                $removed++;
            }
            rmdir($path) or die "Cannot remove empty owned nested fixture directory: $!\n";
        } else {
            unlink($path) or die "Cannot remove owned fixture file $name: $!\n";
            $removed++;
        }
    }
    rmdir($root) or die "Cannot remove empty owned fixture directory: $!\n";
    return $removed;
}

my $root;
my $success=eval {
    die "--mount must be an existing canonical directory without symlink redirection\n"
        unless -d $mount && !-l $mount && (abs_path($mount)//'') eq $mount;
    die "--socket must be a Unix socket path\n" unless -S $socket && !-l $socket;
    die "--report must not be inside the mounted volume\n" if index($report,"$mount/")==0;
    die "Report path already exists\n" if -e $report || -l $report;
    die "Report temporary path already exists\n" if -e "$report.tmp-$$" || -l "$report.tmp-$$";
    die "Filespace must begin mounted and synchronized\n" unless mounted(status()) && synced(status());

    $root="$mount/$folder_name";
    mkdir($root,0700) or die "Cannot create fresh validation folder: $!\n";
    my $source_dir="$root/vm-nested";
    mkdir($source_dir,0700) or die "Cannot create fresh nested source folder: $!\n";
    my $old_path="$root/vm-source.bin";my $replacement_path="$source_dir/vm-replacement.bin";
    my $size=8*1024*1024;
    my $old=make_payload($old_path,"OLD-$run_id-",$size);
    my $new=make_payload($replacement_path,"NEW-$run_id-",$size);
    flush_filespace();
    # Keep both names' vnodes warm before the host commits its backend rename.
    # The target descriptor is writable so the post-replacement check covers
    # continued writes to the displaced inode as well as reads.
    my $target_access=$read_only_target?O_RDONLY:O_RDWR;
    sysopen($held,$old_path,$target_access|O_NOFOLLOW) or die "Cannot hold old target descriptor: $!\n";
    binmode($held);
    my $prefix=read_exact($held,4096);
    die "Initial source descriptor prefix mismatch\n" unless $prefix eq substr(("OLD-$run_id-" x 410),0,4096);
    sysopen($source_held,$replacement_path,O_RDONLY|O_NOFOLLOW)
        or die "Cannot hold replacement source descriptor: $!\n";
    binmode($source_held);
    my $source_prefix=read_exact($source_held,4096);
    die "Initial replacement source descriptor prefix mismatch\n"
        unless $source_prefix eq substr(("NEW-$run_id-" x 410),0,4096);
    my @old_identity_before=stat($held);
    my @source_identity_before=stat($source_held);
    die "Could not capture initial descriptor identities\n"
        unless @old_identity_before && @source_identity_before;
    my $fixture={folder=>$folder_name,sourceFile=>$old,replacementFile=>$new,
        sourceDirectory=>"$folder_name/vm-nested",
        replaceTargetPath=>"$folder_name/vm-source.bin",replaceSourcePath=>"$folder_name/vm-nested/vm-replacement.bin"};
    $fixture_details=$fixture;
    write_report('waiting_for_host_replace',{fixtureDetails=>$fixture,
        replacementPoll=>$replacement_poll});
    my $held_access=$read_only_target
        ? 'read-only descriptors to both original vnodes'
        : 'a read/write target descriptor and a read-only source descriptor';
    emit({event=>'ready',filespace=>$filespace,%$fixture,
        action=>"Move vm-nested/vm-replacement.bin over parent-folder vm-source.bin using the backend API and set the new parent to the reported folder; the VM is holding $held_access."});

    my $poll_result=wait_for_replacement($old_path,$old->{prefix},$new->{prefix},$fixture);
    check('backend replacement became visible at target path',1,
        {target=>$fixture->{replaceTargetPath},replacementPoll=>$poll_result});
    my $fresh_target;
    sysopen($fresh_target,$old_path,O_RDONLY|O_NOFOLLOW)
        or die "Cannot open fresh replacement target path: $!\n";
    binmode($fresh_target);
    my @fresh_identity=stat($fresh_target);
    my @old_identity_after=stat($held);
    die "Old target descriptor identity changed during replacement\n"
        unless @fresh_identity && @old_identity_after
            && $old_identity_after[0]==$old_identity_before[0]
            && $old_identity_after[1]==$old_identity_before[1];
    my $moved_identity_preserved=$fresh_identity[0]==$source_identity_before[0]
        && $fresh_identity[1]==$source_identity_before[1];
    my $displaced_identity_replaced=$fresh_identity[0]!=$old_identity_before[0]
        || $fresh_identity[1]!=$old_identity_before[1];
    check('fresh destination identity differs from displaced target', $displaced_identity_replaced,
        {displacedTarget=>{device=>$old_identity_before[0],inode=>$old_identity_before[1]},
         freshTarget=>{device=>$fresh_identity[0],inode=>$fresh_identity[1]}});
    if (!$moved_identity_preserved) {
        die "Fresh target path does not identify the moved source vnode\n"
            unless $allow_remote_presentation_id_change;
        push @compatibility_limitations,'remote presentation identity changed during replacement';
    }
    my $fresh_target_hash=hash_file($old_path);
    check('fresh target path has replacement bytes',
        $fresh_target_hash->{bytes}==$new->{bytes} && $fresh_target_hash->{sha256} eq $new->{sha256},
        {%$fresh_target_hash,expectedBytes=>$new->{bytes},expectedSHA256=>$new->{sha256},
         pathIdentityMatchesCachedSource=>$moved_identity_preserved?JSON::PP::true:JSON::PP::false,
         identityChangeAllowed=>$allow_remote_presentation_id_change?JSON::PP::true:JSON::PP::false,
         targetIdentity=>{device=>$fresh_identity[0],inode=>$fresh_identity[1]},
         sourceIdentity=>{device=>$source_identity_before[0],inode=>$source_identity_before[1]}});
    close($fresh_target) or die "Cannot close fresh replacement target descriptor: $!\n";
    my $source_absent=! -e $replacement_path && ! -l $replacement_path;
    check('replacement source pathname is absent', $source_absent,
        {source=>$fixture->{replaceSourcePath}});
    die "Replacement source path still exists after move\n" unless $source_absent;

    if ($read_only_target) {
        check('old target descriptor retains original bytes',1,
            {targetDescriptorAccess=>'read-only',writeLifetime=>'not tested'});
    } else {
        # The displaced target descriptor must remain writable on its old
        # inode; the fresh destination must continue to expose moved bytes.
        my $write_tail="OLD-HANDLE-$run_id\n";
        sysseek($held,0,2)>=0 or die "Cannot seek old target descriptor to its end: $!\n";
        my $written=syswrite($held,$write_tail);
        die "Cannot write through old target descriptor: $!\n"
            unless defined($written) && $written==length($write_tail);
        $held->sync or die "Cannot sync old target descriptor write: $!\n";
        sysseek($held,-length($write_tail),2)>=0 or die "Cannot seek old target descriptor to its appended bytes: $!\n";
        my $observed_tail=read_exact($held,length($write_tail));
        check('old target descriptor remains writable after replacement',
            $observed_tail eq $write_tail,
            {bytes=>length($observed_tail),expectedBytes=>length($write_tail),
             oldTargetIdentity=>{device=>$old_identity_after[0],inode=>$old_identity_after[1]}});
        flush_filespace();
        my $target_after_old_write=hash_file($old_path);
        check('old target write does not alter fresh destination',
            $target_after_old_write->{bytes}==$new->{bytes}
                && $target_after_old_write->{sha256} eq $new->{sha256},
            {%$target_after_old_write,expectedBytes=>$new->{bytes},expectedSHA256=>$new->{sha256}});
    }

    my $source_descriptor_prefix=do { sysseek($source_held,0,0); read_exact($source_held,4096) };
    check('cached source descriptor retains moved source bytes',
        $source_descriptor_prefix eq $source_prefix,
        {bytes=>length($source_descriptor_prefix),expectedBytes=>length($source_prefix),
         sourceIdentity=>{device=>$source_identity_before[0],inode=>$source_identity_before[1]}});
    close($source_held) or die "Cannot close cached source descriptor: $!\n";
    $source_held=undef;

    # Reuse the consumed source name and ensure a fresh lookup sees this new
    # file while the destination remains attached to the moved source inode.
    my $reused=make_payload($replacement_path,"REUSE-$run_id-",64*1024);
    $fixture->{reusedSourceNameFile}=$reused;
    flush_filespace();
    my $reused_path_hash=hash_file($replacement_path);
    my $destination_after_reuse=hash_file($old_path);
    my $reused_stat=(stat($replacement_path))[1];
    my $destination_stat=(stat($old_path))[1];
    check('reused source name resolves to a distinct fresh file',
        $reused_path_hash->{bytes}==$reused->{bytes}
            && $reused_path_hash->{sha256} eq $reused->{sha256}
            && defined($reused_stat) && defined($destination_stat) && $reused_stat!=$destination_stat,
        {%$reused_path_hash,expectedBytes=>$reused->{bytes},expectedSHA256=>$reused->{sha256},
         reusedInode=>$reused_stat,destinationInode=>$destination_stat});
    check('destination survives source-name reuse',
        $destination_after_reuse->{bytes}==$new->{bytes}
            && $destination_after_reuse->{sha256} eq $new->{sha256},
        {%$destination_after_reuse,expectedBytes=>$new->{bytes},expectedSHA256=>$new->{sha256}});
    $fixture->{replacementIdentity}={device=>$source_identity_before[0],inode=>$source_identity_before[1]};
    my $tail_length=65536;my $tail_offset=$size-$tail_length;
    sysseek($held,$tail_offset,0)==$tail_offset or die "Cannot seek held descriptor to old payload tail\n";
    my $tail=read_exact($held,$tail_length);
    my $old_tail=substr(("OLD-$run_id-" x int(($tail_offset+$tail_length+length("OLD-$run_id-")-1)/length("OLD-$run_id-"))),$tail_offset,$tail_length);
    my $first_difference;
    for (my $i=0;$i<length($tail) && $i<length($old_tail);$i++) {
        if (substr($tail,$i,1) ne substr($old_tail,$i,1)) {$first_difference=$i;last;}
    }
    check('already-open descriptor retained old inode tail',length($tail)==$tail_length && $tail eq $old_tail,
        {tailBytes=>length($tail),oldFileBytes=>$size,actualTailSHA256=>Digest::SHA::sha256_hex($tail),
         expectedTailSHA256=>Digest::SHA::sha256_hex($old_tail),firstDifferingOffset=>$first_difference,
         actualPrefix=>substr($tail,0,64),expectedPrefix=>substr($old_tail,0,64)});
    close($held) or die "Cannot close held descriptor: $!\n";$held=undef;

    my $post_path="$root/vm-after-edit.bin";
    my $post_edit=make_payload($post_path,"POST-$run_id-",64*1024);
    flush_filespace();
    $fixture->{postEditFile}=$post_edit;
    check('guest can write and flush after host replacement',1,{name=>$post_edit->{name},bytes=>$post_edit->{bytes},sha256=>$post_edit->{sha256}});
    my $unchanged_inode_before=(stat("$root/$post_edit->{name}"))[1];
    die "Cannot capture unchanged file identity before remount\n" unless defined($unchanged_inode_before);


    unmount();
    my $cleared=rpc('cache.clear',{filespace=>$filespace});
    check('cold phase starts with empty guest cache',defined($cleared->{usedBytes}) && $cleared->{usedBytes}==0
        && defined($cleared->{pinnedBytes}) && $cleared->{pinnedBytes}==0,
        {usedBytes=>$cleared->{usedBytes},pinnedBytes=>$cleared->{pinnedBytes}});
    mount_again();
    my $cold_before=quiet_storage();
    my $cold=hash_file($old_path);
    my $cold_post=hash_file($post_path);
    my $cold_after=quiet_storage();
    check('cold remount reads replacement bytes exactly',
        $cold->{bytes}==$new->{bytes} && $cold->{sha256} eq $new->{sha256},
        {%$cold,expectedBytes=>$new->{bytes},expectedSHA256=>$new->{sha256}});
    check('cold remount reads post-edit guest write exactly',
        $cold_post->{bytes}==$post_edit->{bytes} && $cold_post->{sha256} eq $post_edit->{sha256},
        {%$cold_post,expectedBytes=>$post_edit->{bytes},expectedSHA256=>$post_edit->{sha256}});
    my $unchanged_inode_cold=(stat("$root/$post_edit->{name}"))[1];
    check('unchanged file keeps its identity on the cold remount',
        defined($unchanged_inode_cold) && $unchanged_inode_cold==$unchanged_inode_before,
        {before=>"$unchanged_inode_before",after=>defined($unchanged_inode_cold)?"$unchanged_inode_cold":undef});
    check('cold remount fetched replacement objects',$cold_after>$cold_before,
        {beforeRequests=>$cold_before,afterRequests=>$cold_after,additionalRequests=>$cold_after-$cold_before});

    unmount();mount_again();
    my $warm_before=quiet_storage();
    my $warm=hash_file($old_path);
    my $warm_post=hash_file($post_path);
    my $warm_after=quiet_storage();
    check('warm remount reads replacement bytes exactly',
        $warm->{bytes}==$new->{bytes} && $warm->{sha256} eq $new->{sha256},
        {%$warm,expectedBytes=>$new->{bytes},expectedSHA256=>$new->{sha256}});
    check('warm remount reads post-edit guest write exactly',
        $warm_post->{bytes}==$post_edit->{bytes} && $warm_post->{sha256} eq $post_edit->{sha256},
        {%$warm_post,expectedBytes=>$post_edit->{bytes},expectedSHA256=>$post_edit->{sha256}});
    my $unchanged_inode_after=(stat("$root/$post_edit->{name}"))[1];
    check('unchanged file keeps its identity across cold and warm remounts',
        defined($unchanged_inode_after) && $unchanged_inode_after==$unchanged_inode_before,
        {before=>"$unchanged_inode_before",after=>defined($unchanged_inode_after)?"$unchanged_inode_after":undef});
    check('warm remount reused persisted cache',$warm_after==$warm_before,
        {beforeRequests=>$warm_before,afterRequests=>$warm_after,additionalRequests=>$warm_after-$warm_before});
    flush_filespace();
    my $removed=cleanup_owned_fixture($root);
    flush_filespace();
    $fixture->{cleanup}={removedOwnedFiles=>$removed,folderRemoved=>JSON::PP::true};
    check('exact owned fixture cleanup completed',1,$fixture->{cleanup});
    write_report('complete',{fixtureDetails=>$fixture,replacementPoll=>$replacement_poll,
        targetDescriptorAccess=>$read_only_target?'read-only':'read-write',
        targetWriteLifetime=>$read_only_target?'not tested':'passed',
        coldRequestsBefore=>$cold_before,coldRequestsAfter=>$cold_after,
        warmRequestsBefore=>$warm_before,warmRequestsAfter=>$warm_after});
    emit({result=>@compatibility_limitations?'PASS_WITH_LIMITATIONS':'PASS',report=>$report,
        compatibilityLimitations=>\@compatibility_limitations,fixture=>$folder_name,checks=>scalar(@checks)});
    1;
};

if (!$success) {
    my $error=$@ || 'Validation failed';
    if ($held) {close($held);$held=undef;}
    if ($source_held) {close($source_held);$source_held=undef;}
    my $restored=1;
    if ($unmounted) {$restored=eval {mount_again();1}?1:0;}
    my $cleanup;
    if ($root && -d $root && !$unmounted) {
        my $removed=eval {cleanup_owned_fixture($root)};
        $cleanup=defined($removed)
            ? {result=>'removed',files=>$removed,folderRemoved=>JSON::PP::true}
            : {result=>'preserved',reason=>substr($@ || 'cleanup failed',0,160)};
    }
    eval {write_report('failed',{error=>substr($error,0,400),mountRestored=>$restored,
        fixtureDetails=>$fixture_details,replacementPoll=>$replacement_poll,
        (defined($cleanup)?(fixtureCleanup=>$cleanup):())});};
    emit({result=>'FAIL',error=>substr($error,0,400),mountRestored=>$restored,
        (defined($cleanup)?(fixtureCleanup=>$cleanup):()),report=>$report});
    exit 1;
}
exit 0;
