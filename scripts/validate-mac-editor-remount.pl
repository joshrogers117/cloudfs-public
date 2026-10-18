#!/usr/bin/perl
# SPDX-License-Identifier: AGPL-3.0-or-later
# Disposable macOS VM only. No credentials are read, and no apps are controlled.
# Example: perl validate-mac-editor-remount.pl --resolve-report resolve-build31.json \
#   --premiere-report premiere-build31.json --build 32 --run-id build32-UNIQUE \
#   --confirm-disposable-vm
# Alternatively --manifest FILE accepts {"fixture":"cloudfs-editor-validation-20261015",
# "files":[{"kind":"...","name":"basename.mov","bytes":123,"sha256":"..."}, ...]}.
# Exactly one MOV, DRP and PRPROJ are required. --plan prints this portable manifest.
use strict;
use warnings;
use JSON::PP;
use Digest::SHA;
use IO::Socket::UNIX;
use IO::Handle;
use Getopt::Long qw(GetOptions);
use Cwd qw(abs_path);
use Fcntl qw(O_RDONLY O_WRONLY O_CREAT O_EXCL O_NOFOLLOW S_ISREG);
use Time::HiRes qw(time sleep);

$|=1;
my ($resolve_report,$premiere_report,$manifest,$run_id,$build,$plan,$self_test,$confirmed,$premiere_name);
my $timeout=180;
GetOptions('resolve-report=s'=>\$resolve_report,'premiere-report=s'=>\$premiere_report,
    'manifest=s'=>\$manifest,
    'run-id=s'=>\$run_id,'build=i'=>\$build,'timeout=i'=>\$timeout,
    'premiere-name=s'=>\$premiere_name,'confirm-disposable-vm'=>\$confirmed,
    'plan'=>\$plan,'self-test'=>\$self_test) or die "Invalid options\n";
my $json=JSON::PP->new->canonical;
my $home=$ENV{HOME} // die "HOME is required\n";
my $mount="$home/cloudfs/edit1";
my $fixture_name='cloudfs-editor-validation-20261015';
my $root="$mount/$fixture_name";
my $socket="$home/Library/Application Support/cloudfs/d.sock";
my (@checks,$run,$claimed,$unmounted,$initial,$fixtures,$installed_build);
my $started=time;

sub emit { print $json->encode($_[0]),"\n"; }
sub check {
    my ($name,$ok,$details)=@_;
    push @checks,{name=>$name,pass=>$ok?JSON::PP::true:JSON::PP::false,details=>$details};
    emit({event=>'check',%{$checks[-1]}});
    die "Check failed: $name\n" unless $ok;
}
sub simple_name {
    my ($name)=@_;
    die "Invalid fixture filename\n" unless defined($name) && !ref($name) && length($name)>0
        && length($name)<=255 && $name ne '.' && $name ne '..' && $name !~ m{[/\\\x00-\x1f\x7f]};
    return $name;
}
sub expected_file {
    my ($kind,$name,$entry)=@_;
    simple_name($name);
    die "Invalid $kind expected checksum or size\n" unless ref($entry) eq 'HASH'
        && ($entry->{sha256}//'') =~ /^[0-9a-f]{64}$/ && defined($entry->{bytes})
        && !ref($entry->{bytes}) && "$entry->{bytes}" =~ /^[1-9][0-9]*$/ && $entry->{bytes}<2**40;
    return {kind=>$kind,name=>$name,bytes=>0+$entry->{bytes},sha256=>$entry->{sha256}};
}
sub fixtures_from_reports {
    my ($resolve,$premiere,$override)=@_;
    die "Both input reports must have result PASS\n" unless ref($resolve) eq 'HASH' && ref($premiere) eq 'HASH'
        && ($resolve->{result}//'') eq 'PASS' && ($premiere->{result}//'') eq 'PASS';
    my $render=$resolve->{checks}{renderToCloudAndProbe};
    die "Missing Resolve rendered-path evidence\n" unless ref($render) eq 'HASH' && defined($resolve->{root})
        && !ref($resolve->{root}) && $resolve->{root} =~ m{/\Q$fixture_name\E$}
        && index($render->{path}//'',"$resolve->{root}/")==0;
    my $mov=substr($render->{path},length($resolve->{root})+1);
    my $project=$resolve->{createdProjects}[0];
    die "Missing original Resolve project name\n" unless defined($project) && !ref($project);
    $project =~ s/ /-/g;
    my $drp="$project.drp";
    # The build31 Premiere report records checksum/size but no path. This is the
    # basename recorded by premiere-baseline27.json for the reopened same project.
    my $premiere_file=$override // 'CloudFS Editing Validation.prproj';
    return [expected_file('Resolve rendered MOV',$mov,$render),
        expected_file('Resolve exported DRP',$drp,$resolve->{checks}{exportProjectToMountedVolume}),
        expected_file('Premiere saved project',$premiere_file,$premiere)];
}
sub fixtures_from_manifest {
    my ($input)=@_;
    die "Invalid editor manifest\n" unless ref($input) eq 'HASH' && ($input->{fixture}//'') eq $fixture_name
        && ref($input->{files}) eq 'ARRAY' && @{$input->{files}}==3;
    my (@files,%extensions,%names);
    for my $file (@{$input->{files}}) {
        die "Invalid editor manifest entry\n" unless ref($file) eq 'HASH' && defined($file->{kind}) && !ref($file->{kind});
        my $parsed=expected_file($file->{kind},$file->{name},$file);
        die "Manifest must contain one MOV, DRP and PRPROJ\n" unless $parsed->{name} =~ /\.(mov|drp|prproj)$/i;
        die "Duplicate manifest type or filename\n" if $extensions{lc($1)}++ || $names{$parsed->{name}}++;
        push @files,$parsed;
    }
    return \@files;
}
sub synced {
    my ($status)=@_;
    return ref($status) eq 'HASH' && defined($status->{pendingUploads}) && defined($status->{pendingBytes})
        && $status->{pendingUploads}==0 && $status->{pendingBytes}==0;
}
sub counter {
    my ($status)=@_;
    die "Object-request telemetry is unavailable\n" unless ref($status->{storage}) eq 'HASH'
        && defined($status->{storage}{requests}) && "$status->{storage}{requests}" =~ /^[0-9]+$/
        && defined($status->{storage}{activeRequests});
    return 0+$status->{storage}{requests};
}
sub delta {
    my ($before,$after)=@_;
    die "Object-request counter reset; cannot prove cache reuse\n" if $after<$before;
    return $after-$before;
}

if ($self_test) {
    my $n=0;
    for my $name ('../file','a/b','a\\b','.',"bad\nname") {
        die "Unsafe name accepted\n" if eval {simple_name($name);1}; ++$n;
    }
    die "Valid name rejected\n" unless simple_name('CloudFS Editing Validation.prproj'); ++$n;
    die "Pending writes accepted\n" if synced({pendingUploads=>1,pendingBytes=>0}); ++$n;
    die "Missing pending-write telemetry accepted\n" if synced({}); ++$n;
    die "Synchronized status rejected\n" unless synced({pendingUploads=>0,pendingBytes=>0}); ++$n;
    die "Counter reset accepted\n" if eval {delta(5,0);1}; ++$n;
    die "Counter delta wrong\n" unless delta(5,8)==3; ++$n;
    my $entry={bytes=>1,sha256=>'a'x64};
    my $example={result=>'PASS',root=>"/Users/example-user/cloudfs/edit1/$fixture_name",createdProjects=>['Project One'],
        checks=>{renderToCloudAndProbe=>{%$entry,path=>"/Users/example-user/cloudfs/edit1/$fixture_name/render.mov"},exportProjectToMountedVolume=>$entry}};
    my $parsed=fixtures_from_reports($example,{result=>'PASS',%$entry},undef);
    die "Incorrect fixture mapping\n" unless $parsed->[1]{name} eq 'Project-One.drp' && $parsed->[2]{name} eq 'CloudFS Editing Validation.prproj'; ++$n;
    die "Portable manifest rejected\n" unless @{fixtures_from_manifest({fixture=>$fixture_name,files=>$parsed})}==3; ++$n;
    die "Foreign fixture manifest accepted\n" if eval {fixtures_from_manifest({fixture=>'outside',files=>$parsed});1}; ++$n;
    die "Invalid checksum accepted\n" if eval {expected_file('test','test',{bytes=>1,sha256=>'invalid'});1}; ++$n;
    emit({result=>'PASS',checks=>$n,scope=>'Pure validation self-test; no filesystem, credentials, RPC or network operations'});
    exit 0;
}

sub read_json {
    my ($path)=@_;
    open my $f,'<:raw',$path or die "Cannot read input report: $!\n";
    local $/;my $bytes=<$f>;close $f or die "Cannot close input report: $!\n";
    return $json->decode($bytes);
}
die "Use (--manifest FILE | --resolve-report FILE --premiere-report FILE) --build N --run-id UNIQUE_ID --confirm-disposable-vm\n"
    unless ((defined($manifest) && !defined($resolve_report) && !defined($premiere_report))
        || (!defined($manifest) && defined($resolve_report) && defined($premiere_report))) && defined($build) && $build>0
        && defined($run_id) && $run_id =~ /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/ && $timeout>=30 && $timeout<=600;
$fixtures=defined($manifest) ? fixtures_from_manifest(read_json($manifest))
    : fixtures_from_reports(read_json($resolve_report),read_json($premiere_report),$premiere_name);
$run="$root/postupdate-$run_id";
if ($plan) {
    emit({result=>'PLAN',build=>$build,runId=>$run_id,requiredUser=>'cloudfs',requiredVirtualMachine=>JSON::PP::true,
        mount=>$mount,fixture=>$root,report=>"$run/report.json",expectedFiles=>$fixtures,
        manifest=>{fixture=>$fixture_name,files=>$fixtures},
        sequence=>['Require mounted Edit1, zero pending writes, no pins, guest-owned cache and adequate cache budget.',
            'Gracefully unmount, clear evictable guest cache, prove cache is empty, and remount at the same path.',
            'SHA-256 and byte-count all three editor artifacts; require object reads during the cold phase.',
            'Gracefully unmount/remount without clearing; rehash all three; require zero additional object requests.',
            'Create one new postupdate-RUN_ID folder, write/checksum/fsync a probe, flush, then write/fsync/flush report.json.'],
        counterMeaning=>'storage.requests counts all object-store HTTP requests; zero additional requests is stronger than zero additional GETs. Gateway metadata requests are separate.',
        limits=>['Run only in the disposable VM while editing apps and Finder previews are idle.',
            'Checks bytes/cache/remount persistence; does not itself install/update the app or prove editing-app behavior.',
            'cache.clear covers only guest Edit1 cache. Flush is filespace-wide; start and remain free of unrelated writes.']});
    exit 0;
}

$SIG{ALRM}=sub {die "Operation timed out\n"};
$SIG{TERM}=$SIG{INT}=sub {die "Interrupted\n"};
sub rpc {
    my ($method,$params)=@_;
    alarm($timeout+5);
    my $s=IO::Socket::UNIX->new(Peer=>$socket) or die "Cannot connect to guest daemon: $!\n";
    print $s $json->encode({jsonrpc=>'2.0',id=>1,method=>$method,params=>$params//{filespace=>'edit1'}}),"\n"
        or die "RPC write failed: $!\n";
    my $line=<$s>;close $s;alarm(0);
    die "Daemon closed RPC\n" unless defined($line);
    my $reply=$json->decode($line);
    die "Daemon $method failed (code ".($reply->{error}{code}//'unknown').")\n" if $reply->{error};
    return $reply->{result};
}
sub status { return rpc('status'); }
sub quiet {
    my ($phase)=@_;
    my $until=time+$timeout;
    my ($last,$stable_since);
    while (time<$until) {
        my $status=status();
        die "Unrelated or pending writes during $phase\n" unless synced($status);
        my $requests=counter($status);
        if ($status->{storage}{activeRequests}==0 && defined($last) && $requests==$last) {
            $stable_since//=time;
            return $status if time-$stable_since>=2;
        } else {undef $stable_since;}
        $last=$requests;sleep .2;
    }
    die "Object transfers did not settle during $phase\n";
}
sub mounted {
    my ($status)=@_;
    return ($status->{connection}//'') eq 'connected' && ($status->{mountPath}//'') eq $mount;
}
sub unmount {
    die "Cannot unmount a different or unsynchronized volume\n" unless mounted(status()) && synced(status());
    rpc('unmount',{filespace=>'edit1',force=>JSON::PP::false});$unmounted=1;
    die "Volume is still mounted\n" if defined(status()->{mountPath});
}
sub remount {
    my $result=rpc('mount',{filespace=>'edit1',at=>$mount});
    die "Unexpected remount location\n" unless ($result->{mountPath}//'') eq $mount && mounted(status());
    $unmounted=0;
    die "Fixture missing or redirected after remount\n" unless -d $root && !-l $root && (abs_path($root)//'') eq $root;
}
sub hash_file {
    my ($path)=@_;
    alarm($timeout);
    sysopen(my $f,$path,O_RDONLY|O_NOFOLLOW) or die "Cannot open fixture for hashing: $!\n";
    binmode($f);
    my @before=stat($f);
    die "Fixture is not a regular file\n" unless @before && S_ISREG($before[2]);
    my $hash=Digest::SHA->new(256);
    my $bytes=0;
    while (1) {
        my $n=read($f,my $buffer,1024*1024);
        die "Fixture read failed: $!\n" unless defined($n);
        last unless $n;
        $bytes+=$n;$hash->add($buffer);
    }
    my @after=stat($f);close($f) or die "Fixture close failed: $!\n";alarm(0);
    die "Fixture changed during hashing\n" unless @after && $before[7]==$after[7] && $before[9]==$after[9] && $bytes==$after[7];
    return {bytes=>$bytes,sha256=>$hash->hexdigest};
}
sub verify_artifacts {
    my ($phase)=@_;
    my @results;
    for my $file (@$fixtures) {
        my $began=time;
        my $actual=hash_file("$root/$file->{name}");
        my $details={name=>$file->{name},%$actual,elapsedMs=>int((time-$began)*1000)};
        check("$phase $file->{kind}",$actual->{sha256} eq $file->{sha256} && $actual->{bytes}==$file->{bytes},$details);
        push @results,$details;
    }
    return \@results;
}
sub write_owned {
    my ($name,$bytes)=@_;
    simple_name($name);
    die "Run folder has not been claimed\n" unless $claimed && -d $run && !-l $run && (abs_path($run)//'') eq $run;
    alarm($timeout);
    sysopen(my $f,"$run/$name",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600) or die "Cannot create fresh owned output: $!\n";
    binmode($f);print $f $bytes or die "Output write failed: $!\n";
    $f->sync or die "Output fsync failed: $!\n";
    close($f) or die "Output close failed: $!\n";alarm(0);
}
sub flush {
    my $sync=rpc('flush',{filespace=>'edit1',path=>'/',wait=>JSON::PP::true,timeoutMs=>$timeout*1000});
    die "Flush did not reach in-sync state\n" unless $sync->{inSync} && synced($sync);
    die "Pending writes remain after flush\n" unless synced(status());
    return $sync;
}
sub report {
    my ($result,$error)=@_;
    return {result=>$result,build=>$build,runId=>$run_id,elapsedMs=>int((time-$started)*1000),fixture=>$fixture_name,
        installedBundleBuild=>$installed_build,
        expectedFiles=>$fixtures,checks=>\@checks,reportPath=>"$run/report.json",error=>$error,
        scope=>'Disposable cloudfs VM only; original editor artifacts read-only. New writes confined to this run folder.',
        objectCounterMeaning=>'Total object-store requests; unchanged count proves no new object GETs or PUTs during the warm phase.',
        appUpdateLimitation=>'The caller performs installation and browser sign-in before this script; this checks the resulting mounted filesystem.'};
}

my $success=eval {
    die "Only an explicitly confirmed disposable cloudfs VM may run this script\n" unless $confirmed
        && $^O eq 'darwin' && (getpwuid($<)//'') eq 'cloudfs' && ($ENV{HOME}//'') eq $home;
    open my $model_pipe,'-|','/usr/sbin/sysctl','-n','hw.model' or die "Cannot verify VM model\n";
    my $model=<$model_pipe>//'';close($model_pipe) or die "Cannot verify VM model\n";
    chomp($model);die "Refusing a physical Mac\n" unless $model =~ /(?:VirtualMac|Parallels|Virtual)/i;
    for my $input ($0,grep {defined} ($manifest,$resolve_report,$premiere_report)) {
        die "Copy the script and input reports locally before unmounting\n" if index(abs_path($input)//'',"$mount/")==0;
    }
    open my $build_pipe,'-|','/usr/libexec/PlistBuddy','-c','Print :CFBundleVersion','/Applications/CloudFS.app/Contents/Info.plist'
        or die "Cannot verify installed CloudFS build\n";
    $installed_build=<$build_pipe>//'';close($build_pipe) or die "Cannot read installed CloudFS build\n";
    chomp($installed_build);
    check('expected CloudFS app build is installed',$installed_build eq "$build",{expected=>$build,installed=>$installed_build});
    die "Approved fixture must exist without symlink redirection\n" unless -d $root && !-l $root && (abs_path($root)//'') eq $root;
    die "Run ID already exists; choose a fresh ID\n" if -e $run || -l $run;
    $initial=status();
    check('guest begins mounted and synchronized',mounted($initial) && synced($initial),{model=>$model,mountPath=>$initial->{mountPath}});
    my $cache=rpc('cache.info');
    my $cache_path=abs_path($cache->{location}//'')//'';
    my $expected_bytes=0;$expected_bytes+=$_->{bytes} for @$fixtures;
    check('cache is guest-owned, unpinned and large enough',index($cache_path,"$home/")==0
        && defined($cache->{pinnedBytes}) && $cache->{pinnedBytes}==0
        && ($cache->{maxBytes}//0)>=$expected_bytes*2,{location=>$cache_path,pinnedBytes=>$cache->{pinnedBytes},maxBytes=>$cache->{maxBytes},fixtureBytes=>$expected_bytes});
    quiet('initial quiescence');
    unmount();
    my $cleared=rpc('cache.clear');
    check('unmounted guest cache is empty',defined($cleared->{usedBytes}) && $cleared->{usedBytes}==0 && ($cleared->{pinnedBytes}//-1)==0,
        {usedBytes=>$cleared->{usedBytes},pinnedBytes=>$cleared->{pinnedBytes}});
    remount();
    my $cold_before=counter(quiet('before cold read'));
    verify_artifacts('cold');
    my $cold_after=counter(quiet('after cold read'));
    check('cold phase fetched objects',delta($cold_before,$cold_after)>0,{beforeRequests=>$cold_before,afterRequests=>$cold_after,additionalObjectRequests=>delta($cold_before,$cold_after)});
    my $warm_before=$cold_after;
    unmount();remount();
    verify_artifacts('warm remount');
    my $warm_after=counter(quiet('after warm remount read'));
    check('warm remount reads use persisted cache without object requests',delta($warm_before,$warm_after)==0,
        {beforeRequests=>$warm_before,afterRequests=>$warm_after,additionalObjectRequests=>delta($warm_before,$warm_after)});
    die "Unrelated pending writes appeared before owned output\n" unless synced(status());
    mkdir($run,0700) or die "Cannot claim fresh run directory: $!\n";$claimed=1;
    my $probe=("CloudFS post-update guest validation $run_id build $build\n".pack('C*',0..255)) x 257;
    write_owned('guest-write-probe.bin',$probe);
    my $sync=flush();
    my $written=hash_file("$run/guest-write-probe.bin");
    check('guest writes fsync and flush through the live backend',$written->{sha256} eq Digest::SHA::sha256_hex($probe) && $written->{bytes}==length($probe),
        {%$written,inSync=>$sync->{inSync},pendingUploads=>$sync->{pendingUploads},pendingBytes=>$sync->{pendingBytes}});
    my $final=report('PASS',undef);
    write_owned('report.json',$json->encode($final)."\n");
    flush();
    emit({event=>'finished',result=>'PASS',report=>"$run/report.json",reportFlushed=>JSON::PP::true,checks=>scalar(@checks)});
    1;
};
if (!$success) {
    my $error=$@||'Unknown failure';alarm(0);$error =~ s/[\r\n]+/ /g;
    # Restore only the mount this script successfully unmounted. Never force an
    # unmount, stop a daemon, modify credentials, or clear another cache.
    my $restored;
    if ($unmounted) {$restored=eval {my $s=status();die "A different mount is now active\n" if defined($s->{mountPath});remount();1}?JSON::PP::true:JSON::PP::false;}
    my $failure=report('FAIL',substr($error,0,400));$failure->{mountRestored}=$restored if defined($restored);
    if ($claimed && -d $run) {eval {write_owned('failure-report.json',$json->encode($failure)."\n");flush();};}
    emit({event=>'finished',%$failure});exit 1;
}
exit 0;
