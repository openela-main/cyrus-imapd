%define scmt(l:) %(c=%1; echo ${c:0:%{-l:%{-l*}}%{!-l:7}})

# Cassandane commit hash.  Cassandane doesn't have releases often, but it
# receives constant development.  This was fetched on 20180518.
%global cocas 693da6118c0faa9ff1515c615c88be150c3e36c9
%global cocas_short %(echo %{cocas} | cut -c -8)

%global testdata_commit ca669d4b76c71cbeb4fa840e263e2c031e19ea88
%global testdata_short %(echo %{testdata_commit} | cut -c -8)


# Cassandane run by default.  '--without cassandane' disables.
%bcond_without cassandane

Name: cyrus-imapd
Version: 3.4.1
Release: 7%{?dist}


%define ssl_pem_file_prefix /etc/pki/%name/%name

# UID/GID 76 have long been reserved for Cyrus
%define uid 76
%define gid 76

%define cyrususer cyrus
%define cyrusgroup mail
%define cyrexecdir %_libexecdir/%name

%global __provides_exclude ^perl\\(AnnotateInlinedCIDs\\)$

Summary: A high-performance email, contacts and calendar server
License: BSD
URL: http://www.cyrusimap.org/

Source0: https://github.com/cyrusimap/cyrus-imapd/releases/download/cyrus-imapd-%version/cyrus-imapd-%version.tar.gz
# This sources were generated from the cyrus-imapd sources using Fedora machine
# This dirty hack has been introduced to avoid bringing of additional heavy packages into RHEL just for manpage generation
Source1: cyrus-manpages-3.2.6.tar.gz

# Adapt a timeout to handle our slower builders
Patch0: patch-cyrus-testsuite-timeout

# Fedora-specific patch for the default configuration file
Patch1: patch-cyrus-default-configs

# We rename quota to cyr_quota to avoid a conflict with /usr/bin/quota; one
# place in the source must be patched to match.
Patch2: patch-cyrus-rename-quota


# Workaround for some compiled Perl modules not being linked against
# libpcreposix, which causes them to fail to load.
# https://bugzilla.redhat.com/show_bug.cgi?id=1668723
# https://github.com/cyrusimap/cyrus-imapd/issues/2629#issuecomment-456925909
Patch4: patch-cyrus-perl-linking

Patch5: cyrus-imapd-CVE-2021-33582.patch
Patch6: fix-broken-delivery-to-shared-mailboxes.patch
# https://github.com/cyrusimap/cyrus-imapd/pull/3892
Patch7: cyrus-imapd-squatter-assert-crash.patch

Source10: cyrus-imapd.logrotate
Source11: cyrus-imapd.pam-config
Source12: cyrus-imapd.sysconfig
Source13: cyrus-imapd.magic
# XXX A systemd timer would probably be better
Source14: cyrus-imapd.cron-daily
Source15: README.rpm
Source16: cyrus-imapd.service
Source17: cyrus-imapd-init.service
Source18: cyrus-imapd.tmpfiles.conf

# Source files for running the Cassandane test suite at build time.
Source80: https://github.com/cyrusimap/cassandane/archive/%cocas/cassandane-${cocas_short}.tar.gz#/cassandane-%{scmt %cocas}.tar.gz
Source81: https://github.com/brong/Net-CalDAVTalk/archive/%{testdata_commit}/cassandane-testdata-%{testdata_short}.tar.gz

# A template config file for cassandane; we will substitute in varions values.
Source82: cassandane.ini

# These are source files and not patches because you can't use autosetup to
# apply patches to secondary unpacked source files.

# Prevent cassandane from trying to syslog things
Source91: patch-cassandane-no-syslog

# Tell the annotator script to run as the current user/group
# Upstream ticket https://github.com/cyrusimap/cyrus-imapd/issues/1995
Source92: patch-cassandane-fix-annotator


BuildRequires: autoconf automake bison flex gcc gcc-c++ git glibc-langpack-en
BuildRequires: groff libtool pkgconfig rsync systemd transfig

BuildRequires: perl-devel perl-generators perl(ExtUtils::MakeMaker)
BuildRequires: perl(Pod::Html)


%if 0%{?fedora} && 0%{?fedora}  >= 0
BuildRequires: clamav-devel shapelib-devel
%endif
BuildRequires: CUnit-devel cyrus-sasl-devel glib2-devel
BuildRequires: jansson-devel krb5-devel libical-devel libicu-devel
BuildRequires: libnghttp2-devel libxml2-devel mariadb-connector-c-devel net-snmp-devel
BuildRequires: openldap-devel openssl-devel libpq-devel
BuildRequires: sqlite-devel xapian-core-devel
BuildRequires: python3-sphinx

# Miscellaneous modules needed for 'make check' to function:
BuildRequires: cyrus-sasl-plain cyrus-sasl-md5

%if %{with cassandane}
# Additional packages required for cassandane to function
BuildRequires: imaptest net-tools words
BuildRequires: perl-interpreter
BuildRequires: perl(AnyEvent) perl(AnyEvent::Handle) perl(AnyEvent::Socket)
BuildRequires: perl(AnyEvent::Util) perl(attributes) perl(base)
BuildRequires: perl(BSD::Resource) perl(bytes) perl(Carp) perl(charnames)
BuildRequires: perl(Clone) perl(Config) perl(Config::IniFiles) perl(constant)
BuildRequires: perl(Cwd) perl(Data::Dumper) perl(DateTime)
BuildRequires: perl(DateTime::Format::ISO8601) perl(Digest::MD5) perl(Encode)
BuildRequires: perl(Errno) perl(experimental) perl(Exporter)
BuildRequires: perl(File::Basename) perl(File::chdir) perl(File::Find)
BuildRequires: perl(File::Path) perl(File::Slurp) perl(File::stat)
BuildRequires: perl(File::Temp) perl(Getopt::Long) perl(HTTP::Tiny)
BuildRequires: perl(IO::File) perl(IO::Handle) perl(IO::Scalar)
BuildRequires: perl(IO::Socket::INET) perl(IO::Socket::INET6)
BuildRequires: perl(IO::Socket::UNIX) perl(JSON) perl(JSON::XS) perl(lib)
BuildRequires: perl(Mail::IMAPTalk) perl(Mail::JMAPTalk) >= 0.11
BuildRequires: perl(Math::Int64) perl(MIME::Base64)
BuildRequires: perl(Net::CalDAVTalk) >= 0.12 perl(Net::CardDAVTalk) >= 0.05
BuildRequires: perl(Net::CardDAVTalk::VCard) perl(Net::DAVTalk)
BuildRequires: perl(Net::POP3) perl(Net::Server::PreForkSimple)
BuildRequires: perl(News::NNTPClient) perl(overload)
BuildRequires: perl(POSIX) perl(Scalar::Util) perl(Storable) perl(strict)
BuildRequires: perl(String::CRC32) perl(Sys::Hostname) perl(Sys::Syslog)
BuildRequires: perl(Test::Unit::Exception) perl(Test::Unit::Listener)
BuildRequires: perl(Test::Unit::Result) perl(Test::Unit::Runner)
BuildRequires: perl(Test::Unit::TestCase) perl(Test::Unit::TestRunner)
BuildRequires: perl(Time::HiRes) perl(URI) perl(URI::Escape) perl(User::pwent)
BuildRequires: perl(utf8) perl(vars) perl(warnings) perl(XML::DOM)
BuildRequires: perl(XML::Generator) perl(XML::Spice)
%if 0%{?fedora} && 0%{?fedora}  >= 0
BuildRequires: clamav-data
%endif

BuildRequires: perl(Unix::Syslog)
BuildRequires: perl(HTTP::Daemon) perl(DBI) perl(Net::LDAP::Constant)
BuildRequires: perl(Net::LDAP::Server)
BuildRequires: make

# These were only for JMAP-Tester
# perl(Moo), perl(Moose), perl(MooseX::Role::Parameterized) perl(Throwable), perl(Safe::Isa)
%endif

Requires(pre): shadow-utils
%{?systemd_requires}

Requires: %name-utils = %version-%release
Requires: file sscg
Requires: perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))

%{?perl_default_filter}

%description
The Cyrus IMAP (Internet Message Access Protocol) server provides access to
personal mail, system-wide bulletin boards, news-feeds, calendar and contacts
through the IMAP, JMAP, NNTP, CalDAV and CardDAV protocols. The Cyrus IMAP
server is a scalable enterprise groupware system designed for use from small to
large enterprise environments using technologies based on well-established Open
Standards.

A full Cyrus IMAP implementation allows a seamless mail and bulletin board
environment to be set up across one or more nodes. It differs from other IMAP
server implementations in that it is run on sealed nodes, where users are not
normally permitted to log in. The mailbox database is stored in parts of the
filesystem that are private to the Cyrus IMAP system. All user access to mail
is through software using the IMAP, IMAPS, JMAP, POP3, POP3S, KPOP, CalDAV
and/or CardDAV protocols.

The private mailbox database design gives the Cyrus IMAP server large
advantages in efficiency, scalability, and administratability. Multiple
concurrent read/write connections to the same mailbox are permitted. The server
supports access control lists on mailboxes and storage quotas on mailbox
hierarchies.


%package devel
Summary: Cyrus IMAP server development files
Requires: %name%{?_isa} = %version-%release
Requires: pkgconfig

%description devel
The %name-devel package contains header files and libraries
necessary for developing applications which use the imclient library.


%package doc-extra
Summary: Extra documentation for the Cyrus IMAP server
BuildArch: noarch

%description doc-extra
This package contains the HTML documentation for the Cyrus IMAP server, as well
as some legacy and internal documentation not useful for normal operation of
the server.


%package libs
Summary: Runtime libraries for cyrus-imapd

%description libs
The cyrus-imapd-libs package contains libraries shared by the Cyrus IMAP server
and the its utilities.


%package utils
Summary: Cyrus IMAP server administration utilities
Requires: cyrus-imapd = %{version}-%{release}

%description utils
The cyrus-imapd-utils package contains administrative tools for the
Cyrus IMAP server. It can be installed on systems other than the
one running the server.


%package virusscan
Summary: Cyrus virus scanning utility

%description virusscan
The cyrus-imapd-virusscan package contains the cyr_virusscan utility.  It
exists in a separate package so that users who do not wish to install all of
the clamav suite don't have to.

Install this package if you wish to use the internal cyrus virus scanning
utility.


%package -n perl-Cyrus
Summary: Perl libraries for interfacing with Cyrus IMAPd

%description -n perl-Cyrus
This package contains Perl libraries used to interface with Cyrus IMAPd.


%prep
%autosetup -p1
echo %version > VERSION

# Install the Fedora-specific documentation file
install -m 644 %SOURCE15 doc/

# Unpack and prepare cassandane
tar xf %SOURCE80
ln -s cassandane-%cocas cassandane
pushd cassandane
mkdir work
tar xf %SOURCE81

patch -p1 < %SOURCE91
patch -p1 < %SOURCE92

cp %SOURCE82 cassandane.ini
# RF rpm-buildroot-usage
sed -i \
    -e "s!CASSDIR!$(pwd)!" \
    -e "s!BUILDROOT!%buildroot!" \
    cassandane.ini

popd

# The pm files have shebang lines for some reason
sed -i -e '1{/usr.bin.perl/d}' perl/annotator/{Message,Daemon}.pm

# This one uses env
sed -i -e '1i#!/usr/bin/perl' -e '1d' tools/rehash

# These files have a bizarre perl-in-shell shebang setup.  The exec perl bit
# sometimes comes after a long comment block.  All use magic to turn on -w.
# Some of these aren't installed, but we might as well fix them all just in
# case.
sed -i \
    -e '1i#!/usr/bin/perl -w' \
    -e '/^exec perl/d' \
    -e '/^#!perl -w/d' \
    -e '/^#!\/bin\/sh/d' \
    -e '/^#! \/bin\/sh/d' \
    perl/sieve/scripts/installsieve.pl \
    perl/sieve/scripts/sieveshell.pl perl/imap/cyradm.sh tools/config2header \
    tools/masssievec tools/config2rst tools/mknewsgroups tools/config2sample \
    tools/mkimap tools/translatesieve


%build
# This is the test suite, which doesn't build much but does verify its dependencies.
# If this is done after the configure call, the one thing it does build fails
# because the configure macro puts some hardening flags into the environment.
%if %{with cassandane}
pushd cassandane
export NOCYRUS=1
make
popd
%endif

# Notes about configure options:
# --enable-objectstore
#   It's experimental, and it doesn't appear that either openio or caringo are
#   in Fedora.
# --with-cyrus-prefix and --with-service-path went away; use --with-libexecdir=
# instead.

# Needed because of Patch4.
autoreconf -vi

%configure \
    --disable-silent-rules \
    \
    --libexecdir=%cyrexecdir \
    --with-clamav \
    --with-extraident="%release Fedora" \
    --with-krbimpl=mit \
    --with-ldap=/usr \
    --with-libwrap=no \
    --with-mysql \
    --with-pgsql \
    --with-perl=%__perl \
    --with-snmp \
    --with-syslogfacility=MAIL \
    \
    --enable-autocreate \
    --enable-backup \
    --enable-calalarmd \
    --enable-http \
    --enable-idled \
    --enable-murder \
    --enable-nntp \
    --enable-replication \
    --enable-unit-tests \
    --enable-xapian \
#

# Try to get rid of RPATH....
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

# The configure script will set up the Perl makefiles, but not in the way
# Fedora needs them.  So regenerate them manually.
for i in perl/annotator perl/imap perl/sieve/managesieve; do
    pushd $i
    rm -f Makefile
    perl Makefile.PL INSTALLDIRS=vendor # NO_PERLOCAL=1 NO_PACKLIST=1
    popd
done

%make_build

# This isn't built by default, but this package has always installed it.
make notifyd/notifytest

pushd ./man
tar -xvf %SOURCE1
popd

%install
make install DESTDIR=%buildroot

# Create directories
install -d \
    %buildroot/etc/{rc.d/init.d,logrotate.d,pam.d,sysconfig,cron.daily} \
    %buildroot/%_libdir/sasl \
    %buildroot/var/spool/imap \
    %buildroot/var/lib/imap/{user,quota,proc,log,msg,socket,db,sieve,sync,md5,rpm,backup,meta} \
    %buildroot/var/lib/imap/ptclient \
    %buildroot/%_datadir/%name/rpm \
    %buildroot/%cyrexecdir \
    %buildroot/etc/pki/%name

install -d -m 0750 \
    %buildroot/run/cyrus \
    %buildroot/run/cyrus/socket

install -d -m 0700 \
    %buildroot/run/cyrus/db \
    %buildroot/run/cyrus/lock \
    %buildroot/run/cyrus/proc

# Some tools which aren't installed by the makefile which we have always installed
install -m 755 notifyd/notifytest  %buildroot%_bindir/
install -m 755 perl/imap/cyradm    %buildroot%_bindir/
for i in arbitronsort.pl masssievec mkimap mknewsgroups rehash translatesieve; do
    install -m 755 tools/$i %buildroot/%cyrexecdir/
done

install -p -m 644 %SOURCE10 %buildroot/etc/logrotate.d/%name

# PAM configuration files.
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/csync
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/http
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/imap
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/lmtp
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/mupdate
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/nntp
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/pop
install -p -m 644 %SOURCE11 %buildroot/etc/pam.d/sieve

install -p -m 644 %SOURCE12 %buildroot/etc/sysconfig/%name
install -p -m 644 %SOURCE13 %buildroot/%_datadir/%name/rpm/magic
install -p -m 755 %SOURCE14 %buildroot/etc/cron.daily/%name
install -p -m 644 doc/examples/cyrus_conf/prefork.conf %buildroot/etc/cyrus.conf
install -p -m 644 doc/examples/imapd_conf/normal.conf %buildroot/etc/imapd.conf
install -p -D -m 644 %SOURCE16 %buildroot/%_unitdir/cyrus-imapd.service
install -p -D -m 644 %SOURCE17 %buildroot/%_unitdir/cyrus-imapd-init.service
install -p -D -m 644 %SOURCE18 %buildroot/%_tmpfilesdir/cyrus-imapd.conf

# Cleanup of doc dir
find doc perl -name CVS -type d -prune -exec rm -rf {} \;
find doc perl -name .cvsignore -type f -exec rm -f {} \;
rm -f doc/Makefile.dist*
rm -f doc/text/htmlstrip.c
rm -f doc/text/Makefile
rm -rf doc/man

# fix permissions on perl .so files
find %buildroot/%_libdir/perl5/ -type f -name "*.so" -exec chmod 755 {} \;

# Generate db config file
# XXX Is this still necessary?
( grep '^{' lib/imapoptions | grep _db | cut -d'"' -f 2,4 | \
  sed -e 's/^ *//' -e 's/-nosync//' -e 's/ *$//' -e 's/"/=/'
  echo sieve_version=2.2.3 ) | sort > %buildroot/%_datadir/%name/rpm/db.cfg

# Cyrus has various files with extremely conflicting names.  Some of these are
# not unexpected ("imapd" itself) but some like "httpd" are rather surprising.

# Where there are only conflicting manpages, they have been moved to a "8cyrus"
# section.  If the binary was renamed, then the manpages are renamed to match
# but a internal replacement has not been done.  This may lead to more
# confusion but involves modifying fewer upstream files.

# Actual binary conflicts
# Rename 'fetchnews' binary and manpage to avoid clash with leafnode
mv %buildroot/%_sbindir/fetchnews %buildroot/%_sbindir/cyr_fetchnews
mv %buildroot/%_mandir/man8/fetchnews.8 %buildroot/%_mandir/man8/cyr_fetchnews.8

# Fix conflict with dump
mv %buildroot/%_sbindir/restore %buildroot/%_sbindir/cyr_restore
mv %buildroot/%_mandir/man8/restore.8 %buildroot/%_mandir/man8/cyr_restore.8

# Fix conceptual conflict with quota
mv %buildroot/%_sbindir/quota %buildroot/%_sbindir/cyr_quota
mv %buildroot/%_mandir/man8/quota.8 %buildroot/%_mandir/man8/cyr_quota.8

# fix conflicts with uw-imap
mv %buildroot/%_mandir/man8/imapd.8 %buildroot/%_mandir/man8/imapd.8cyrus
mv %buildroot/%_mandir/man8/pop3d.8 %buildroot/%_mandir/man8/pop3d.8cyrus

# Rename 'master' manpage
mv %buildroot/%_mandir/man8/master.8 %buildroot/%_mandir/man8/master.8cyrus

# Rename 'httpd' manpage to avoid clash with Apache
mv %buildroot/%_mandir/man8/httpd.8 %buildroot/%_mandir/man8/httpd.8cyrus

# Old cyrus packages used to keep the deliver executable in
# /usr/lib/cyrus-imapd, and MTA configurations might rely on this.
# Remove this hack in the F30 timeframe.
# RF hardcoded-library-path in %%buildroot/usr/lib/cyrus-imapd
mkdir %buildroot/usr/lib/cyrus-imapd
pushd %buildroot/usr/lib/cyrus-imapd
ln -s ../../sbin/deliver
popd

#remove executable bit from docs and Perl modules
for ddir in doc perl/imap/examples
do
  find $ddir -type f -exec chmod -x {} \;
done

# Remove pointless libtool archives
rm %buildroot/%_libdir/*.la

# Remove installed but not packaged files
rm %buildroot/%cyrexecdir/pop3proxyd
find %buildroot -name "perllocal.pod" -exec rm {} \;
find %buildroot -name ".packlist" -exec rm {} \;

# And this one gets installed with executable permission
chmod -x %buildroot/%perl_vendorlib/Cyrus/Annotator/Daemon.pm


%check
export LD_LIBRARY_PATH=%buildroot/%_libdir
export CYRUS_USER=$USER

make %{?_smp_mflags} check || exit 1

%ifarch %{ix86} armv7hl ppc64le
exit 0
%endif

%if %{without cassandane}
exit 0
%endif

# Run the Cassandane test suite.  This will exhaustively test the various
# server components, but running it in a mock chroot is rather an exercise.
pushd cassandane

mkdir -p imaptest/src
ln -s /usr/bin/imaptest imaptest/src
ln -s /usr/share/imaptest/tests imaptest/src

# Construct the set of excluded tests to pass to Cassandane
# ---------------------------------------------------------
exclude=()
tests=(
    # This exclusion list was verified on 2021-08-11.

    # This tests coredumping and won't work on a machine where systemd
    # intercepts coredumps, which includes our builders.
    Cassandane::Test::Core

    # Can't currently be run at build time because of compiled-in paths.  See
    # https://github.com/cyrusimap/cyrus-imapd/issues/2386
    Admin.imap_admins

    Rename.intermediate_cleanup

    ## FIXME
    ## Following tests started to fail with rebase and in rhel/centos only
    
    Cyrus::ImapTest.urlauth-binary
    Reconstruct.reconstruct_snoozed
    SearchSquat.simple
    SearchSquat.skip_unmodified
)
for i in ${tests[@]}; do exclude+=("!$i"); done


%ifarch s390x
# This one test fails occasionally on s390x because the hosts are just too slow
# to complete it.D  It's testing something valid (that the fork rate limiting
# settings work properly) but s390x can't fork quickly enough to exceeed the
# limits it's testing.
exclude+=("!Master.maxforkrate")
%endif

# Add -vvv for too much output
./testrunner.pl %{?_smp_mflags} -v -f pretty ${exclude[@]} 2>&1


%pre
# Create 'cyrus' user on target host
getent group saslauth >/dev/null || /usr/sbin/groupadd -g %gid -r saslauth
getent passwd cyrus >/dev/null || /usr/sbin/useradd -c "Cyrus IMAP Server" -d /var/lib/imap -g %cyrusgroup \
  -G saslauth -s /sbin/nologin -u %uid -r %cyrususer

%post
%systemd_post cyrus-imapd.service

%preun
%systemd_preun cyrus-imapd.service

%postun
%systemd_postun_with_restart cyrus-imapd.service


%files
%doc README.md doc/README.* doc/examples doc/text

%_sbindir/*
%_datadir/cyrus-imapd
%_mandir/man5/*
%_mandir/man8/*
%exclude %_sbindir/cyr_virusscan
%exclude %_mandir/man8/cyr_virusscan.8*

# For the legacy symlink to the deliver binary
# RF hardcoded-library-path in /usr/lib/cyrus-imapd
/usr/lib/cyrus-imapd/


%dir /etc/pki/cyrus-imapd
%attr(0644,root,%cyrusgroup) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %ssl_pem_file_prefix-ca.pem
%attr(0644,root,%cyrusgroup) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %ssl_pem_file_prefix.pem
%attr(0640,root,%cyrusgroup) %ghost %config(missingok,noreplace) %verify(not md5 size mtime) %ssl_pem_file_prefix-key.pem

%config(noreplace) /etc/cyrus.conf
%config(noreplace) /etc/imapd.conf
%config(noreplace) /etc/logrotate.d/cyrus-imapd
%config(noreplace) /etc/sysconfig/cyrus-imapd
%config(noreplace) /etc/pam.d/*

/etc/cron.daily/cyrus-imapd
%_unitdir/cyrus-imapd.service
%_unitdir/cyrus-imapd-init.service
%_tmpfilesdir/cyrus-imapd.conf

%dir %cyrexecdir/
%cyrexecdir/[a-uw-z]*

# This creates some directories which in the default configuration cyrus will
# never use because they are placed under /run instead.  However, old
# configurations or setup advice from the 'net might reference them, and so
# it's simpler to just leave them in the package.
%attr(0750,%cyrususer,%cyrusgroup) %dir /var/lib/imap/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/backup/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/db/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/log/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/meta/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/md5/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/msg/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/proc/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/ptclient/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/quota/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/rpm/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/sieve/
%attr(0750,%cyrususer,%cyrusgroup) /var/lib/imap/socket
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/sync/
%attr(0700,%cyrususer,%cyrusgroup) /var/lib/imap/user/
%attr(0700,%cyrususer,%cyrusgroup) /var/spool/imap/

# The new locations
%attr(0750,%cyrususer,%cyrusgroup) %dir /run/cyrus/
%attr(0700,%cyrususer,%cyrusgroup) /run/cyrus/db/
%attr(0700,%cyrususer,%cyrusgroup) /run/cyrus/lock/
%attr(0700,%cyrususer,%cyrusgroup) /run/cyrus/proc/
%attr(0750,%cyrususer,%cyrusgroup) /run/cyrus/socket/


%files devel
%_includedir/cyrus/
%_libdir/libcyrus*.so
%_libdir/pkgconfig/*.pc
%_mandir/man3/imclient.3*


%files doc-extra
%doc doc/html doc/internal doc/legacy


%files libs
%license COPYING
%_libdir/libcyrus*.so.*


%files utils
%{_bindir}/*
%_mandir/man1/*


%files virusscan
%_sbindir/cyr_virusscan
%_mandir/man8/cyr_virusscan.8*


%files -n perl-Cyrus
%license COPYING
%doc perl/imap/README
%doc perl/imap/Changes
%doc perl/imap/examples
%perl_vendorarch/auto/Cyrus
%perl_vendorarch/Cyrus
%perl_vendorlib/Cyrus
%_mandir/man3/*.3pm*


%changelog
* Wed Aug 17 2022 Martin Osvald <mosvald@redhat.com> - 3.4.1-7
- Resolves: #2096149 - Fatal error when running "squatter -r user"
- Resolves: #2096885 - Enhanced TMT testing for centos-stream

* Wed Nov 24 2021 Martin Osvald <mosvald@redhat.com> - 3.4.1-6
- Sending email with /usr/lib/cyrus-imapd/deliver fails with code 75
- Resolves: #2021532

* Wed Nov 03 2021 Martin Osvald <mosvald@redhat.com> - 3.4.1-5
- Add fix for CVE-2021-33582
- Resolves: #1994034

* Mon Aug 23 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.4.1-4
- Drop tzdist module. Clients must use OS provided timezone info

* Thu Aug 19 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.4.1-3
- Actually drop timezones requirement

* Thu Aug 19 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.4.1-2
- bump release

* Mon Aug 09 2021 Mohan Boddu <mboddu@redhat.com>
- Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
  Related: rhbz#1991688

* Thu Aug  5 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.4.1-1
- Update to v3.4.1


* Mon Jul 12 2021 Honza Horak <hhorak@redhat.com> - 3.2.6-12
- Require mariadb-connector-c-devel instead of mariadb-devel
  Resolves: #1981257

* Fri Jun 11 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-6
- Disable tests on 32bit arches. Started to fail with perl rebase

* Thu Apr 29 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-8
- Add pregerated man pages

* Mon Apr 26 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-7
- Add python3-sphinx BR to properly build man pages

* Mon Apr 26 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-7
- Add python3-sphinx BR to properly build man pages

* Mon Mar 22 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-2
- Require online target to prevent binding to down devices

* Wed Mar 17 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-3
- Do not require clamav in rhel
- Disable tests for ppc64le
- Disable tests for ix86 to work brew bug around

* Thu Mar 11 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.6-1
- New version v3.2.6

* Tue Mar 02 2021 Zbigniew Jędrzejewski-Szmek <zbyszek@in.waw.pl> - 3.2.4-8
- Rebuilt for updated systemd-rpm-macros
  See https://pagure.io/fesco/issue/2583.

* Wed Feb 17 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.4-7
- Require shapelib on Fedoras only

* Mon Feb 08 2021 Pavel Raiskup <praiskup@redhat.com> - 3.2.4-6
- rebuild for libpq ABI fix rhbz#1908268

* Tue Jan 26 2021 Fedora Release Engineering <releng@fedoraproject.org> - 3.2.4-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

* Tue Jan 12 2021 Pavel Zhukov <pzhukov@redhat.com> - 3.2.4-4
- Drop clamav BR for eln

* Mon Dec 14 2020 Pavel Zhukov <pzhukov@redhat.com> - 3.2.4-3
- Add ExecReload to service file (#1907223)

* Thu Sep  3 2020 Pavel Zhukov <pzhukov@redhat.com> - 3.2.3-1
- New version v3.2.3

* Thu Aug 27 2020 Josef Řídký <jridky@redhat.com> - 3.0.13-13
- Rebuilt for new net-snmp release

* Mon Aug 10 2020 Jeff Law <law@redhat.com> - 3.0.13-12
- Disable LTO on s390x for now

* Sat Aug 01 2020 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.13-11
- Second attempt - Rebuilt for
  https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Mon Jul 27 2020 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.13-10
- Rebuilt for https://fedoraproject.org/wiki/Fedora_33_Mass_Rebuild

* Mon Jul 13 2020 Pavel Zhukov <pzhukov@redhat.com> - 3.0.13-9
- Fix FTBFS caused by weak certificates (#1852137)

* Thu Jun 25 2020 Jitka Plesnikova <jplesnik@redhat.com> - 3.0.13-8
- Perl 5.32 rebuild

* Sat May 16 2020 Pete Walter <pwalter@fedoraproject.org> - 3.0.13-7
- Rebuild for ICU 67

* Wed May  6 2020 Pavel Zhukov <pzhukov@redhat.com> - 3.0.13-6
- Add missed dependencies (#1819685)

* Thu Apr 23 2020 Pavel Zhukov <pzhukov@redhat.com> - 3.0.13-5
- Specify version of cyrus-imapd for utils to avoid the need to test interoperability

* Thu Apr 23 2020 Pavel Zhukov <pzhukov@redhat.com> - 3.0.13-4
- Fix pem files permission

* Wed Apr 01 2020 Petr Pisar <ppisar@redhat.com> - 3.0.13-3
- Specify all Perl dependencies of Cassandane

* Tue Jan 28 2020 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.13-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_32_Mass_Rebuild

* Mon Dec 16 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.13-1
- Update to 3.0.13, fixing CVE-2019-19783.

* Fri Nov 22 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.12-1
- Update to 3.0.12, fixing CVE-2019-18928.

* Tue Jul 30 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.11-1
- Update to 3.0.11.

* Wed Jul 24 2019 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.10-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_31_Mass_Rebuild

* Fri May 31 2019 Jitka Plesnikova <jplesnik@redhat.com> - 3.0.10-2
- Perl 5.30 rebuild

* Tue May 28 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.10-1
- Update to 3.0.10.
- Drop upstreamed patch.

* Thu May 16 2019 Pavel Zhukov <pzhukov@redhat.com> - 3.0.9-2
- Run sscg as mail group for proper certs permissions

* Thu Mar 14 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.9-1
- Update to 3.0.9.

* Mon Feb 11 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.8-10
- Add pam configuration file for httpd auth.  Thanks to Jeroen van Meeuwen.

* Thu Jan 31 2019 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.8-9
- Rebuilt for https://fedoraproject.org/wiki/Fedora_30_Mass_Rebuild

* Thu Jan 24 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.8-8
- Update Perl linkage patch.

* Wed Jan 23 2019 Pete Walter <pwalter@fedoraproject.org> - 3.0.8-7
- Rebuild for ICU 63

* Wed Jan 23 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.8-6
- Re-enable --as-needed, now that PCRE has been patched.
- Add workaround for improper linking of some Perl modules.

* Tue Jan 15 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.8-5
- Disable passing --as-needed to to the linker.  This breaks cyrus horribly.
- Re-enable Cassandane run.

* Tue Jan 15 2019 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.8-4
- Allow building against ClamAV 0.101.
- Add build dependency on glibc-langpack-en to slience some Perl complaints.

* Thu Dec 13 2018 Pavel Zhukov <pzhukov@redhat.com> - 3.0.8-3
- Temporary disable cassandane in master branch

* Sun Oct 28 2018 Nils Philippsen <nils@tiptoe.de> - 3.0.8-2
- remove jmap from list of httpmodules

* Sat Aug 11 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.8-1
- Update to 3.0.8.
- Drop upstreamed patch.

* Tue Jul 24 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.7-9
- Rebuild for unannounced net-snmp soname bump.

* Thu Jul 12 2018 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.7-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_29_Mass_Rebuild

* Tue Jul 10 2018 Pete Walter <pwalter@fedoraproject.org> - 3.0.7-7
- Rebuild for ICU 62

* Sat Jun 30 2018 Jitka Plesnikova <jplesnik@redhat.com> - 3.0.7-6
- Perl 5.28 rebuild

* Wed Jun 13 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.7-5
- Split out cyr_virusscan into a -virusscan subpackage.
- Split libraries into a -libs subpackage.
- Fix rpath issues in libraries.
- Split Perl module into a separate perl-Cyrus package.
- Move utilities in /usr/sbin from -utils package to main package.  This
  matches the way we packaged the 2.4 versions.
- Fix some odd Perl shebangs and an erroneous provided symbol.
- Moved deliver symlink to the main package as well.
- Drop cvt_cyrusdb_all and libdb-utils requirement.  Cyrus 3 does not use
  BerkeleyDB at all.

* Thu Jun 07 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.7-4
- Update Cassandane checkout.  Drop upstreamed patch.
- Patch code for RECONSTRUCT implementation to use the renamed cyr_quota.
- Re-exclude maxforkrate test on s390x.

* Wed May 30 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.7-3
- Remove ldconfig scriptlets.
- Remove F26-specific test exclusions.
- Update Cassandane checkout.
- Add extra Cassandane patch from https://github.com/cyrusimap/cassandane/pull/57
- Revalidate the excluded test list.

* Fri May 18 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.7-2
- Really enable mysql and clamav support.

* Fri May 18 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.7-1
- Update to 3.0.7.
- Update Cassandane checkout.
- Update excluded Cassandane test list.

* Tue May 01 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.6-1
- Update to 3.0.6.
- Remove upstreamed patches and renumber the rest.
- Disable one new failing test:
  https://github.com/cyrusimap/cyrus-imapd/issues/2332

* Mon Apr 30 2018 Pete Walter <pwalter@fedoraproject.org> - 3.0.5-15
- Rebuild for ICU 61.1

* Tue Apr 17 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-14
- Update Cassandane again, fixing a broken test.

* Fri Apr 13 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-13
- Update Cassandane, fixing a few tests and a class of weird random build
  failures.

* Fri Apr 06 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-12
- Update list of excluded tests.
- Update Cassandane snapshot; use new base_port config setting.  No need to
  patch that in now.
- Add four new expected-to-fail tests from new Cassandane snapshot.
- Add patch to collect extra Cassandane logging in case we hit some of those
  sporadic failures again.

* Tue Apr 03 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-11
- Re-enable imaptest on >= F29.
- F29's imaptest fixes several bugs, allowing all tests to be run there.
- Relocate cassandane base port to hopefully work better in koji.

* Mon Apr 02 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-10
- Update cassandane checkout to fix a test that was broken by DST.
- Add patch to fix sieve scripts for usernames containing a dot.
- Disable imaptest in cassandane until
  https://bugzilla.redhat.com/show_bug.cgi?id=1562970 is fixed.
- Re-enable tests on s390; it seems to be better now.

* Thu Mar 15 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-9
- Re-enable clamav on ppc64.

* Thu Mar 01 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-8
- Bump client_timeout value in test suite.

* Thu Mar 01 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-7
- Add patch to fix imtest (rhbz#1543481).
- Fix vzic makefile to use proper cflags (rhbz#1550543).

* Mon Feb 26 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-6
- Update cassandane checkout.
- Add two new build dependencies.
- Remove all JMAP-related tests from the exclusion lists, since cassandane no
  longer runs any JMAP tests on cyrus 3.0.
- Collapse unused test skip lists.
- Add ten additional skipped tests, after consultation with upstream.

* Mon Feb 26 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-5
- Add patch to fix segfaults in squatter.
- Exclude one test on all releases instead of just F28+.
- Remove --cleanup from cassandane invocation.

* Wed Feb 07 2018 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.5-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Tue Jan 09 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-3
- Re-enable clamav and mariadb support as those are now built with openssl 1.1.
- But no clamav on ppc64 because of
  https://bugzilla.redhat.com/show_bug.cgi?id=1534071

* Thu Jan 04 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-2
- Reorganize some test exclusions so things build on all releases.

* Thu Jan 04 2018 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.5-1
- Update to 3.0.5.
- Add one new failing test.
- Remove one now-passing test on rawhide.

* Mon Dec 18 2017 Pavel Zhukov <pzhukov@redhat.com> - 3.0.4-6
- Rebuild with new net-snmp

* Thu Nov 30 2017 Pete Walter <pwalter@fedoraproject.org> - 3.0.4-5
- Rebuild for ICU 60.1

* Wed Nov 29 2017 Pavel Zhukov <pzhukov@redhat.com> - 3.0.4-4
- Do not require tcp_wrappers (#1518759)

* Tue Nov 14 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.4-3
- Rebuild for new libical.
- Add patch to fix compilation error with new libical.
- Disable two tests which fail due to the new libical.

* Tue Oct 24 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.4-2
- Fix typo in default config;
  https://bugzilla.redhat.com/show_bug.cgi?id=1506000

* Tue Sep 05 2017 Pavel Zhukov <landgraf@fedoraproject.org> - 3.0.4-1
- Update to 3.0.4
- Patched cassandane for new behaviour. It should be updated idealy.
- Disable ImapTest.urlauth2 test; it seems to fail randomly regardless of
  architecture.

* Fri Aug 11 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.3-1
- Update to 3.0.3, which contains an important security fix.  The fix is not
  embargoed but no CVE has been assigned yet.
- Drop patches merged upstream.
- An update of imaptest has resulted in three additional cassandane failures,
  reported upstream as https://github.com/cyrusimap/cyrus-imapd/issues/2087.
  In order to get the security fix out without delay, those three tests have been
  disabled.

* Fri Aug 11 2017 Igor Gnatenko <ignatenko@redhat.com> - 3.0.2-9
- Rebuilt after RPM update (№ 3)

* Thu Aug 10 2017 Igor Gnatenko <ignatenko@redhat.com> - 3.0.2-8
- Rebuilt for RPM soname bump

* Wed Aug 02 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.2-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Wed Jul 26 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.0.2-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Fri Jun 30 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.2-5
- Add two patches from upstream which fix JMAPCalendars issues on 32-bit and
  big-endian architectures.
- Clean up test invocation and exclusion list.  More tests pass now.

* Wed Jun 28 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.2-4
- Explicitly set specialusealways: 1 in the default config.

* Tue Jun 27 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.2-3
- Patch the provided imapd.conf and cyrus.conf to more closely match previous
  Fedora defaults and directories included in this package and to enable
  features which are supported by the Fedora build.
- Add tmpfiles.d configuration file for directories in /run.

* Tue Jun 27 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.2-2
- Exclude one more test from 32-bit arches.  Looks like this failure crept in
  with the Cassandane update.

* Thu Jun 22 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.2-1
- Update to 3.0.2.
- New Cassandane snapshot, with more tests (all of which are passing).

* Tue Jun 20 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.1-7
- Add old /usr/lib/cyrus-imapd directory to the utils package and add a symlink
  there to the deliver binary.  This should help a bit with migrations.
- Add upstream patch to fix reconstruct failures on 32-bit architectures.
  Re-enable those five Cassandane tests.

* Thu Jun 15 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.1-6
- Rename two commands: quota -> cyr_quota, restore -> cyr_restore.
- Fix Cassandane to handle those renames.
- Fix location of cyr_fetchnews.
- Fix Perl 5.26-related module linking issue which caused a test failure.
  Fixes https://bugzilla.redhat.com/show_bug.cgi?id=1461669

* Tue Jun 06 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.1-5
- Use proper path to ctl_mboxlist in cron file.
- Add patch to increase individual test timeout.  Sometimes armv7hl can't
  complete a single test in 20 seconds.
- Disable the Metronome tests; upstream says that they just won't reliably on
  shared hardware.
- Don't bother running Cassandane on s390x for now.  The machines are simply
  too slow.

* Tue Jun 06 2017 Jitka Plesnikova <jplesnik@redhat.com> - 3.0.1-4
- Perl 5.26 rebuild

* Fri Jun 02 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.1-3
- Remove clamav from build requirements.
- Add --cleanup to Cassandane call to hopefully reduce build disk usage.
- Disable maxforkrate test on s390x; our builders are too slow to run it.

* Fri Jun 02 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.1-2
- Add patch to fix up some endianness issues.
- Enable both test suites on all architectures.
- Add arch-specific excludes for a few Cassandane tests.

* Thu Apr 20 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 3.0.1-1
- Initial attempt at importing 3.0.  Many new dependencies.
- Use a stock sample imapd.conf file instead of a Fedora-provided one.

* Fri Feb 10 2017 Fedora Release Engineering <releng@fedoraproject.org> - 2.5.10-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Mon Jan 09 2017 Jason L Tibbitts III <tibbs@math.uh.edu> - 2.5.10-2
- Rename httpd manpage to "cyrhttpd" to avoid conflict with the httpd package.

* Wed Nov 23 2016 Jason L Tibbitts III <tibbs@math.uh.edu> - 2.5.10-1
- Initial update to the 2.5 series.
- Significant spec cleanups.
- Add sscg dep and follow
  https://fedoraproject.org/wiki/Packaging:Initial_Service_Setup for initial
  cert generation.
- Change default conf to use the system crypto policy.

* Tue May 17 2016 Jitka Plesnikova <jplesnik@redhat.com> - 2.4.18-3
- Perl 5.24 rebuild

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 2.4.18-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Thu Oct 01 2015 Jason L Tibbitts III <tibbs@math.uh.edu> - 2.4.18-1
- Update to 2.4.18, rhbz#1267871 and rhbz#1267878
- Backport ff4e6c71d932b3e6bbfa67d76f095e27ff21bad0 to fix issues from
  http://seclists.org/oss-sec/2015/q3/651

* Wed Sep 09 2015 Jason L Tibbitts III <tibbs@math.uh.edu> - 2.4.17-14
- Use %%license tag
- Have -devel require the base package
- Minor cleanups

* Sat Aug 08 2015 Jason L Tibbitts III <tibbs@math.uh.edu> - 2.4.17-13
- Remove invalid Patch0: URL.
- Use HTTP for upstream source.
- pod2html was split out of the main perl package, breaking cyrus.
  Add a build dep for it.

* Wed Jul 29 2015 Kevin Fenzi <kevin@scrye.com> 2.4.17-12
- Rebuild for new librpm

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.17-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Fri Jun 05 2015 Jitka Plesnikova <jplesnik@redhat.com> - 2.4.17-10
- Perl 5.22 rebuild

* Wed Aug 27 2014 Jitka Plesnikova <jplesnik@redhat.com> - 2.4.17-9
- Perl 5.20 rebuild

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.17-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.17-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.17-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Thu Jul 18 2013 Petr Pisar <ppisar@redhat.com> - 2.4.17-5
- Perl 5.18 rebuild

* Fri Jul 12 2013 Michal Hlavinka <mhlavink@redhat.com> - 2.4.17-4
- spec clean up

* Thu Apr 18 2013 Michal Hlavinka <mhlavink@redhat.com> - 2.4.17-3
- make sure binaries are hardened

* Wed Feb 13 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.17-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Sat Dec  1 2012 Jeroen van Meeuwen <vanmeeuwen@kolabsys.com> - 2.4.17-1
- New upstream version, fixes upstream bugs:
- reconstruct doesn't retain internaldate correctly (#3733)
- Race condition in maibox rename (#3696)
- DBERROR db4: Transaction not specified for a transactional database (#3715)
- performance degradation on huge indexes in 2.4 branch (#3717)
- typo fix in imapd.conf man page (#3729)
- quota does not find all quotaroots if quotalegacy, fulldirhash and prefix are used and virtdomains is off (#3735)
- Mail delivered during XFER was lost (#3737)
- replication does not work on RENAME (#3742)
- Failed asserting during APPEND (#3754)

* Fri Nov 30 2012 Michal Hlavinka <mhlavink@redhat.com> - 2.4.16-5
- do not use strict aliasing

* Tue Aug 21 2012 Michal Hlavinka <mhlavink@redhat.com> - 2.4.16-4
- use new systemd rpm macros (#850079)

* Wed Jul 18 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.16-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Mon Jun 11 2012 Petr Pisar <ppisar@redhat.com> - 2.4.16-2
- Perl 5.16 rebuild

* Thu Apr 19 2012 Jeroen van Meeuwen <vanmeeuwen@kolabsys.com> - 2.4.16-1
- New upstream release

* Wed Apr 18 2012 Jeroen van Meeuwen <vanmeeuwen@kolabsys.com> - 2.4.15-1
- New upstream release

* Wed Apr 11 2012 Michal Hlavinka <mhlavink@redhat.com> - 2.4.14-2
- rebuilt because of new libdb

* Wed Mar 14 2012 Michal Hlavinka <mhlavink@redhat.com> - 2.4.14-1
- updated to 2.4.14

* Tue Feb 07 2012 Michal Hlavinka <mhlavink@redhat.com> - 2.4.13-3
- use PraveTmp in systemd unit file

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.4.13-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Mon Jan 02 2012 Jeroen van Meeuwen <vanmeeuwen@kolabsys.com> - 2.4.13-1
- New upstream release

* Wed Dec 07 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.12-5
- do not use digest-md5 as part of default auth mechanisms,
  it does not coop with pam

* Tue Nov 22 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.12-4
- reduce noisy logging, add option to turn on LOG_DEBUG syslog
  messages again (thanks Philip Prindeville) (#754940)

* Mon Oct 24 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.12-3
- add login and digest-md5 as part of default auth mechanisms (#748278)

* Tue Oct 11 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.12-2
- do not hide errors if cyrus user can't be added

* Wed Oct 05 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.12-1
- cyrus-imapd updated to 2.4.12
- fixes incomplete authentication checks in nntpd (Secunia SA46093)

* Fri Sep  9 2011 Jeroen van Meeuwen <vanmeeuwen@kolabsys.com> - 2.4.11-1
- update to 2.4.11
- Fix CVE-2011-3208 (#734926, #736838)

* Tue Aug 16 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.10-4
- rebuild with db5

* Thu Jul 21 2011 Petr Sabata <contyk@redhat.com> - 2.4.10-3
- Perl mass rebuild

* Wed Jul 20 2011 Petr Sabata <contyk@redhat.com> - 2.4.10-2
- Perl mass rebuild

* Wed Jul  6 2011 Jeroen van Meeuwen <kanarip@kanarip.com> - 2.4.10-1
- New upstream release

* Wed Jun 22 2011 Iain Arnell <iarnell@gmail.com> 2.4.8-5
- Patch to work with Perl 5.14

* Mon Jun 20 2011 Marcela Mašláňová <mmaslano@redhat.com> - 2.4.8-4
- Perl mass rebuild

* Fri Jun 10 2011 Marcela Mašláňová <mmaslano@redhat.com> - 2.4.8-3
- Perl 5.14 mass rebuild

* Mon May 09 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.8-2
- fixed: systemd commands in %%post (thanks Bill Nottingham)

* Thu Apr 14 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.8-1
- cyrus-imapd updated to 2.4.8
- fixed: cannot set unlimited quota through proxy
- fixed: reconstruct tries to set timestamps again and again
- fixed: response for LIST "" user is wrong
- fixed: THREAD command doesn't support quoted charset
- fixed crashes in mupdatetest and cyr_expire when using -x

* Mon Apr 04 2011 Michal Hlaivnka <mhlavink@redhat.com> - 2.4.7-2
- now using systemd

* Thu Mar 31 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.7-1
- updated to 2.4.7

* Fri Feb 11 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.4.6-1
- updated to 2.4.6
- "autocreate" and "autosieve" features were removed

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.3.16-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Fri Jan 21 2011 Michal Hlavinka <mhlavink@redhat.com> - 2.3.16-7
- don't force sync io for all filesystems

* Fri Jul 09 2010 Michal Hlavinka <mhlavink@redhat.com> - 2.3.16-6
- follow licensing guideline update
- devel sub-package has to have virtual static provides (#609604)

* Mon Jun 07 2010 Michal Hlavinka <mhlavink@redhat.com> - 2.3.16-5
- spec cleanup
- simplified packaging (merge -perl in -utils)
- remove obsoleted and/or unmaintained additional sources/patches
- remove long time not used files from the cvs/srpm
- update additional sources/patches from their upstream

* Tue Jun 01 2010 Marcela Maslanova <mmaslano@redhat.com> - 2.3.16-4
- Mass rebuild with perl-5.12.0

* Tue Apr 20 2010 Michal Hlavinka <mhlavink@redhat.com> - 2.3.16-3
- add support for QoS marked traffic (#576652)

* Thu Jan 14 2010 Michal Hlavinka <mhlavink@redhat.com> - 2.3.16-2
- ignore user_denny.db if missing (#553011)
- fix location of certificates in default imapd.conf

* Tue Dec 22 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.16-1
- updated to 2.3.16

* Fri Dec 04 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-10
- fix shell for daily cron job (#544182)

* Fri Dec 04 2009 Stepan Kasal <skasal@redhat.com> - 2.3.15-9
- rebuild against perl 5.10.1

* Thu Nov 26 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-8
- spec cleanup

* Tue Nov 24 2009 Michal Hlavinka <mhlaivnk@redhat.com> - 2.3.15-7
- rebuild with new db4 (#540093)
- spec cleanup

* Fri Nov 06 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-6
- fix sourcing of /etc/sysconfig/cyrus-imapd (#533320)

* Thu Nov 05 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-5
- do not fill logs with mail (de)compression messages (#528093)

* Thu Oct 29 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-4
- spec cleanup

* Fri Oct 09 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-3
- fix cyrus user shell for db import (#528126)

* Fri Sep 18 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-2
- make init script LSB-compliant (#523227)

* Fri Sep 18 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.15-1
- fix buffer overflow in cyrus sieve (CVE-2009-3235)

* Wed Sep 16 2009 Tomas Mraz <tmraz@redhat.com> - 2.3.14-6
- use password-auth common PAM configuration instead of system-auth

* Mon Sep 07 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.14-5
- fix buffer overflow in cyrus sieve (#521010)

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 2.3.14-4
- rebuilt with new openssl

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.3.14-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon May 25 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.14-2
- rebuild because of changed dependencies

* Thu Apr 02 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.14-1
- updated to 2.3.14

* Wed Apr 01 2009 Michael Schwendt <mschwendt@fedoraproject.org> - 2.3.13-5
- fix unowned directory (#483336).

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2.3.13-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Mon Feb 02 2009 Michal Hlavinka <mhlavink@rehdat.com> - 2.3.13-3
- fix directory ownership

* Wed Jan 21 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.13-2
- fix: #480138 - assertion failed: libcyr_cfg.c: cyrus_options[opt].opt == opt

* Tue Jan 13 2009 Michal Hlavinka <mhlavink@redhat.com> - 2.3.13-1
- updated to 2.3.13

* Fri Sep 26 2008 Dan Horák <dan[at]danny.cz - 2.3.12p2-3
- better fix for linking with recent db4.x

* Fri Sep 12 2008 Dan Horák <dan[at]danny.cz - 2.3.12p2-2
- fix linking with db4.7 (Resolves: #461875)
- patch cleanup

* Mon Sep  1 2008 Dan Horák <dan[at]danny.cz - 2.3.12p2-1
- update to new upstream version 2.3.12p2
- update patches

* Mon Sep  1 2008 Dan Horák <dan[at]danny.cz - 2.3.11-3
- refresh patches

* Sat May 31 2008 Dan Horák <dan[at]danny.cz - 2.3.11-2
- call automake to update config.* files and be buildable again on rawhide

* Tue Mar 25 2008 Tomas Janousek <tjanouse@redhat.com> - 2.3.11-1
- update to latest upstream
- (temporarily) dropped the rmquota+deletemailbox patch (doesn't apply)

* Wed Mar 19 2008 Rex Dieter <rdieter@fedoraproject.org> - 2.3.9-12
- cyrus-imapd conflicts with uw-imap (#222506)

* Tue Mar 18 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 2.3.9-11
- add Requires for versioned perl (libperl.so)

* Wed Feb 20 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 2.3.9-10
- Autorebuild for GCC 4.3

* Fri Feb 08 2008 Tomas Janousek <tjanouse@redhat.com> - 2.3.9-9
- don't run cronjob if cyrus-imapd has never been started (#418191)

* Tue Dec 04 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.9-8
- move certificate creation from -utils postinst to main package
- rebuild with newer openssl and openldap

* Sun Sep 23 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.9-7
- updated the getgrouplist patch
- fixed a few undeclared functions (and int to pointer conversions)

* Wed Aug 22 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.9-6
- update to latest upstream
- updated all patches from uoa and reenabled rmquota+deletemailbox

* Thu Aug 16 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.9-5.rc2
- update to latest upstream beta

* Tue Aug 14 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.9-4.rc1
- update to latest upstream beta
- temporarily dropped the rmquota+deletemailbox patch (doesn't apply)
- fixed to compile with newer glibc
- added the getgrouplist patch from RHEL-4, dropped groupcache patch
- dropped the allow_auth_plain patch
- buildrequire perl-devel

* Mon Jul 23 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.8-3.2
- removed the lm_sensors-devel dependency, since it's properly required in
  net-snmp-devel
- #248984 - cyrus-imapd.logrotate updated for rsyslog

* Mon Apr 23 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.8-3.1
- the -devel subpackage no longer requires the main one

* Wed Apr 11 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.8-3
- updated the no-bare-nl patch (#235569), thanks to Matthias Hensler

* Wed Apr 04 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.8-2
- fixed mboxlist backup rotation (#197054)

* Mon Mar 12 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.8-1
- update to latest upstream

* Wed Jan 24 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.7-8
- compile with kerberos support

* Wed Jan 24 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.7-7
- fixed Makefile typo (caused multiarch conflict)

* Mon Jan 08 2007 Tomas Janousek <tjanouse@redhat.com> - 2.3.7-6
- #218046: applied patches to compile with db4-4.5

* Tue Dec  5 2006 John Dennis <jdennis@redhat.com> - 2.3.7-5
- Resolves: bug# 218046: Cyrus-imapd in rawhide needs to be rebuilt
  against new snmp package

* Thu Oct 05 2006 Christian Iseli <Christian.Iseli@licr.org> 2.3.7-4
- rebuilt for unwind info generation, broken in gcc-4.1.1-21

* Mon Sep 18 2006 John Dennis <jdennis@redhat.com> - 2.3.7-3
- bump rev for rebuild

* Fri Aug 04 2006 Petr Rockai <prockai@redhat.com> - 2.3.7-2
- only buildrequire lm_sensors on i386 and x86_64, since it is not
  available elsewhere

* Sun Jul 23 2006 Petr Rockai <prockai@redhat.com> - 2.3.7-1
- update to latest upstream version, fixes a fair amount of issues
- forward-port the autocreate and rmquota patches (used latest
  upstream patches, those are for 2.3.3)

* Tue Jul 18 2006 Petr Rockai <prockai@redhat.com> - 2.3.1-3
- install perl modules into vendor_perl instead of site_perl
- change mode of perl .so files to 755 instead of 555
- update pam configuration to use include directive instead
  of deprecated pam_stack
- change prereq on cyrus-imapd-utils to requires

* Tue Jul 11 2006 Petr Rockai <prockai@redhat.com> - 2.3.1-2.99.test1
- address bunch of rpmlint errors and warnings
- rename perl-Cyrus to cyrus-imapd-perl to be consistent with rest
  of package (the cyrus modules are not part of cpan)
- added provides on cyrus-nntp and cyrus-murder (the functionality
  is part of main package now)
- removed generation of README.buildoptions
- the two above made it possible to get rid of most build-time parameter
  guessing from environment
- get rid of internal autoconf (iew)
- don't strip binaries, renders -debuginfo useless...
- remove prereq's in favour of newly added requires(...)

* Tue Feb 28 2006 John Dennis <jdennis@redhat.com> - 2.3.1-2
- bring up to Simon Matter's 2.3.1-2 release
- fix bug #173319, require cyrus-sasl-lib instead of cyrus-sasl
- fix bug #176470, hardcoded disttag
- add backend_sigsegv patch
- add replication_policycheck patch

* Mon Jan 23 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-1
- update to official autocreate and autosievefolder patches

* Thu Jan 19 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.18
- update rpm_set_permissions script
- add snmp support as build time option, disabled by default
  because it doesn't build on older distributions

* Wed Jan 18 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.15
- add make_md5 patch

* Mon Jan 16 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.13
- add autosievefolder patch
- add rmquota+deletemailbox patch
- change default path for make_md5, add md5 directory

* Fri Jan 13 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.10
- spec file cleanup
- add more cvt_cyrusdb_all fixes
- fix pre/post scripts
- fix requirements
- add patch to set Invoca RPM config defaults
- add sync directory used for replication
- add autocreate patch

* Thu Jan 12 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.8
- update cvt_cyrusdb_all script
- build db.cfg on the fly

* Thu Jan 05 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.5
- create ptclient directory if ldap enabled

* Wed Jan 04 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.4
- build without ldap support if openldap is linked against SASLv1

* Tue Jan 03 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.3
- fix ldap support

* Mon Jan 02 2006 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.2
- add openldap-devel to buildprereq, build with ldap support

* Wed Dec 21 2005 Simon Matter <simon.matter@invoca.ch> 2.3.1-0.1
- update to 2.3.1, officially called BETA-quality release

* Fri Dec 16 2005 Simon Matter <simon.matter@invoca.ch> 2.3.0-0.4
- add skiplist.py to contrib/
- port authid_normalize patch

* Thu Dec 15 2005 Simon Matter <simon.matter@invoca.ch> 2.3.0-0.3
- reintroduce subpackage utils, fix requirements
- move some utils to %%{_bindir}/

* Wed Dec 14 2005 Simon Matter <simon.matter@invoca.ch> 2.3.0-0.2
- integrate subpackages murder, nntp, replication, utils

* Tue Dec 13 2005 Simon Matter <simon.matter@invoca.ch> 2.3.0-0.1
- update to 2.3.0, officially called BETA-quality release
- add replication subpackage

* Fri Dec 09 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-15.1
- add missing automake to buildprereq
- change package description

* Tue Dec 06 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-15
- update cvt_cyrusdb_all script
- update autocreate patches

* Mon Dec 05 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-14
- update cvt_cyrusdb_all script

* Mon Nov 14 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-13
- add 64bit quota support backported from 2.3

* Fri Nov 11 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-12
- add quickstart/stop option to init script to bypass db import/export
- add authid_normalize patch
- add allow_auth_plain_proxying patch
- update gcc4 patch
- remove useless fdatasync patch
- add private autoconf used for build, remove autoconf dependency
- generate correct docs including man pages
- remove unneeded files from doc directory

* Fri Nov 04 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-11
- add mupdate thread-safe patch

* Mon Oct 24 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-9.4
- add spool patch, which is already fixed in CVS

* Tue Aug 30 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-9.2
- pull in CPPFLAGS and LDFLAGS from openssl's pkg-config data, if it exists

* Wed Aug 24 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-9.1
- add timsieved_reset_sasl_conn patch

* Mon Aug 22 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-9
- cosmetic changes in pre and post scripts

* Fri Aug 19 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-8
- add more pki dir fixes for inplace upgrades

* Thu Aug 18 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-7
- include requirement for Berkeley DB utils

* Thu Aug 18 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-6
- fix recovery problems with db4, which do not exist with db3
- fix logic for handling ssl certs
- remove initlog from init script

* Wed Aug 17 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-5
- add notifytest to the distribution
- add functionality to convert all berkeley databases to skiplist
  on shutdown and convert them back as needed on startup. This should
  solve the upgrade problems with Berkeley databases.

* Tue Aug 16 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-4.14
- add gcc4 patch
- determine and handle pki directory for openssl correctly
- add skiplist recovery docs
- add notify_sms patch

* Mon Jul 18 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-4.10
- update cvt_cyrusdb_all script
- update autocreate patches

* Fri Jul 15 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-4.9
- add patch to remove ACLs with invalid identifier
- update cvt_cyrusdb_all script

* Sat Jun 18 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-4.1
- update munge8bit patch

* Wed Jun 08 2005 Simon Matter <simon.matter@invoca.ch> 2.2.12-4
- updated seenstate patch

* Thu Jun 02 2005 Simon Matter <simon.matter@invoca.ch>
- removed nolinkimapspool patch, added singleinstancestore patch instead

* Thu Jun 02 2005 Simon Matter <simon.matter@invoca.ch>
- added nolinkimapspool patch
- fix debug_package macro, it was still being expanded,
  comments don't hide macro expansion
- change license field to BSD, its not exact BSD, but BSD is the closest

* Fri Apr 22 2005 John Dennis <jdennis@redhat.com> - 2.2.12-6.fc4
- the openssl package moved all its certs, CA, Makefile, etc. to /etc/pki
  now we are consistent with the openssl directory changes.

* Thu Apr 21 2005 John Dennis <jdennis@redhat.com> - 2.2.12-5.fc4
- we finally have a common directory, /etc/pki for certs, so create
  /etc/pki/cyrus-imapd and put the ssl pem file there. The /etc/cyrus-imapd
  location will not be used, this change supercedes that.

* Mon Apr 18 2005 John Dennis <jdennis@redhat.com> - 2.2.12-4.fc4
- fix bug #141479, move ssl pem file from /usr/share/ssl/certs to /etc/cyrus-imapd/cyrus-imapd.pem
- change license field to BSD, its not exact BSD, but BSD is the closest.

* Fri Apr 15 2005 John Dennis <jdennis@redhat.com> - 2.2.12-3.fc4
- fix release field to be single digit

* Fri Apr 15 2005 John Dennis <jdennis@redhat.com> - 2.2.12-1.2.fc4
- fix debug_package macro, it was still being expanded,
  comments don't hide macro expansion
- fix changelog chronological order
- fix bug 118832, cyrus-imapd is modifying /etc/services

* Mon Apr  4 2005 John Dennis <jdennis@redhat.com> - 2.2.12-1.1.fc4
- bring up to 2.2.12, includes security fix for CAN-2005-0546

* Mon Mar 07 2005 Simon Matter <simon.matter@invoca.ch>
- updated rmquota+deletemailbox patches

* Fri Mar  4 2005 John Dennis <jdennis@redhat.com> - 2.2.10-11.4.fc4
- fix gcc4 build problems

* Thu Mar  3 2005 John Dennis <jdennis@redhat.com> 2.2.10-11.3.fc4
- bump rev for build

* Mon Feb 14 2005 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.12
- updated autocreate and autosievefolder patches

* Fri Feb 11 2005 John Dennis <jdennis@redhat.com> - 2.2.10-11.2.fc4
- make _contribdir identical to Simon's,
  I had been getting burned by rpm's bizarre handling of macros in comments

* Thu Feb 10 2005 John Dennis <jdennis@redhat.com> - 2.2.10-11.1.fc4
- bring up to date with Simon Matter's 2.2.10-11 rpm

* Sat Feb 05 2005 Simon Matter <simon.matter@invoca.ch>
- updated autosievefolder patch

* Tue Feb 01 2005 Simon Matter <simon.matter@invoca.ch>
- remove special ownership and permissions from deliver
- enable deliver-wrapper per default
- enable OutlookExpress seenstate patch per default

* Wed Jan 19 2005 Simon Matter <simon.matter@invoca.ch>
- updated autocreate patch

* Fri Jan 14 2005 Simon Matter <simon.matter@invoca.ch>
- spec file cleanup

* Tue Jan 11 2005 Simon Matter <simon.matter@invoca.ch>
- updated autocreate patch

* Fri Jan 07 2005 Simon Matter <simon.matter@invoca.ch>
- moved contrib dir into doc, made scripts not executable

* Thu Jan 06 2005 Simon Matter <simon.matter@invoca.ch>
- added more fixes to the autocreate patch
- don't use %%_libdir for %%_cyrexecdir, it's a mess on x86_64
- don't use %%_libdir for symlinks
- remove %%_libdir pachtes
- change pam configs to work on x86_64
- changed default build option for IDLED to on
- changed rpm_set_permissions to honor partitions in /etc/imapd.conf

* Tue Jan 04 2005 Simon Matter <simon.matter@invoca.ch>
- updated autocreate patch

* Mon Dec 20 2004 Simon Matter <simon.matter@invoca.ch>
- remove idled docs when disabled, fixes RedHat's bug #142345

* Fri Dec 17 2004 Simon Matter <simon.matter@invoca.ch>
- removed allnumeric patch, not needed anymore
- made groupcache a compile time option
- rename nntp's pam service, fixes RedHat's bug #142672

* Thu Dec 16 2004 Simon Matter <simon.matter@invoca.ch>
- updated groupcache patch
- updated cvt_cyrusdb_all to use runuser instead of su if available
- added upd_groupcache tool

* Wed Dec 15 2004 Simon Matter <simon.matter@invoca.ch>
- added groupfile patch to help those using nss_ldap

* Thu Dec 02 2004 Simon Matter <simon.matter@invoca.ch>
- modified config directives and removed verify options

* Thu Dec  2 2004 John Dennis <jdennis@redhat.com> 2.2.10-3.devel
- fix bug #141673, dup of bug #141470
  Also make cyrus.conf noreplace in addition to imapd.conf
  Remove the verify overrides on the noreplace config files,
  we do want config file changes visible when verifying

* Wed Dec  1 2004 John Dennis <jdennis@redhat.com> 2.2.10-2.devel
- fix bug #141470, make imapd.conf a noreplace config file

* Wed Dec  1 2004 John Dennis <jdennis@redhat.com> 2.2.10-1.devel
- update to Simon Matter's 2.2.10 RPM,
  fixes bug #139382,
  security advisories: CAN-2004-1011 CAN-2004-1012 CAN-2004-1013 CAN-2004-1015

* Wed Nov 24 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.10

* Tue Nov 23 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.9

* Fri Nov 19 2004 Simon Matter <simon.matter@invoca.ch>
- changed scripts to use runuser instead of su if available

* Thu Nov 18 2004 Simon Matter <simon.matter@invoca.ch>
- changed requirement for file >= 3.35-1 from BuildPrereq to
  Requires, fixes RedHat's bug #124991
- added acceptinvalidfrom patch to fix RedHat's bug #137705

* Mon Oct 4 2004 Dan Walsh <dwalsh@redhat.com> 2.2.6-2.FC3.6
- Change cyrus init scripts and cron job to use runuser instead of su

* Fri Aug  6 2004 John Dennis <jdennis@redhat.com> 2.2.6-2.FC3.5
- remove obsoletes tag, fixes bugs #127448, #129274

* Wed Aug  4 2004 John Dennis <jdennis@redhat.com>
- replace commas in release field with dots, bump build number

* Tue Aug 03 2004 Simon Matter <simon.matter@invoca.ch>
- fixed symlinks for x86_64, now uses the _libdir macro
  reported by John Dennis, fixes RedHat's bug #128964
- removed obsoletes tag, fixes RedHat's bugs #127448, #129274

* Mon Aug  2 2004 John Dennis <jdennis@redhat.com> 2.2.6-2,FC3,3
- fix bug #128964, lib symlinks wrong on x86_64

* Thu Jul 29 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.8

* Thu Jul 29 2004 Simon Matter <simon.matter@invoca.ch>
- updated autocreate and autosieve patches
- made authorization a compile time option
- added sieve-bc_eval patch

* Tue Jul 27 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.7
- modified autocreate patch or 2.2.7
- removed snmpargs patch which was needed for RedHat 6.2

* Tue Jul 13 2004 Simon Matter <simon.matter@invoca.ch>
- added mboxlist / mboxname patches from CVS

* Tue Jul 06 2004 Simon Matter <simon.matter@invoca.ch>
- updated rmquota+deletemailbox patch

* Sat Jul  3 2004 John Dennis <jdennis@redhat.com> - 2.2.6-2,FC3,1
- bring up to date with Simon Matter's latest upstream rpm 2.2.6-2
- comment out illegal tags Packager, Vendor, Distribution
  build for FC3

* Wed Jun 30 2004 Simon Matter <simon.matter@invoca.ch>
- added quota patches from CVS

* Fri Jun 25 2004 Simon Matter <simon.matter@invoca.ch>
- updated autocreate patch

* Fri Jun 18 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.6

* Fri Jun 11 2004 Simon Matter <simon.matter@invoca.ch>
- updated autocreate and autosieve patches

* Tue Jun 01 2004 Simon Matter <simon.matter@invoca.ch>
- updated autocreate, autosieve and rmquota patches
- fixed rmquota patch to build on gcc v3.3.x
- added lmtp_sieve patch

* Sat May 29 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.5

* Fri May 28 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.5 pre-release

* Mon May 24 2004 Simon Matter <simon.matter@invoca.ch>
- added hash patch to fix a sig11 problem
- added noncritical typo patch

* Fri May 21 2004 Simon Matter <simon.matter@invoca.ch>
- include OutlookExpress seenstate patch
- fixed allnumeric patch

* Thu May 20 2004 Simon Matter <simon.matter@invoca.ch>
- don't enable cyrus-imapd per default
- rename fetchnews to cyrfetchnews to avoid namespace conflicts with leafnode
- replace fetchnews with cyrfetchnews in man pages
- replace master with cyrus-master in man pages

* Tue May 18 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.4

* Fri Apr 30 2004 Simon Matter <simon.matter@invoca.ch>
- Don't provides: imap

* Wed Mar 17 2004 Simon Matter <simon.matter@invoca.ch>
- fix init script

* Thu Mar 04 2004 Simon Matter <simon.matter@invoca.ch>
- strip binaries

* Tue Mar 02 2004 Simon Matter <simon.matter@invoca.ch>
- add more SELinux fixes

* Wed Feb 25 2004 Simon Matter <simon.matter@invoca.ch>
- add makedepend to path, thank you Andreas Piesk for reporting it

* Mon Feb 23 2004 Dan Walsh <dwalsh@redhat.com>
- change su within init script to get input from /dev/null
  this prevents hang when running in SELinux
- don't use -fpie as default, it breaks different distributions

* Thu Feb 19 2004 Simon Matter <simon.matter@invoca.ch>
- merged in most changes from Karsten Hopp's RedHat package
- fixed permissions of files in contrib, thank you
  Edward Rudd for reporting it.
- modified snmp patch to make it build on RedHat 6.2 again

* Tue Feb 03 2004 Karsten Hopp <karsten@redhat.de>
- switch to Simon Matter's cyrus-imapd package, which has
  some major improvements over the old Red Hat package.
  - configdirectory moved from /var/imap to /var/lib/imap
  - sasl_pwcheck_method changed to saslauthd
- needed to delete package/vendor tags for buildsystem.
- added USEPIE variable for linking with -fpie flag
- removed rpath from linker arguments
- removed email header from README.HOWTO-recover-mailboxes
- added lib64 patch
- use CFLAGS from specfile in imtest subdir
- disable -pie on ppc for now

* Tue Feb 03 2004 Simon Matter <simon.matter@invoca.ch>
- added tls_ca_file: to imapd.conf
- updated autocreate patch which fixes a small sig11 problem

* Thu Jan 29 2004 Simon Matter <simon.matter@invoca.ch>
- convert sieve scripts to UTF-8 only if sievec failed before
- add note to the readme about limiting loggin on busy servers
- added build time option to chose the syslog facility

* Wed Jan 28 2004 Simon Matter <simon.matter@invoca.ch>
- sieve scripts are now converted to UTF-8 with cvt_cyrusdb_all

* Tue Jan 27 2004 Simon Matter <simon.matter@invoca.ch>
- fixed problems with masssievec
- lots of small fixes in the init scripts

* Fri Jan 23 2004 Simon Matter <simon.matter@invoca.ch>
- updated auto db converting functionality
- added auto masssievec functionality

* Thu Jan 22 2004 Simon Matter <simon.matter@invoca.ch>
- updated autocreate/autosievefolder patches

* Fri Jan 16 2004 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.3

* Wed Jan 14 2004 Simon Matter <simon.matter@invoca.ch>
- number of mailbox list dumps can now be configured

* Fri Jan 02 2004 Simon Matter <simon.matter@invoca.ch>
- updated autosievefolder patch

* Thu Dec 18 2003 Simon Matter <simon.matter@invoca.ch>
- updated autocreate/autosievefolder/rmquota patches

* Tue Oct 28 2003 Simon Matter <simon.matter@invoca.ch>
- updated to 2.2.2-BETA

* Tue Aug 05 2003 Simon Matter <simon.matter@invoca.ch>
- add sendmail m4 macro, some people were looking for it
- just one source for pam default configuration (they were all the same)
- added /etc/pam.d/lmtp
- added build support for RedHat Beta severn

* Wed Jul 30 2003 Simon Matter <simon.matter@invoca.ch>
- updated autocreate patch to 0.8.1
- removed creation of spool/config dirs, not needed anymore
- added cyrus_sharedbackup to contrib

* Fri Jul 18 2003 Simon Matter <simon.matter@invoca.ch>
- modified for 2.2.1-BETA

* Wed Jul 09 2003 Simon Matter <simon.matter@invoca.ch>
- modified rpm_set_permissions script

* Mon Jul 07 2003 Simon Matter <simon.matter@invoca.ch>
- changed permissions on config and spool dirs
- modified init script

* Thu Jul 03 2003 Simon Matter <simon.matter@invoca.ch>
- upgraded to 2.1.14
- removed now obsolete forcedowncase patch
- use --with-extraident to add extra version information
- updated munge8bit patch

* Wed Jun 04 2003 Simon Matter <simon.matter@invoca.ch>
- added RedHat 2.1ES support to the perlhack detection

* Tue May 20 2003 Simon Matter <simon.matter@invoca.ch>
- upgraded autocreate patch

* Fri May 09 2003 Simon Matter <simon.matter@invoca.ch>
- upgraded autocreate patch
- modified init script

* Mon May 05 2003 Simon Matter <simon.matter@invoca.ch>
- upgraded to 2.1.13
- replaced commands with macros, cleaned up spec file

* Fri May 02 2003 Simon Matter <simon.matter@invoca.ch>
- added murder subpackage
- changed exec path to /usr/lib/cyrus-imapd

* Thu May 01 2003 Simon Matter <simon.matter@invoca.ch>
- included modified munge8bit patch again

* Tue Apr 29 2003 Simon Matter <simon.matter@invoca.ch>
- added new 8bit header patch
- upgraded IPv6 patch
- upgraded autocreate patch to 0.7

* Mon Apr 28 2003 Simon Matter <simon.matter@invoca.ch>
- added new autocreate patch

* Mon Mar 31 2003 H-E Sandstrom <hes@mailcore.net>
- added munge8bit patch

* Mon Mar 24 2003 Simon Matter <simon.matter@invoca.ch>
- added createonpost fix patch

* Thu Mar 20 2003 Simon Matter <simon.matter@invoca.ch>
- added functionality to patch the IPv6 patch on the fly if
  autoconf > 2.13, we can now use newer autoconf again.

* Tue Mar 18 2003 Paul Bender <pbender@qualcomm.com>
- fixed spec file so that autoconf 2.13 will always be used,
  since the IPv6 patch requires autoconf <= 2.13

* Fri Mar 14 2003 Simon Matter <simon.matter@invoca.ch>
- fixed problems with new file package

* Thu Mar 13 2003 Simon Matter <simon.matter@invoca.ch>
- added kerberos include for RedHat Beta phoebe 2
- added Henrique's forcedowncase patch

* Mon Mar 03 2003 Simon Matter <simon.matter@invoca.ch>
- corrected imapd.conf

* Sat Mar 01 2003 Simon Matter <simon.matter@invoca.ch>
- added note about lmtp socket in sendmail
- added flock patches

* Fri Feb 07 2003 Simon Matter <simon.matter@invoca.ch>
- added build time option for fulldirhash

* Wed Feb 05 2003 Simon Matter <simon.matter@invoca.ch>
- added IPV6 patch to source rpm
- fixed build on RedHat 6.2

* Tue Feb 04 2003 Simon Matter <simon.matter@invoca.ch>
- update to 2.1.12
- added logrotate entry for /var/log/auth.log
- modified init script to use builtin daemon mode

* Fri Jan 10 2003 Simon Matter <simon.matter@invoca.ch>
- small change in mboxlist backup script

* Fri Jan 10 2003 Simon Matter <simon.matter@invoca.ch>
- fixed a cosmetic bug in cvt_cyrusdb_all
- added cron.daily job to backup mailboxes.db

* Mon Jan 06 2003 Simon Matter <simon.matter@invoca.ch>
- add more entries to /etc/services

* Wed Jan 01 2003 Simon Matter <simon.matter@invoca.ch>
- include snmpargs patch for build on RedHat 6.2
- added build support for RedHat 6.2

* Mon Dec 30 2002 Simon Matter <simon.matter@invoca.ch>
- removed autoconf hack, not needed anymore
- enabled build on RedHat Beta Phoebe
- added services entry for lmtp
- cleanup spec file

* Thu Dec 26 2002 Simon Matter <simon.matter@invoca.ch>
- removed BuildPrereq for e2fsprogs-devel

* Thu Dec 12 2002 Simon Matter <simon.matter@invoca.ch>
- modified RedHat release detection
- added BuildPrereq for file

* Thu Dec 05 2002 Simon Matter <simon.matter@invoca.ch>
- upgraded to cyrus-imapd 2.1.11
- upgrade IPV6 patch to 20021205

* Thu Nov 28 2002 Simon Matter <simon.matter@invoca.ch>
- Fixed some default attributes

* Thu Nov 28 2002 Troels Arvin <troels@arvin.dk>
- Explicitly changed files-section to
   - use defattr for simple (root-owned 0644) files
   - explictly set root as user/group owner where
     the user/group ownership was previously indicated
     as "-"; this allows building valid packages without
     having to being root when building

* Mon Nov 25 2002 Simon Matter <simon.matter@invoca.ch>
- changed default build option for IDLED to off
- included some useful info in README.*

* Thu Nov 21 2002 Simon Matter <simon.matter@invoca.ch>
- added build time option for IDLED, thank you Roland Pope

* Tue Nov 19 2002 Simon Matter <simon.matter@invoca.ch>
- fixed spec to really use fdatasync patch
- added createonpost patch

* Thu Nov 14 2002 Simon Matter <simon.matter@invoca.ch>
- upgraded to cyrus-imapd 2.1.10
- build without IPv6 support by default

* Tue Nov 12 2002 Simon Matter <simon.matter@invoca.ch>
- fixed db detection in .spec

* Mon Oct 21 2002 Simon Matter <simon.matter@invoca.ch>
- updated cvt_cyrusdb_all script

* Fri Oct 18 2002 Simon Matter <simon.matter@invoca.ch>
- added fdatasync patch

* Thu Oct 03 2002 Simon Matter <simon.matter@invoca.ch>
- add RPM version 4.1 compatibility, which means remove installed
  but not packaged files

* Wed Sep 18 2002 Simon Matter <simix@datacomm.ch>
- added auto db converting functionality
- changed default for MBOXLIST_DB and SEEN_DB to skiplist

* Mon Sep 16 2002 Simon Matter <simix@datacomm.ch>
- remove creation of cyrus user at build time
- added scripts from ftp://kalamazoolinux.org/pub/projects/awilliam/cyrus/

* Mon Sep 02 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.9

* Fri Aug 30 2002 Simon Matter <simix@datacomm.ch>
- included extra ident string

* Thu Aug 29 2002 Simon Matter <simix@datacomm.ch>
- modified path in deliver-wrapper, thank you Richard L. Phipps
- added RedHat 2.1AS support to the perlhack detection
- added build time option to force syncronous updates on ext3

* Wed Aug 28 2002 Simon Matter <simix@datacomm.ch>
- added updated IPv6 patch from Hajimu UMEMOTO

* Wed Aug 28 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.8

* Thu Aug 22 2002 Simon Matter <simix@datacomm.ch>
- included IPv6 patch from Hajimu UMEMOTO

* Wed Aug 21 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.7 because of wrong version info

* Wed Aug 21 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.6

* Mon Aug 19 2002 Simon Matter <simix@datacomm.ch>
- change db version detection, thank you Chris for reporting

* Tue Aug 13 2002 Simon Matter <simix@datacomm.ch>
- fixed autoconf detection

* Mon Aug 12 2002 Simon Matter <simix@datacomm.ch>
- included support for different autoconf versions
- modified the perl build and install process
- made some .spec changes to build on RedHat 7.x and limbo

* Fri Aug 09 2002 Simon Matter <simix@datacomm.ch>
- included sieve matching patch

* Thu Jun 27 2002 Simon Matter <simix@datacomm.ch>
- fixed %%post script where %%F was expanded to file.file

* Wed Jun 26 2002 Simon Matter <simix@datacomm.ch>
- fixed missing man page

* Tue Jun 25 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.5

* Mon Jun 24 2002 Simon Matter <simix@datacomm.ch>
- added compile time parameters to configure the package based on
  the idea from Luca Olivetti <luca@olivetti.cjb.net>
- make deliver-wrapper a compile time option

* Fri May 03 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.4

* Mon Apr 22 2002 Simon Matter <simix@datacomm.ch>
- small initscript fix

* Fri Mar 08 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.3
- removed some stuff that was cleaned up in the sources
- added compile time options for db backends

* Wed Mar 06 2002 Simon Matter <simix@datacomm.ch>
- removed requires perl-File-Temp for utils package, it's in the RedHat
  perl RPM now

* Fri Feb 22 2002 Simon Matter <simix@datacomm.ch>
- removed deliverdb/db

* Wed Feb 20 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.2

* Mon Feb 11 2002 Simon Matter <simix@datacomm.ch>
- changed sasl_mech_list: PLAIN in /etc/imapd.conf
- added sieve to /etc/pam.d

* Fri Feb 08 2002 Simon Matter <simix@datacomm.ch>
- added requires perl-File-Temp for utils package

* Wed Feb 06 2002 Simon Matter <simix@datacomm.ch>
- added some %%dir flags
- removed /usr/lib/sasl/Cyrus.conf
- added conf templates
- build time option for usage of saslauth group

* Tue Feb 05 2002 Simon Matter <simix@datacomm.ch>
- upgraded to cyrus-imapd 2.1.1
- dependency of cyrus-sasl >= 2.1.0-1

* Sun Feb 03 2002 Simon Matter <simix@datacomm.ch>
- saslauth group is only deleted on uninstall if there is no other
  member in this group

* Sat Feb 02 2002 Simon Matter <simix@datacomm.ch>
- changed start/stop level in init file

* Tue Jan 29 2002 Simon Matter <simix@datacomm.ch>
- dependency of cyrus-sasl >= 1.5.24-22
- dotstuffing patch for sendmail calls made by sieve for outgoing
  mails
- patch for ability to force ipurge to traverse personal folders

* Mon Jan 28 2002 Simon Matter <simix@datacomm.ch>
- minor spec file changes

* Sat Jan 19 2002 Simon Matter <simix@datacomm.ch>
- changed default auth to pam
- remove several %%dir from %%files sections
- change from /usr/lib/cyrus -> /usr/libexec/cyrus
- rename source files to something like cyrus...
- added rehash tool
- changed to hashed spool

* Fri Jan 18 2002 Simon Matter <simix@datacomm.ch>
- fixed init script
- fixed %%post section in spec

* Thu Jan 17 2002 Simon Matter <simix@datacomm.ch>
- ready for first build

* Wed Jan 09 2002 Simon Matter <simix@datacomm.ch>
- initial package, with help from other packages out there
