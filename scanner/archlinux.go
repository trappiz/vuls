package scanner

import (
	"bufio"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type archlinux struct {
	base
}

// NewArchLinux is constructor
func newArchLinux(c config.ServerInfo) *archlinux {
	d := &archlinux{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

// ArchLinux
// https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/archlinux.rb
func detectArchLinux(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/archlinux-release", noSudo); !r.isSuccess() {
		return false, nil
	}
	if r := exec(c, "cat /etc/archlinux-release", noSudo); r.isSuccess() {
		os := newArchLinux(c)
		os.setDistro(constant.ArchLinux, strings.TrimSpace(r.Stdout))
		return true, os
	}
	return false, nil
}

func (o *archlinux) checkScanMode() error {
	return nil
}

func (o *archlinux) checkDeps() error {
	o.log.Infof("Dependencies... No need")
	return nil
}

func (o *archlinux) checkIfSudoNoPasswd() error {
	o.log.Infof("sudo ... No need")
	return nil
}

func (o *archlinux) pacmanUpdate() error {
	if o.getServerInfo().Mode.IsOffline() {
		return nil
	}
	r := o.exec("checkupdates", noSudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to SSH: %s", r)
	}
	return nil
}

func (o *archlinux) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *archlinux) postScan() error {
	return nil
}

func (o *archlinux) detectIPAddr() (err error) {
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

func (o *archlinux) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	if err := o.pacmanUpdate(); err != nil {
		return err
	}
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		err = xerrors.Errorf("Failed to scan updatable packages: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	} else {
		installed.MergeNewVersion(updatable)
	}

	o.Packages = installed
	return nil
}

func (o *archlinux) scanInstalledPackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("pacman -Qe")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	return o.parseApkInfo(r.Stdout)
}

func (o *archlinux) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	installedPackages, err := o.parseApkInfo(stdout)
	return installedPackages, nil, err
}

func (o *archlinux) parseApkInfo(stdout string) (models.Packages, error) {
	packs := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		ss := strings.Split(line, "-")
		if len(ss) < 3 {
			if strings.Contains(ss[0], "WARNING") {
				continue
			}
			return nil, xerrors.Errorf("Failed to parse pacman -Qe: %s", line)
		}
		name := strings.Join(ss[:len(ss)-2], "-")
		packs[name] = models.Package{
			Name:    name,
			Version: strings.Join(ss[len(ss)-2:], "-"),
		}
	}
	return packs, nil
}

func (o *archlinux) scanUpdatablePackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("pacman --version")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	return o.parseApkVersion(r.Stdout)
}

func (o *archlinux) parseApkVersion(stdout string) (models.Packages, error) {
	packs := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "<") {
			continue
		}
		ss := strings.Split(line, "<")
		namever := strings.TrimSpace(ss[0])
		tt := strings.Split(namever, "-")
		name := strings.Join(tt[:len(tt)-2], "-")
		packs[name] = models.Package{
			Name:       name,
			NewVersion: strings.TrimSpace(ss[1]),
		}
	}
	return packs, nil
}
