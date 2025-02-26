package models

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
)

func TestIsDisplayUpdatableNum(t *testing.T) {
	var tests = []struct {
		mode     []byte
		family   string
		expected bool
	}{
		{
			mode:     []byte{config.Offline},
			expected: false,
		},
		{
			mode:     []byte{config.FastRoot},
			expected: true,
		},
		{
			mode:     []byte{config.Deep},
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.RedHat,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Oracle,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Debian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Ubuntu,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Raspbian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.CentOS,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Alma,
			expected: true,
		},
                {
                        mode:     []byte{config.Fast},
                        family:   constant.ArchLinux,
                        expected: true,
                },
		{
			mode:     []byte{config.Fast},
			family:   constant.Rocky,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Amazon,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.FreeBSD,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.OpenSUSE,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Alpine,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Fedora,
			expected: true,
		},
	}

	for i, tt := range tests {
		mode := config.ScanMode{}
		for _, m := range tt.mode {
			mode.Set(m)
		}
		r := ScanResult{
			ServerName: "name",
			Family:     tt.family,
		}
		act := r.isDisplayUpdatableNum(mode)
		if tt.expected != act {
			t.Errorf("[%d] expected %#v, actual %#v", i, tt.expected, act)
		}
	}
}

func TestRemoveRaspbianPackFromResult(t *testing.T) {
	var tests = []struct {
		in       ScanResult
		expected ScanResult
	}{
		{
			in: ScanResult{
				Family: constant.Raspbian,
				Packages: Packages{
					"apt":                Package{Name: "apt", Version: "1.8.2.1"},
					"libraspberrypi-dev": Package{Name: "libraspberrypi-dev", Version: "1.20200811-1"},
				},
				SrcPackages: SrcPackages{},
			},
			expected: ScanResult{
				Family: constant.Raspbian,
				Packages: Packages{
					"apt": Package{Name: "apt", Version: "1.8.2.1"},
				},
				SrcPackages: SrcPackages{},
			},
		},
		{
			in: ScanResult{
				Family: constant.Debian,
				Packages: Packages{
					"apt": Package{Name: "apt", Version: "1.8.2.1"},
				},
				SrcPackages: SrcPackages{},
			},
			expected: ScanResult{
				Family: constant.Debian,
				Packages: Packages{
					"apt": Package{Name: "apt", Version: "1.8.2.1"},
				},
				SrcPackages: SrcPackages{},
			},
		},
	}

	for i, tt := range tests {
		r := tt.in
		r = *r.RemoveRaspbianPackFromResult()
		if !reflect.DeepEqual(r, tt.expected) {
			t.Errorf("[%d] expected %+v, actual %+v", i, tt.expected, r)
		}
	}
}

func TestScanResult_Sort(t *testing.T) {
	type fields struct {
		Packages    Packages
		ScannedCves VulnInfos
	}
	tests := []struct {
		name     string
		fields   fields
		expected fields
	}{
		{
			name: "already asc",
			fields: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "1", Name: "procB"},
							{PID: "2", Name: "procA"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "1"},
							{PID: "2"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgA"},
							PackageFixStatus{Name: "pkgB"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-1"},
							{AdvisoryID: "adv-2"},
						},
						Exploits: []Exploit{
							{URL: "a"},
							{URL: "b"},
						},
						Metasploits: []Metasploit{
							{Name: "a"},
							{Name: "b"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							JPCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							CISA: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
						},
					},
				},
			},
			expected: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "1", Name: "procB"},
							{PID: "2", Name: "procA"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "1"},
							{PID: "2"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgA"},
							PackageFixStatus{Name: "pkgB"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-1"},
							{AdvisoryID: "adv-2"},
						},
						Exploits: []Exploit{
							{URL: "a"},
							{URL: "b"},
						},
						Metasploits: []Metasploit{
							{Name: "a"},
							{Name: "b"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							JPCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							CISA: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
						},
					},
				},
			},
		},
		{
			name: "sort",
			fields: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "2", Name: "procA"},
							{PID: "1", Name: "procB"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "91"},
							{PID: "90"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgB"},
							PackageFixStatus{Name: "pkgA"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-2"},
							{AdvisoryID: "adv-1"},
						},
						Exploits: []Exploit{
							{URL: "b"},
							{URL: "a"},
						},
						Metasploits: []Metasploit{
							{Name: "b"},
							{Name: "a"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "b"},
									Reference{Link: "a"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "b"},
									Reference{Link: "a"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "b"},
								{Title: "a"},
							},
							JPCERT: []Alert{
								{Title: "b"},
								{Title: "a"},
							},
							CISA: []Alert{
								{Title: "b"},
								{Title: "a"},
							},
						},
					},
				},
			},
			expected: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "1", Name: "procB"},
							{PID: "2", Name: "procA"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "90"},
							{PID: "91"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgA"},
							PackageFixStatus{Name: "pkgB"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-1"},
							{AdvisoryID: "adv-2"},
						},
						Exploits: []Exploit{
							{URL: "a"},
							{URL: "b"},
						},
						Metasploits: []Metasploit{
							{Name: "a"},
							{Name: "b"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							JPCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							CISA: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
						},
					},
				},
			},
		},
		{
			name: "sort JVN by cvss v3",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{Cvss3Score: 3},
								{Cvss3Score: 10},
							},
						},
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{Cvss3Score: 10},
								{Cvss3Score: 3},
							},
						},
					},
				},
			},
		},
		{
			name: "sort JVN by cvss3, cvss2, sourceLink",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{
									Cvss3Score: 3,
									Cvss2Score: 3,
									SourceLink: "https://jvndb.jvn.jp/ja/contents/2023/JVNDB-2023-001210.html",
								},
								{
									Cvss3Score: 3,
									Cvss2Score: 3,
									SourceLink: "https://jvndb.jvn.jp/ja/contents/2021/JVNDB-2021-001210.html",
								},
							},
						},
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{
									Cvss3Score: 3,
									Cvss2Score: 3,
									SourceLink: "https://jvndb.jvn.jp/ja/contents/2021/JVNDB-2021-001210.html",
								},
								{
									Cvss3Score: 3,
									Cvss2Score: 3,
									SourceLink: "https://jvndb.jvn.jp/ja/contents/2023/JVNDB-2023-001210.html",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "sort JVN by cvss3, cvss2",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{
									Cvss3Score: 3,
									Cvss2Score: 1,
								},
								{
									Cvss3Score: 3,
									Cvss2Score: 10,
								},
							},
						},
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{
									Cvss3Score: 3,
									Cvss2Score: 10,
								},
								{
									Cvss3Score: 3,
									Cvss2Score: 1,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ScanResult{
				Packages:    tt.fields.Packages,
				ScannedCves: tt.fields.ScannedCves,
			}
			r.SortForJSONOutput()
			if !reflect.DeepEqual(r.Packages, tt.expected.Packages) {
				t.Errorf("act %+v, want %+v", r.Packages, tt.expected.Packages)
			}

			if !reflect.DeepEqual(r.ScannedCves, tt.expected.ScannedCves) {
				t.Errorf("act %+v, want %+v", r.ScannedCves, tt.expected.ScannedCves)
			}
		})
	}
}
