when RULE_INIT {
    array set NTLMFlags {
        unicode        0x00000001
        oem            0x00000002
        req_target     0x00000004
        unknown1       0x00000008
        sign           0x00000010
        seal           0x00000020
        datagram       0x00000040
        lmkey          0x00000080
        netware        0x00000100
        ntlm           0x00000200
        unknown2       0x00000400
        unknown3       0x00000800
        ntlm_domain    0x00001000
        ntlm_server    0x00002000
        ntlm_share     0x00004000
        NTLM2          0x00008000
        targetinfo     0x00800000
        128bit         0x20000000
        keyexch        0x40000000
        56bit          0x80000000
    }
	set static::email_domain   		"domain.org"
	set static::user_domain    		"DOMAIN"
    set static::log_pri        		"local0."
    set static::fail_tab       		"NTLMfails"
    set static::blacklist_tab  		"NTLMblackhole"
    set static::userfail_tab       	"NTLMUserfails"
    set static::userblacklist_tab  	"NTLMUserblackhole"
    set static::max_failures   		5
    set static::fail_memory    		300
    set static::block_duration 		300
}

when CLIENT_ACCEPTED {
    if {[table lookup -subtable $static::blacklist_tab [IP::client_addr]] == 1} {
        log $static::log_pri "[virtual] - BLACKHOLED IPADDR [IP::client_addr]:[TCP::client_port] (Reputation=[IP::reputation [IP::client_addr]])"
        reject
        return
    }
}

when CLIENTSSL_HANDSHAKE {
   SSL::collect
}
when CLIENTSSL_DATA {
	set payload [SSL::payload]
	if { ($payload contains "3 REGISTER") } {
		regexp -nocase {gssapi-data=\"([A-Za-z0-9+\/=]*)\",} $payload match gssapi garbage	
		if { [info exists match] } {
			unset match
			unset garbage
			if { $gssapi != "" } {
				set ntlm_msg [ b64decode [string trim $gssapi]]
				binary scan $ntlm_msg a7ci protocol zero type
				if { $type eq 3} {
					binary scan $ntlm_msg @12ssissississississii \
						lmlen lmlen2 lmoff \
						ntlen ntlen2 ntoff \
						dlen  dlen2  doff  \
						ulen  ulen2  uoff \
						hlen  hlen2  hoff \
						slen  slen2  soff \
						flags
					set ntlm_domain {}; binary scan $ntlm_msg @${doff}a${dlen} ntlm_domain
					set ntlm_user {};   binary scan $ntlm_msg @${uoff}a${ulen} ntlm_user
					set ntlm_host {};   binary scan $ntlm_msg @${hoff}a${hlen} ntlm_host
					set unicode [expr {$flags & 0x00000001}]
					if {$unicode} {
						set ntlm_domain_convert ""
						foreach i [ split $ntlm_domain ""] {
							scan $i %c c
							if {$c>1} {
								append ntlm_domain_convert $i
							} elseif {$c<128} {
								set ntlm_domain_convert $ntlm_domain_convert
							} else {
								append ntlm_domain_convert \\u[format %04.4X $c]
							}
						}
						set ntlm_domain $ntlm_domain_convert
						set ntlm_user_convert ""
						foreach i [ split $ntlm_user ""] {
							scan $i %c c
							if {$c>1} {
								append ntlm_user_convert $i
							} elseif {$c<128} {
								set ntlm_user_convert $ntlm_user_convert
							} else {
								append ntlm_user_convert \\u[format %04.4X $c]
							}
						}
						set ntlm_user   $ntlm_user_convert
						set ntlm_host_convert ""
						foreach i [ split $ntlm_host ""] {
							scan $i %c c
							if {$c>1} {
								append ntlm_host_convert $i
							} elseif {$c<128} {
								set ntlm_host_convert $ntlm_host_convert
							} else {
								append ntlm_host_convert \\u[format %04.4X $c]
							}
						}
						set ntlm_host   $ntlm_host_convert
					}
					binary scan $ntlm_msg @${ntoff}a${ntlen} ntdata
					binary scan $ntlm_msg @${lmoff}a${lmlen} lmdata
					binary scan $ntdata H* ntdata_h
					binary scan $lmdata H* lmdata_h
					set interesting 1
					
					if { ($ntlm_domain equals $static::user_domain or $ntlm_user ends_with $static::email_domain) } {
						set attack 1
						if {[table lookup -subtable $static::userblacklist_tab $ntlm_user] == 1} {
							log $static::log_pri "[virtual] - BLACKHOLED $ntlm_domain\\$ntlm_user from $ntlm_host at [IP::client_addr]:[TCP::client_port] (Reputation=[IP::reputation [IP::client_addr]])"
							reject
							return
						} else {
							log $static::log_pri "[virtual] - Login attempt by $ntlm_domain\\$ntlm_user from $ntlm_host for SIP."
						}
					} else {
						set attack 0
						log $static::log_pri "[virtual] - Not a valid user - Login attempt by $ntlm_domain\\$ntlm_user from $ntlm_host for SIP."
					}
				}
			}
		}
	}
	# Release the payload
	SSL::release
	SSL::collect
}

when SERVERSSL_HANDSHAKE {
   SSL::collect
   SSL::release 0
}

when SERVERSSL_DATA {
	set payload [SSL::payload]

	if {[info exists interesting] && $interesting == 1} {
        set client [IP::client_addr]:[TCP::client_port]
        set node [IP::server_addr]:[TCP::server_port]

        if { $payload contains "401 Unauthorized ms-user-logon-data" and ([info exists attack] and $attack == 1) } {
            table set -subtable $static::fail_tab -notouch -excl [IP::client_addr] 0 indef $static::fail_memory
            table incr -subtable $static::fail_tab [IP::client_addr]
			
			set now [clock seconds]
            set now_date [split [clock format $now -format {%X %x}] " "]
				
			set later [expr {$now + $static::block_duration}]
			set later_date [split [clock format $later -format {%X %x}] " "]

			if {[info exists ntlm_user]} {
				table set -subtable $static::userfail_tab -notouch -excl $ntlm_user 0 indef $static::fail_memory
				table incr -subtable $static::userfail_tab $ntlm_user

				if {[table lookup -subtable $static::userfail_tab $ntlm_user] >= $static::max_failures} {
					log $static::log_pri "[virtual] - BLACKHOLING USER - $ntlm_user at $now_date until $later_date"
					table set -subtable $static::userblacklist_tab -excl $ntlm_user 1 indef $static::block_duration
				}

			}

            if {[table lookup -subtable $static::fail_tab [IP::client_addr]] >= $static::max_failures} {
                log $static::log_pri "[virtual] - BLACKHOLING IPADDR - [IP::client_addr] (Reputation=[IP::reputation [IP::client_addr]]) at $now_date until $later_date"
                table set -subtable $static::blacklist_tab -excl [IP::client_addr] 1 indef $static::block_duration
            }
        }
    }

	SSL::release
	SSL::collect
}