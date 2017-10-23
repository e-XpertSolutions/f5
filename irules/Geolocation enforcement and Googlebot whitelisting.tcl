when CLIENT_ACCEPTED {
    set decrypt 1
}

###
# Analyze the first request after an Handshake.
###

when CLIENTSSL_HANDSHAKE {
    if { [info exists decrypt] and $decrypt } {
        SSL::collect
    }
}

when CLIENTSSL_DATA {
    if { [SSL::payload] matches_glob "*User-Agent:*googlebot*"  } {
        set decrypt 0
        SSL::release
    } elseif { !([whereis [IP::client_addr] country] equals "CH") and ([class search -all AccessIP equals [IP::client_addr]] eq "0" ) } {
        log local0. "1 Client [IP::client_addr] from [whereis [IP::client_addr]] rejected due to security policy enforcement !!!"
        reject
    } else {
        set decrypt 0
        SSL::release
    }
}
